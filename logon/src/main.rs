mod repo;
mod webauthn;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use common::dpop::DpopError;
use common::Config;
use firestore::FirestoreDb;
use repo::AuthenticationSession;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse, Webauthn};

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");
const COMMON_STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../common/static");

#[derive(Clone)]
struct AppState {
    db: FirestoreDb,
    webauthn: Webauthn,
    rp_origin: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env();
    let db = common::firestore::connect(&config)
        .await
        .expect("failed to connect to Firestore");
    let webauthn = webauthn::build(&config);
    let port = config.port;
    let rp_origin = config.rp_origin.clone();
    let state = AppState {
        db,
        webauthn,
        rp_origin,
    };

    let app = Router::new()
        .route("/api/logon/start", post(start_logon))
        .route("/api/logon/finish", post(finish_logon))
        .nest_service("/common", ServeDir::new(COMMON_STATIC_DIR))
        .fallback_service(ServeDir::new(STATIC_DIR))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind port");
    tracing::info!("logon service listening on :{port}");
    axum::serve(listener, app).await.expect("server error");
}

#[derive(Debug, Deserialize)]
struct StartLogonRequest {
    username: String,
}

#[derive(Debug, Serialize)]
struct StartLogonResponse {
    session_id: String,
    #[serde(flatten)]
    challenge: RequestChallengeResponse,
}

async fn start_logon(
    State(state): State<AppState>,
    Json(req): Json<StartLogonRequest>,
) -> Result<Json<StartLogonResponse>, AppError> {
    let username = req.username.trim().to_lowercase();
    if username.is_empty() {
        return Err(AppError::BadRequest("username is required".to_string()));
    }

    let user_id = repo::find_user_id_by_username(&state.db, &username)
        .await?
        .ok_or(AppError::UnknownUsername)?;

    let passkeys = repo::list_passkeys(&state.db, user_id).await?;
    if passkeys.is_empty() {
        tracing::error!(%user_id, "registered user has no stored credentials");
        return Err(AppError::NoCredentials);
    }

    let (challenge, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(AppError::Webauthn)?;

    let session_id = Uuid::new_v4().to_string();
    let session = AuthenticationSession::new(auth_state, user_id);
    repo::save_authentication_session(&state.db, &session_id, &session).await?;

    Ok(Json(StartLogonResponse {
        session_id,
        challenge,
    }))
}

#[derive(Debug, Deserialize)]
struct FinishLogonRequest {
    session_id: String,
    credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
struct FinishLogonResponse {
    user_id: Uuid,
    username: String,
    access_token: String,
    expires_at: DateTime<Utc>,
}

async fn finish_logon(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<FinishLogonRequest>,
) -> Result<Json<FinishLogonResponse>, AppError> {
    // Verified before the WebAuthn session is consumed: a bad DPoP proof
    // shouldn't burn the one-shot authentication session, since the client
    // may just need to retry with a corrected proof.
    let dpop_proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingDpopProof)?;
    let expected_htu = format!("{}/api/logon/finish", state.rp_origin);
    let verified_dpop = common::dpop::verify_proof(&state.db, dpop_proof, "POST", &expected_htu)
        .await
        .map_err(AppError::Dpop)?;

    let session = repo::take_authentication_session(&state.db, &req.session_id)
        .await?
        .ok_or(AppError::SessionNotFound)?;
    if session.is_expired() {
        return Err(AppError::SessionExpired);
    }

    let result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &session.state)
        .map_err(AppError::Webauthn)?;

    if result.needs_update()
        && let Some(mut stored) =
            repo::get_credential(&state.db, session.user_id, result.cred_id()).await?
        && stored.passkey.update_credential(&result).unwrap_or(false)
    {
        repo::save_credential(&state.db, session.user_id, result.cred_id(), &stored).await?;
    }

    let user = repo::get_user(&state.db, session.user_id)
        .await?
        .ok_or(AppError::UnknownUsername)?;

    let (access_token, expires_at) =
        repo::create_session(&state.db, user.user_id, &verified_dpop.jkt).await?;

    Ok(Json(FinishLogonResponse {
        user_id: user.user_id,
        username: user.username,
        access_token,
        expires_at,
    }))
}

#[derive(Debug)]
enum AppError {
    UnknownUsername,
    NoCredentials,
    SessionNotFound,
    SessionExpired,
    MissingDpopProof,
    Dpop(DpopError),
    BadRequest(String),
    Webauthn(webauthn_rs::prelude::WebauthnError),
    Firestore(firestore::errors::FirestoreError),
}

impl From<firestore::errors::FirestoreError> for AppError {
    fn from(e: firestore::errors::FirestoreError) -> Self {
        AppError::Firestore(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::UnknownUsername => (StatusCode::NOT_FOUND, "unknown username".to_string()),
            AppError::NoCredentials => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "no credentials on file for this user".to_string(),
            ),
            AppError::SessionNotFound => (
                StatusCode::BAD_REQUEST,
                "unknown or already-used logon session".to_string(),
            ),
            AppError::SessionExpired => {
                (StatusCode::BAD_REQUEST, "logon session expired".to_string())
            }
            AppError::MissingDpopProof => (
                StatusCode::BAD_REQUEST,
                "missing DPoP proof header".to_string(),
            ),
            AppError::Dpop(e) => {
                tracing::warn!(?e, "dpop proof verification failed");
                (
                    StatusCode::BAD_REQUEST,
                    "invalid or replayed DPoP proof".to_string(),
                )
            }
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Webauthn(e) => {
                tracing::warn!(?e, "webauthn ceremony failed");
                (StatusCode::BAD_REQUEST, "logon ceremony failed".to_string())
            }
            AppError::Firestore(e) => {
                tracing::error!(?e, "firestore error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
