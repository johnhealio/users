mod repo;
mod webauthn;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use common::models::User;
use common::Config;
use firestore::FirestoreDb;
use repo::RegistrationSession;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential, Webauthn};

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");
const COMMON_STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../common/static");

#[derive(Clone)]
struct AppState {
    db: FirestoreDb,
    webauthn: Webauthn,
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
    let state = AppState { db, webauthn };

    let app = Router::new()
        .route("/api/register/start", post(start_registration))
        .route("/api/register/finish", post(finish_registration))
        .nest_service("/common", ServeDir::new(COMMON_STATIC_DIR))
        .fallback_service(ServeDir::new(STATIC_DIR))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind port");
    tracing::info!("registration service listening on :{port}");
    axum::serve(listener, app).await.expect("server error");
}

#[derive(Debug, Deserialize)]
struct StartRegisterRequest {
    username: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct StartRegisterResponse {
    session_id: String,
    #[serde(flatten)]
    challenge: CreationChallengeResponse,
}

async fn start_registration(
    State(state): State<AppState>,
    Json(req): Json<StartRegisterRequest>,
) -> Result<Json<StartRegisterResponse>, AppError> {
    let username = req.username.trim().to_lowercase();
    let display_name = req.display_name.trim().to_string();
    if username.is_empty() || display_name.is_empty() {
        return Err(AppError::BadRequest(
            "username and display_name are required".to_string(),
        ));
    }

    if repo::username_exists(&state.db, &username).await? {
        return Err(AppError::UsernameTaken);
    }

    let user_id = Uuid::new_v4();
    let (challenge, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &username, &display_name, None)
        .map_err(AppError::Webauthn)?;

    let session_id = Uuid::new_v4().to_string();
    let session = RegistrationSession::new(reg_state, user_id, username, display_name);
    repo::save_registration_session(&state.db, &session_id, &session).await?;

    Ok(Json(StartRegisterResponse {
        session_id,
        challenge,
    }))
}

#[derive(Debug, Deserialize)]
struct FinishRegisterRequest {
    session_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize)]
struct FinishRegisterResponse {
    user_id: Uuid,
    username: String,
}

async fn finish_registration(
    State(state): State<AppState>,
    Json(req): Json<FinishRegisterRequest>,
) -> Result<Json<FinishRegisterResponse>, AppError> {
    let session = repo::take_registration_session(&state.db, &req.session_id)
        .await?
        .ok_or(AppError::SessionNotFound)?;
    if session.is_expired() {
        return Err(AppError::SessionExpired);
    }

    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &session.state)
        .map_err(AppError::Webauthn)?;

    let user = User {
        user_id: session.user_id,
        username: session.username,
        display_name: session.display_name,
        created_at: chrono::Utc::now(),
    };
    repo::complete_registration(&state.db, &user, &passkey).await?;

    Ok(Json(FinishRegisterResponse {
        user_id: user.user_id,
        username: user.username,
    }))
}

#[derive(Debug)]
enum AppError {
    UsernameTaken,
    SessionNotFound,
    SessionExpired,
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
            AppError::UsernameTaken => (StatusCode::CONFLICT, "username already taken".to_string()),
            AppError::SessionNotFound => (
                StatusCode::BAD_REQUEST,
                "unknown or already-used registration session".to_string(),
            ),
            AppError::SessionExpired => (
                StatusCode::BAD_REQUEST,
                "registration session expired".to_string(),
            ),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Webauthn(e) => {
                tracing::warn!(?e, "webauthn ceremony failed");
                (
                    StatusCode::BAD_REQUEST,
                    "registration ceremony failed".to_string(),
                )
            }
            AppError::Firestore(e) => {
                let is_conflict = format!("{e:?}").contains("AlreadyExists");
                tracing::error!(?e, "firestore error");
                if is_conflict {
                    (StatusCode::CONFLICT, "username already taken".to_string())
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal error".to_string(),
                    )
                }
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
