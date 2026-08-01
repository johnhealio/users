mod repo;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use common::session::SessionError;
use common::Config;
use firestore::FirestoreDb;
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");
const COMMON_STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../common/static");

#[derive(Clone)]
struct AppState {
    db: FirestoreDb,
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
    let port = config.port;
    let state = AppState {
        db,
        rp_origin: config.rp_origin,
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind port");
    tracing::info!("logout service listening on :{port}");
    axum::serve(listener, build_router(state))
        .await
        .expect("server error");
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/logout", post(logout))
        .nest_service("/common", ServeDir::new(COMMON_STATIC_DIR))
        .fallback_service(ServeDir::new(STATIC_DIR))
        .with_state(state)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<StatusCode, AppError> {
    let authorization = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingAuthorizationHeader)?;
    let dpop_proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingDpopProof)?;

    let expected_htu = format!("{}/api/logout", state.rp_origin);
    let authenticated =
        common::session::authenticate(&state.db, authorization, dpop_proof, "POST", &expected_htu)
            .await
            .map_err(AppError::Session)?;

    repo::delete_session(&state.db, &authenticated.token_hash).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug)]
enum AppError {
    MissingAuthorizationHeader,
    MissingDpopProof,
    Session(SessionError),
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
            AppError::MissingAuthorizationHeader => (
                StatusCode::UNAUTHORIZED,
                "missing Authorization header".to_string(),
            ),
            AppError::MissingDpopProof => (
                StatusCode::BAD_REQUEST,
                "missing DPoP proof header".to_string(),
            ),
            AppError::Session(e) => {
                tracing::warn!(?e, "session authentication failed");
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid, expired, or unrecognized session".to_string(),
                )
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use common::firestore::COLLECTION_SESSIONS;
    use common::models::Session;
    use common::Config;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use uuid::Uuid;

    async fn test_db() -> FirestoreDb {
        let config = Config::from_env();
        common::firestore::connect(&config)
            .await
            .expect("connect to firestore")
    }

    /// Starts a real logout server on an ephemeral localhost port and
    /// returns its base URL. This is why `build_router` is factored out of
    /// `main()`: the test exercises the actual HTTP handler, not just the
    /// Firestore layer, since a browser can't be used locally to do it
    /// (see the plan for why).
    async fn spawn_server(db: FirestoreDb) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let rp_origin = format!("http://{addr}");
        let state = AppState {
            db,
            rp_origin: rp_origin.clone(),
        };
        tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.unwrap();
        });
        rp_origin
    }

    struct TestKey {
        signing_key: SigningKey,
        jwk: Jwk,
        x: String,
        y: String,
    }

    fn generate_test_key() -> TestKey {
        let signing_key = SigningKey::random(&mut OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            point.x().unwrap(),
        );
        let y = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            point.y().unwrap(),
        );
        let jwk: Jwk =
            serde_json::from_value(json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
                .unwrap();
        TestKey {
            signing_key,
            jwk,
            x,
            y,
        }
    }

    #[derive(Serialize, Deserialize)]
    struct DpopClaims {
        jti: String,
        htm: String,
        htu: String,
        iat: i64,
    }

    fn sign_proof(key: &TestKey, htm: &str, htu: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(key.jwk.clone());
        let claims = DpopClaims {
            jti: Uuid::new_v4().to_string(),
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat: Utc::now().timestamp(),
        };
        let der = key
            .signing_key
            .to_pkcs8_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        encode(&header, &claims, &EncodingKey::from_ec_der(&der)).unwrap()
    }

    async fn seed_session(db: &FirestoreDb, user_id: Uuid, jkt: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let session = Session {
            user_id,
            jkt: jkt.to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        db.fluent()
            .insert()
            .into(COLLECTION_SESSIONS)
            .document_id(common::session::hash_token(&token))
            .object(&session)
            .execute::<Session>()
            .await
            .unwrap();
        token
    }

    async fn session_exists(db: &FirestoreDb, token: &str) -> bool {
        let doc: Option<Session> = db
            .fluent()
            .select()
            .by_id_in(COLLECTION_SESSIONS)
            .obj()
            .one(&common::session::hash_token(token))
            .await
            .unwrap();
        doc.is_some()
    }

    #[tokio::test]
    async fn valid_logout_deletes_the_session() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;
        let key = generate_test_key();
        let user_id = Uuid::new_v4();
        let jkt = common::dpop::jwk_thumbprint(&key.x, &key.y);
        let token = seed_session(&db, user_id, &jkt).await;

        let htu = format!("{base_url}/api/logout");
        let proof = sign_proof(&key, "POST", &htu);

        let client = reqwest::Client::new();
        let res = client
            .post(&htu)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 204);
        assert!(!session_exists(&db, &token).await);
    }

    #[tokio::test]
    async fn missing_authorization_header_is_rejected() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;
        let key = generate_test_key();
        let htu = format!("{base_url}/api/logout");
        let proof = sign_proof(&key, "POST", &htu);

        let client = reqwest::Client::new();
        let res = client
            .post(&htu)
            .header("DPoP", proof)
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 401);
    }

    #[tokio::test]
    async fn proof_from_the_wrong_key_is_rejected() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;
        let bound_key = generate_test_key();
        let attacker_key = generate_test_key();
        let user_id = Uuid::new_v4();
        let jkt = common::dpop::jwk_thumbprint(&bound_key.x, &bound_key.y);
        let token = seed_session(&db, user_id, &jkt).await;

        let htu = format!("{base_url}/api/logout");
        // Signed correctly, but by a key different from the one bound to
        // this session at logon — this is exactly what DPoP is meant to
        // catch: a stolen token alone isn't enough.
        let proof = sign_proof(&attacker_key, "POST", &htu);

        let client = reqwest::Client::new();
        let res = client
            .post(&htu)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 401);
        assert!(session_exists(&db, &token).await);
    }
}
