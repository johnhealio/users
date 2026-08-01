use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use common::models::Attributes;
use common::session::SessionError;
use common::Config;
use firestore::FirestoreDb;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const FUNCTION_ID: &str = "check2";
const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");
const COMMON_STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../common/static");

#[derive(Clone)]
struct AppState {
    db: FirestoreDb,
    rp_origin: String,
    authorization_url: String,
    http: reqwest::Client,
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
        authorization_url: config.authorization_url,
        http: reqwest::Client::new(),
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind port");
    tracing::info!("{FUNCTION_ID} service listening on :{port}");
    axum::serve(listener, build_router(state))
        .await
        .expect("server error");
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/check", post(check))
        .nest_service("/common", ServeDir::new(COMMON_STATIC_DIR))
        .fallback_service(ServeDir::new(STATIC_DIR))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct AuthorizeServiceResponse {
    authorized: bool,
    #[serde(default)]
    user_id: Option<Uuid>,
    #[serde(default)]
    attributes: Option<Attributes>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckResponse {
    authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    attributes: Option<Attributes>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    reason: Option<String>,
}

async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CheckResponse>, AppError> {
    let authorization = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingAuthorizationHeader)?;
    let dpop_proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingDpopProof)?;

    // Verifies the browser's own DPoP proof for *this* request, locally —
    // this is the one place proof-of-possession is actually checked. The
    // authorization service below is a plain server-to-server call with
    // the now-validated raw token, not a second DPoP round trip (see the
    // plan for why: a proof's htu is bound to one exact URL, so a proof
    // built for this endpoint couldn't be re-verified against a different
    // one anyway).
    let expected_htu = format!("{}/api/check", state.rp_origin);
    let authenticated =
        common::session::authenticate(&state.db, authorization, dpop_proof, "POST", &expected_htu)
            .await
            .map_err(AppError::Session)?;

    let authz: AuthorizeServiceResponse = state
        .http
        .post(format!("{}/api/authorize", state.authorization_url))
        .json(&serde_json::json!({
            "session_id": authenticated.token,
            "function_id": FUNCTION_ID,
        }))
        .send()
        .await
        .map_err(AppError::AuthorizationServiceUnreachable)?
        .json()
        .await
        .map_err(AppError::AuthorizationServiceUnreachable)?;

    Ok(Json(CheckResponse {
        authorized: authz.authorized,
        user_id: authz.user_id,
        attributes: authz.attributes,
        reason: authz.reason,
    }))
}

#[derive(Debug)]
enum AppError {
    MissingAuthorizationHeader,
    MissingDpopProof,
    Session(SessionError),
    AuthorizationServiceUnreachable(reqwest::Error),
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
            AppError::AuthorizationServiceUnreachable(e) => {
                tracing::error!(?e, "authorization service call failed");
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
    use chrono::Utc;
    use common::firestore::{COLLECTION_FUNCTIONS, COLLECTION_GROUPS, COLLECTION_SESSIONS};
    use common::models::{GroupMembership, Session};
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    use serde_json::json;

    async fn test_db() -> FirestoreDb {
        let config = Config::from_env();
        common::firestore::connect(&config)
            .await
            .expect("connect to firestore")
    }

    /// Spawns the real `authorization` server (a dev-dependency) on an
    /// ephemeral port, so this test exercises the actual authorization
    /// logic rather than a copy of it.
    async fn spawn_authorization_server(db: FirestoreDb) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let app = authorization::build_router(authorization::AppState { db });
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn spawn_check2_server(db: FirestoreDb, authorization_url: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let rp_origin = format!("http://{addr}");
        let state = AppState {
            db,
            rp_origin: rp_origin.clone(),
            authorization_url,
            http: reqwest::Client::new(),
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
            expires_at: Utc::now() + chrono::Duration::minutes(5),
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

    async fn seed_group_membership(db: &FirestoreDb, user_id: Uuid, group_id: &str) {
        let parent = db
            .parent_path(common::firestore::COLLECTION_USERS, user_id.to_string())
            .unwrap();
        db.fluent()
            .insert()
            .into(COLLECTION_GROUPS)
            .document_id(group_id)
            .parent(&parent)
            .object(&GroupMembership::default())
            .execute::<GroupMembership>()
            .await
            .unwrap();
    }

    async fn seed_function_group_attributes(db: &FirestoreDb, group_id: &str, attrs: &Attributes) {
        let parent = db.parent_path(COLLECTION_FUNCTIONS, FUNCTION_ID).unwrap();
        db.fluent()
            .insert()
            .into(COLLECTION_GROUPS)
            .document_id(group_id)
            .parent(&parent)
            .object(attrs)
            .execute::<Attributes>()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn end_to_end_authorized_check() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let check2_url = spawn_check2_server(db.clone(), authorization_url).await;

        let key = generate_test_key();
        let user_id = Uuid::new_v4();
        let group_id = format!("test-group-{}", Uuid::new_v4());
        let jkt = common::dpop::jwk_thumbprint(&key.x, &key.y);

        let token = seed_session(&db, user_id, &jkt).await;
        seed_group_membership(&db, user_id, &group_id).await;
        seed_function_group_attributes(&db, &group_id, &{
            let mut m = Attributes::new();
            m.insert("department".to_string(), json!("sales"));
            m
        })
        .await;

        let check_url = format!("{check2_url}/api/check");
        let proof = sign_proof(&key, "POST", &check_url);

        let client = reqwest::Client::new();
        let res: CheckResponse = client
            .post(&check_url)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(res.authorized);
        assert_eq!(res.user_id, Some(user_id));
        assert_eq!(
            res.attributes.unwrap().get("department").unwrap(),
            "sales"
        );
    }

    #[tokio::test]
    async fn end_to_end_unauthorized_check() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let check2_url = spawn_check2_server(db.clone(), authorization_url).await;

        let key = generate_test_key();
        let user_id = Uuid::new_v4();
        let jkt = common::dpop::jwk_thumbprint(&key.x, &key.y);
        // Session exists, but the user has no group membership or override
        // granting them check2 at all.
        let token = seed_session(&db, user_id, &jkt).await;

        let check_url = format!("{check2_url}/api/check");
        let proof = sign_proof(&key, "POST", &check_url);

        let client = reqwest::Client::new();
        let res: CheckResponse = client
            .post(&check_url)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(!res.authorized);
    }
}
