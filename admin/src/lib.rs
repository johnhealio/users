pub mod repo;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use common::models::{Attributes, FunctionInfo, GroupInfo, User};
use common::session::SessionError;
use firestore::FirestoreDb;
use repo::GrantTarget;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;
use uuid::Uuid;

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/static");
const COMMON_STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../common/static");

#[derive(Clone)]
pub struct AppState {
    pub db: FirestoreDb,
    pub rp_origin: String,
    pub authorization_url: String,
    pub http: reqwest::Client,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/admin/functions", post(upsert_function))
        .route("/api/admin/functions/list", post(list_functions))
        .route("/api/admin/groups", post(upsert_group))
        .route("/api/admin/groups/list", post(list_groups))
        .route("/api/admin/groups/members/add", post(add_group_member))
        .route("/api/admin/groups/members/remove", post(remove_group_member))
        .route("/api/admin/groups/members/list", post(list_group_members))
        .route("/api/admin/grants", post(set_grant))
        .route("/api/admin/grants/revoke", post(revoke_grant))
        .route("/api/admin/grants/list", post(list_grants))
        .route("/api/admin/users/list", post(list_users))
        .route("/api/admin/users/groups", post(user_groups))
        .route("/api/admin/groups/functions", post(group_functions))
        .nest_service("/common", ServeDir::new(COMMON_STATIC_DIR))
        .fallback_service(ServeDir::new(STATIC_DIR))
        .with_state(state)
}

/// Every admin action is gated the same way `check1`/`check2` gate theirs:
/// verify the browser's own DPoP proof for *this* request locally, then a
/// server-to-server call to `authorization` asking whether this session is
/// granted `function_id = "admin"`.
async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    request_path: &str,
) -> Result<Uuid, AppError> {
    let authorization = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingAuthorizationHeader)?;
    let dpop_proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::MissingDpopProof)?;

    let expected_htu = format!("{}{request_path}", state.rp_origin);
    let authenticated =
        common::session::authenticate(&state.db, authorization, dpop_proof, "POST", &expected_htu)
            .await
            .map_err(AppError::Session)?;

    #[derive(Debug, Deserialize)]
    struct AuthorizeServiceResponse {
        authorized: bool,
    }

    let authz: AuthorizeServiceResponse = state
        .http
        .post(format!("{}/api/authorize", state.authorization_url))
        .json(&serde_json::json!({
            "session_id": authenticated.token,
            "function_id": "admin",
        }))
        .send()
        .await
        .map_err(AppError::AuthorizationServiceUnreachable)?
        .json()
        .await
        .map_err(AppError::AuthorizationServiceUnreachable)?;

    if !authz.authorized {
        return Err(AppError::Forbidden);
    }

    Ok(authenticated.user_id)
}

fn parse_target(
    group_id: Option<String>,
    user_id: Option<Uuid>,
) -> Result<GrantTarget, AppError> {
    match (group_id, user_id) {
        (Some(g), None) => Ok(GrantTarget::Group(g)),
        (None, Some(u)) => Ok(GrantTarget::User(u)),
        _ => Err(AppError::BadRequest(
            "exactly one of group_id or user_id is required".to_string(),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct UpsertFunctionRequest {
    function_id: String,
    name: String,
    description: String,
}

async fn upsert_function(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpsertFunctionRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&state, &headers, "/api/admin/functions").await?;
    repo::upsert_function(&state.db, &req.function_id, &req.name, &req.description).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, Deserialize)]
struct ListFunctionsResponse {
    functions: Vec<FunctionInfo>,
}

async fn list_functions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListFunctionsResponse>, AppError> {
    require_admin(&state, &headers, "/api/admin/functions/list").await?;
    let functions = repo::list_functions(&state.db).await?;
    Ok(Json(ListFunctionsResponse { functions }))
}

#[derive(Debug, Deserialize)]
struct UpsertGroupRequest {
    group_id: String,
    name: String,
}

async fn upsert_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpsertGroupRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&state, &headers, "/api/admin/groups").await?;
    repo::upsert_group(&state.db, &req.group_id, &req.name).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, Deserialize)]
struct ListGroupsResponse {
    groups: Vec<GroupInfo>,
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListGroupsResponse>, AppError> {
    require_admin(&state, &headers, "/api/admin/groups/list").await?;
    let groups = repo::list_groups(&state.db).await?;
    Ok(Json(ListGroupsResponse { groups }))
}

#[derive(Debug, Deserialize)]
struct GroupMemberRequest {
    group_id: String,
    user_id: Uuid,
}

async fn add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GroupMemberRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&state, &headers, "/api/admin/groups/members/add").await?;
    repo::add_group_member(&state.db, &req.group_id, req.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GroupMemberRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&state, &headers, "/api/admin/groups/members/remove").await?;
    repo::remove_group_member(&state.db, &req.group_id, req.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct ListGroupMembersRequest {
    group_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListGroupMembersResponse {
    user_ids: Vec<Uuid>,
}

async fn list_group_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ListGroupMembersRequest>,
) -> Result<Json<ListGroupMembersResponse>, AppError> {
    require_admin(&state, &headers, "/api/admin/groups/members/list").await?;
    let user_ids = repo::list_group_members(&state.db, &req.group_id).await?;
    Ok(Json(ListGroupMembersResponse { user_ids }))
}

#[derive(Debug, Deserialize)]
struct GrantRequest {
    function_id: String,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    user_id: Option<Uuid>,
    #[serde(default)]
    attributes: Attributes,
}

async fn set_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GrantRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&state, &headers, "/api/admin/grants").await?;
    let target = parse_target(req.group_id, req.user_id)?;
    repo::set_grant(&state.db, &req.function_id, &target, &req.attributes).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct RevokeGrantRequest {
    function_id: String,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    user_id: Option<Uuid>,
}

async fn revoke_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RevokeGrantRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&state, &headers, "/api/admin/grants/revoke").await?;
    let target = parse_target(req.group_id, req.user_id)?;
    repo::revoke_grant(&state.db, &req.function_id, &target).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct ListGrantsRequest {
    function_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupGrant {
    group_id: String,
    attributes: Attributes,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserGrant {
    user_id: Uuid,
    attributes: Attributes,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListGrantsResponse {
    groups: Vec<GroupGrant>,
    users: Vec<UserGrant>,
}

async fn list_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ListGrantsRequest>,
) -> Result<Json<ListGrantsResponse>, AppError> {
    require_admin(&state, &headers, "/api/admin/grants/list").await?;
    let grants = repo::list_grants(&state.db, &req.function_id).await?;
    Ok(Json(ListGrantsResponse {
        groups: grants
            .groups
            .into_iter()
            .map(|(group_id, attributes)| GroupGrant {
                group_id,
                attributes,
            })
            .collect(),
        users: grants
            .users
            .into_iter()
            .map(|(user_id, attributes)| UserGrant {
                user_id,
                attributes,
            })
            .collect(),
    }))
}

#[derive(Debug, Serialize, Deserialize)]
struct ListUsersResponse {
    users: Vec<User>,
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListUsersResponse>, AppError> {
    require_admin(&state, &headers, "/api/admin/users/list").await?;
    let users = repo::list_users(&state.db).await?;
    Ok(Json(ListUsersResponse { users }))
}

#[derive(Debug, Deserialize)]
struct UserGroupsRequest {
    user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserGroupsResponse {
    group_ids: Vec<String>,
}

async fn user_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UserGroupsRequest>,
) -> Result<Json<UserGroupsResponse>, AppError> {
    require_admin(&state, &headers, "/api/admin/users/groups").await?;
    let group_ids = repo::list_user_groups(&state.db, req.user_id).await?;
    Ok(Json(UserGroupsResponse { group_ids }))
}

#[derive(Debug, Deserialize)]
struct GroupFunctionsRequest {
    group_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupFunctionGrant {
    function_id: String,
    attributes: Attributes,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupFunctionsResponse {
    functions: Vec<GroupFunctionGrant>,
}

async fn group_functions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GroupFunctionsRequest>,
) -> Result<Json<GroupFunctionsResponse>, AppError> {
    require_admin(&state, &headers, "/api/admin/groups/functions").await?;
    let functions = repo::list_group_functions(&state.db, &req.group_id).await?;
    Ok(Json(GroupFunctionsResponse {
        functions: functions
            .into_iter()
            .map(|(function_id, attributes)| GroupFunctionGrant {
                function_id,
                attributes,
            })
            .collect(),
    }))
}

#[derive(Debug)]
enum AppError {
    MissingAuthorizationHeader,
    MissingDpopProof,
    Session(SessionError),
    AuthorizationServiceUnreachable(reqwest::Error),
    Forbidden,
    BadRequest(String),
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
            AppError::AuthorizationServiceUnreachable(e) => {
                tracing::error!(?e, "authorization service call failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "not authorized for the admin function".to_string(),
            ),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
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
    use chrono::Utc;
    use common::firestore::{COLLECTION_FUNCTIONS, COLLECTION_SESSIONS};
    use common::models::Session;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    use futures::stream::TryStreamExt;
    use serde_json::json;

    async fn test_db() -> FirestoreDb {
        let config = common::Config::from_env();
        common::firestore::connect(&config)
            .await
            .expect("connect to firestore")
    }

    /// Spawns the real `authorization` server (a dev-dependency) on an
    /// ephemeral port, so admin-gating tests exercise the actual service.
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

    async fn spawn_admin_server(db: FirestoreDb, authorization_url: String) -> String {
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

    /// Grants `user_id` the "admin" function directly (a user override, no
    /// group needed) — the same bootstrap mechanism a real deployment would
    /// use to seed its first admin.
    async fn make_admin(db: &FirestoreDb, user_id: Uuid) {
        let parent = db.parent_path(COLLECTION_FUNCTIONS, "admin").unwrap();
        db.fluent()
            .update()
            .in_col(common::firestore::COLLECTION_USERS)
            .document_id(user_id.to_string())
            .parent(&parent)
            .object(&Attributes::new())
            .execute::<Attributes>()
            .await
            .unwrap();
    }

    /// Sets up a real admin session ready to call `base_url`: a live
    /// session plus the `admin` grant, and returns the key/token needed to
    /// sign requests with.
    async fn admin_session(db: &FirestoreDb) -> (TestKey, String) {
        let key = generate_test_key();
        let user_id = Uuid::new_v4();
        let jkt = common::dpop::jwk_thumbprint(&key.x, &key.y);
        let token = seed_session(db, user_id, &jkt).await;
        make_admin(db, user_id).await;
        (key, token)
    }

    fn authed_post(
        client: &reqwest::Client,
        url: &str,
        key: &TestKey,
        token: &str,
    ) -> reqwest::RequestBuilder {
        let proof = sign_proof(key, "POST", url);
        client
            .post(url)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
    }

    #[tokio::test]
    async fn upsert_function_then_list_shows_it() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();
        let function_id = format!("test-fn-{}", Uuid::new_v4());

        let create_url = format!("{base_url}/api/admin/functions");
        let res = authed_post(&client, &create_url, &key, &token)
            .json(&json!({"function_id": function_id, "name": "Test Fn", "description": "a test function"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);

        let list_url = format!("{base_url}/api/admin/functions/list");
        let list: ListFunctionsResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(list
            .functions
            .iter()
            .any(|f| f.function_id.as_deref() == Some(function_id.as_str()) && f.name == "Test Fn"));
    }

    #[tokio::test]
    async fn upsert_group_then_list_shows_it() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();
        let group_id = format!("test-group-{}", Uuid::new_v4());

        let create_url = format!("{base_url}/api/admin/groups");
        let res = authed_post(&client, &create_url, &key, &token)
            .json(&json!({"group_id": group_id, "name": "Test Group"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);

        let list_url = format!("{base_url}/api/admin/groups/list");
        let list: ListGroupsResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(list
            .groups
            .iter()
            .any(|g| g.group_id.as_deref() == Some(group_id.as_str()) && g.name == "Test Group"));
    }

    #[tokio::test]
    async fn add_member_then_list_then_remove() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();
        let group_id = format!("test-group-{}", Uuid::new_v4());
        let member_id = Uuid::new_v4();

        let add_url = format!("{base_url}/api/admin/groups/members/add");
        let res = authed_post(&client, &add_url, &key, &token)
            .json(&json!({"group_id": group_id, "user_id": member_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);

        let list_url = format!("{base_url}/api/admin/groups/members/list");
        let list: ListGroupMembersResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({"group_id": group_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(list.user_ids.contains(&member_id));

        // Also verify the reverse index (users/{uid}/groups/{gid}) landed.
        let user_groups: Vec<common::models::GroupMembership> = db
            .fluent()
            .list()
            .from(common::firestore::COLLECTION_GROUPS)
            .parent(
                db.parent_path(common::firestore::COLLECTION_USERS, member_id.to_string())
                    .unwrap(),
            )
            .obj()
            .stream_all_with_errors()
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();
        assert!(user_groups
            .iter()
            .any(|m| m.group_id.as_deref() == Some(group_id.as_str())));

        let remove_url = format!("{base_url}/api/admin/groups/members/remove");
        let res = authed_post(&client, &remove_url, &key, &token)
            .json(&json!({"group_id": group_id, "user_id": member_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);

        let list: ListGroupMembersResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({"group_id": group_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(!list.user_ids.contains(&member_id));
    }

    #[tokio::test]
    async fn set_grant_to_group_and_to_user_then_revoke() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();
        let function_id = format!("test-fn-{}", Uuid::new_v4());
        let group_id = format!("test-group-{}", Uuid::new_v4());
        let user_id = Uuid::new_v4();

        let set_url = format!("{base_url}/api/admin/grants");
        let res = authed_post(&client, &set_url, &key, &token)
            .json(&json!({"function_id": function_id, "group_id": group_id, "attributes": {"department": "engineering"}}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);

        let res = authed_post(&client, &set_url, &key, &token)
            .json(&json!({"function_id": function_id, "user_id": user_id, "attributes": {"approval_limit": 500}}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);

        let list_url = format!("{base_url}/api/admin/grants/list");
        let list: ListGrantsResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({"function_id": function_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(list.groups.iter().any(|g| g.group_id == group_id));
        assert!(list.users.iter().any(|u| u.user_id == user_id));

        let revoke_url = format!("{base_url}/api/admin/grants/revoke");
        let res = authed_post(&client, &revoke_url, &key, &token)
            .json(&json!({"function_id": function_id, "group_id": group_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);

        let list: ListGrantsResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({"function_id": function_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(!list.groups.iter().any(|g| g.group_id == group_id));
        assert!(list.users.iter().any(|u| u.user_id == user_id));
    }

    #[tokio::test]
    async fn grant_with_both_group_and_user_is_rejected() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();

        let set_url = format!("{base_url}/api/admin/grants");
        let res = authed_post(&client, &set_url, &key, &token)
            .json(&json!({
                "function_id": "whatever",
                "group_id": "some-group",
                "user_id": Uuid::new_v4(),
                "attributes": {}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn non_admin_is_forbidden() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let client = reqwest::Client::new();

        // A real, live session — just never granted the "admin" function.
        let key = generate_test_key();
        let user_id = Uuid::new_v4();
        let jkt = common::dpop::jwk_thumbprint(&key.x, &key.y);
        let token = seed_session(&db, user_id, &jkt).await;

        let url = format!("{base_url}/api/admin/groups");
        let res = authed_post(&client, &url, &key, &token)
            .json(&json!({"group_id": "whatever", "name": "whatever"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403);
    }

    #[tokio::test]
    async fn missing_authorization_header_is_rejected() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let client = reqwest::Client::new();

        let url = format!("{base_url}/api/admin/groups");
        let res = client
            .post(&url)
            .json(&json!({"group_id": "whatever", "name": "whatever"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401);
    }

    #[tokio::test]
    async fn list_users_shows_a_registered_user() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();

        let user_id = Uuid::new_v4();
        db.fluent()
            .insert()
            .into(common::firestore::COLLECTION_USERS)
            .document_id(user_id.to_string())
            .object(&common::models::User {
                user_id,
                username: format!("test-user-{user_id}"),
                display_name: "Test User".to_string(),
                created_at: Utc::now(),
            })
            .execute::<common::models::User>()
            .await
            .unwrap();

        let list_url = format!("{base_url}/api/admin/users/list");
        let list: ListUsersResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(list.users.iter().any(|u| u.user_id == user_id));
    }

    #[tokio::test]
    async fn user_groups_reflects_membership() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();
        let group_id = format!("test-group-{}", Uuid::new_v4());
        let member_id = Uuid::new_v4();

        let add_url = format!("{base_url}/api/admin/groups/members/add");
        authed_post(&client, &add_url, &key, &token)
            .json(&json!({"group_id": group_id, "user_id": member_id}))
            .send()
            .await
            .unwrap();

        let groups_url = format!("{base_url}/api/admin/users/groups");
        let res: UserGroupsResponse = authed_post(&client, &groups_url, &key, &token)
            .json(&json!({"user_id": member_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(res.group_ids.contains(&group_id));
    }

    #[tokio::test]
    async fn group_functions_reflects_grants_and_revokes() {
        let db = test_db().await;
        let authorization_url = spawn_authorization_server(db.clone()).await;
        let base_url = spawn_admin_server(db.clone(), authorization_url).await;
        let (key, token) = admin_session(&db).await;
        let client = reqwest::Client::new();
        let function_id = format!("test-fn-{}", Uuid::new_v4());
        let group_id = format!("test-group-{}", Uuid::new_v4());

        let set_url = format!("{base_url}/api/admin/grants");
        authed_post(&client, &set_url, &key, &token)
            .json(&json!({"function_id": function_id, "group_id": group_id, "attributes": {}}))
            .send()
            .await
            .unwrap();

        let list_url = format!("{base_url}/api/admin/groups/functions");
        let res: GroupFunctionsResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({"group_id": group_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(res
            .functions
            .iter()
            .any(|f| f.function_id == function_id));

        let revoke_url = format!("{base_url}/api/admin/grants/revoke");
        authed_post(&client, &revoke_url, &key, &token)
            .json(&json!({"function_id": function_id, "group_id": group_id}))
            .send()
            .await
            .unwrap();

        let res: GroupFunctionsResponse = authed_post(&client, &list_url, &key, &token)
            .json(&json!({"group_id": group_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(!res
            .functions
            .iter()
            .any(|f| f.function_id == function_id));
    }
}
