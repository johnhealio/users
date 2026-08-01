pub mod repo;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use common::models::Attributes;
use firestore::FirestoreDb;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: FirestoreDb,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/authorize", post(authorize))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct AuthorizeRequest {
    session_id: String,
    function_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Attributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuthorizeResponse {
    fn denied(reason: &str) -> Self {
        Self {
            authorized: false,
            user_id: None,
            attributes: None,
            reason: Some(reason.to_string()),
        }
    }
}

/// Always responds 200 for a well-formed request: whether the caller is
/// authorized is the answer this endpoint exists to give, not an HTTP-
/// semantic error. Malformed request bodies still get axum's normal 4xx.
async fn authorize(
    State(state): State<AppState>,
    Json(req): Json<AuthorizeRequest>,
) -> Json<AuthorizeResponse> {
    let session = match common::session::load_active_session(&state.db, &req.session_id).await {
        Ok(session) => session,
        Err(e) => {
            tracing::info!(?e, "session lookup failed");
            return Json(AuthorizeResponse::denied("invalid or expired session"));
        }
    };

    match repo::resolve_access(&state.db, session.user_id, &req.function_id).await {
        Ok(Some(attributes)) => Json(AuthorizeResponse {
            authorized: true,
            user_id: Some(session.user_id),
            attributes: Some(attributes),
            reason: None,
        }),
        Ok(None) => Json(AuthorizeResponse::denied("not authorized for this function")),
        Err(e) => {
            tracing::error!(?e, "firestore error resolving access");
            Json(AuthorizeResponse::denied("internal error"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::firestore::{COLLECTION_FUNCTIONS, COLLECTION_GROUPS, COLLECTION_SESSIONS};
    use common::models::{GroupMembership, Session};
    use common::Config;
    use serde_json::json;

    async fn test_db() -> FirestoreDb {
        let config = Config::from_env();
        common::firestore::connect(&config)
            .await
            .expect("connect to firestore")
    }

    async fn spawn_server(db: FirestoreDb) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let state = AppState { db };
        tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn seed_session(db: &FirestoreDb, user_id: Uuid) -> String {
        let token = Uuid::new_v4().to_string();
        let session = Session {
            user_id,
            jkt: "unused-in-authorization-checks".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
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

    async fn seed_function_group_attributes(
        db: &FirestoreDb,
        function_id: &str,
        group_id: &str,
        attrs: &Attributes,
    ) {
        let parent = db.parent_path(COLLECTION_FUNCTIONS, function_id).unwrap();
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

    async fn seed_function_user_attributes(
        db: &FirestoreDb,
        function_id: &str,
        user_id: Uuid,
        attrs: &Attributes,
    ) {
        let parent = db.parent_path(COLLECTION_FUNCTIONS, function_id).unwrap();
        db.fluent()
            .insert()
            .into(common::firestore::COLLECTION_USERS)
            .document_id(user_id.to_string())
            .parent(&parent)
            .object(attrs)
            .execute::<Attributes>()
            .await
            .unwrap();
    }

    fn attrs(json_obj: serde_json::Value) -> Attributes {
        serde_json::from_value(json_obj).unwrap()
    }

    #[tokio::test]
    async fn authorized_via_group_membership() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;
        let user_id = Uuid::new_v4();
        let function_id = format!("test-fn-{}", Uuid::new_v4());
        let group_id = format!("test-group-{}", Uuid::new_v4());

        let token = seed_session(&db, user_id).await;
        seed_group_membership(&db, user_id, &group_id).await;
        seed_function_group_attributes(
            &db,
            &function_id,
            &group_id,
            &attrs(json!({"department": "engineering"})),
        )
        .await;

        let client = reqwest::Client::new();
        let res: AuthorizeResponse = client
            .post(format!("{base_url}/api/authorize"))
            .json(&json!({"session_id": token, "function_id": function_id}))
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
            "engineering"
        );
    }

    #[tokio::test]
    async fn authorized_via_user_override_alone() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;
        let user_id = Uuid::new_v4();
        let function_id = format!("test-fn-{}", Uuid::new_v4());

        let token = seed_session(&db, user_id).await;
        // No group membership at all — only a direct per-user grant.
        seed_function_user_attributes(
            &db,
            &function_id,
            user_id,
            &attrs(json!({"approval_limit": 100})),
        )
        .await;

        let client = reqwest::Client::new();
        let res: AuthorizeResponse = client
            .post(format!("{base_url}/api/authorize"))
            .json(&json!({"session_id": token, "function_id": function_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(res.authorized);
        assert_eq!(res.attributes.unwrap().get("approval_limit").unwrap(), 100);
    }

    #[tokio::test]
    async fn user_override_merges_over_group_attributes() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;
        let user_id = Uuid::new_v4();
        let function_id = format!("test-fn-{}", Uuid::new_v4());
        let group_id = format!("test-group-{}", Uuid::new_v4());

        let token = seed_session(&db, user_id).await;
        seed_group_membership(&db, user_id, &group_id).await;
        seed_function_group_attributes(
            &db,
            &function_id,
            &group_id,
            &attrs(json!({"department": "engineering", "approval_limit": 100})),
        )
        .await;
        seed_function_user_attributes(
            &db,
            &function_id,
            user_id,
            &attrs(json!({"approval_limit": 500})),
        )
        .await;

        let client = reqwest::Client::new();
        let res: AuthorizeResponse = client
            .post(format!("{base_url}/api/authorize"))
            .json(&json!({"session_id": token, "function_id": function_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(res.authorized);
        let attributes = res.attributes.unwrap();
        assert_eq!(attributes.get("department").unwrap(), "engineering");
        assert_eq!(attributes.get("approval_limit").unwrap(), 500);
    }

    #[tokio::test]
    async fn unknown_session_is_denied() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;

        let client = reqwest::Client::new();
        let res: AuthorizeResponse = client
            .post(format!("{base_url}/api/authorize"))
            .json(&json!({"session_id": "does-not-exist", "function_id": "whatever"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(!res.authorized);
        assert!(res.reason.is_some());
    }

    #[tokio::test]
    async fn unpermitted_function_is_denied() {
        let db = test_db().await;
        let base_url = spawn_server(db.clone()).await;
        let user_id = Uuid::new_v4();
        let function_id = format!("test-fn-{}", Uuid::new_v4());
        let group_id = format!("test-group-{}", Uuid::new_v4());

        let token = seed_session(&db, user_id).await;
        // User is in a group, but that group has no grant for this function.
        seed_group_membership(&db, user_id, &group_id).await;

        let client = reqwest::Client::new();
        let res: AuthorizeResponse = client
            .post(format!("{base_url}/api/authorize"))
            .json(&json!({"session_id": token, "function_id": function_id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(!res.authorized);
    }
}
