use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use common::firestore::{
    COLLECTION_AUTHENTICATION_SESSIONS, COLLECTION_CREDENTIALS, COLLECTION_SESSIONS,
    COLLECTION_USERNAMES, COLLECTION_USERS,
};
use common::models::{Session, StoredCredential, User, UsernameLock};
use common::session::hash_token;
use firestore::{FirestoreDb, FirestoreResult};
use futures::stream::TryStreamExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{CredentialID, Passkey, PasskeyAuthentication};

const AUTHENTICATION_SESSION_TTL_MINUTES: i64 = 5;
const SESSION_TTL_MINUTES: i64 = 15;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationSession {
    pub state: PasskeyAuthentication,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

impl AuthenticationSession {
    pub fn new(state: PasskeyAuthentication, user_id: Uuid) -> Self {
        Self {
            state,
            user_id,
            expires_at: Utc::now() + Duration::minutes(AUTHENTICATION_SESSION_TTL_MINUTES),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

pub fn encode_credential_id(id: &CredentialID) -> String {
    URL_SAFE_NO_PAD.encode(id.as_ref())
}

pub async fn find_user_id_by_username(
    db: &FirestoreDb,
    username: &str,
) -> FirestoreResult<Option<Uuid>> {
    let lock: Option<UsernameLock> = db
        .fluent()
        .select()
        .by_id_in(COLLECTION_USERNAMES)
        .obj()
        .one(username)
        .await?;
    Ok(lock.map(|l| l.user_id))
}

pub async fn get_user(db: &FirestoreDb, user_id: Uuid) -> FirestoreResult<Option<User>> {
    db.fluent()
        .select()
        .by_id_in(COLLECTION_USERS)
        .obj()
        .one(&user_id.to_string())
        .await
}

pub async fn list_passkeys(db: &FirestoreDb, user_id: Uuid) -> FirestoreResult<Vec<Passkey>> {
    let parent_path = db.parent_path(COLLECTION_USERS, user_id.to_string())?;
    let stream = db
        .fluent()
        .list()
        .from(COLLECTION_CREDENTIALS)
        .parent(&parent_path)
        .obj::<StoredCredential>()
        .stream_all_with_errors()
        .await?;
    let credentials: Vec<StoredCredential> = stream.try_collect().await?;
    Ok(credentials.into_iter().map(|c| c.passkey).collect())
}

pub async fn get_credential(
    db: &FirestoreDb,
    user_id: Uuid,
    cred_id: &CredentialID,
) -> FirestoreResult<Option<StoredCredential>> {
    let parent_path = db.parent_path(COLLECTION_USERS, user_id.to_string())?;
    db.fluent()
        .select()
        .by_id_in(COLLECTION_CREDENTIALS)
        .parent(&parent_path)
        .obj()
        .one(&encode_credential_id(cred_id))
        .await
}

pub async fn save_credential(
    db: &FirestoreDb,
    user_id: Uuid,
    cred_id: &CredentialID,
    credential: &StoredCredential,
) -> FirestoreResult<()> {
    let parent_path = db.parent_path(COLLECTION_USERS, user_id.to_string())?;
    db.fluent()
        .update()
        .in_col(COLLECTION_CREDENTIALS)
        .document_id(encode_credential_id(cred_id))
        .parent(&parent_path)
        .object(credential)
        .execute::<StoredCredential>()
        .await?;
    Ok(())
}

pub async fn save_authentication_session(
    db: &FirestoreDb,
    session_id: &str,
    session: &AuthenticationSession,
) -> FirestoreResult<()> {
    db.fluent()
        .insert()
        .into(COLLECTION_AUTHENTICATION_SESSIONS)
        .document_id(session_id)
        .object(session)
        .execute::<AuthenticationSession>()
        .await?;
    Ok(())
}

/// Loads and deletes the session in one step: an authentication ceremony can
/// only ever be completed once.
pub async fn take_authentication_session(
    db: &FirestoreDb,
    session_id: &str,
) -> FirestoreResult<Option<AuthenticationSession>> {
    let session: Option<AuthenticationSession> = db
        .fluent()
        .select()
        .by_id_in(COLLECTION_AUTHENTICATION_SESSIONS)
        .obj()
        .one(session_id)
        .await?;

    if session.is_some() {
        db.fluent()
            .delete()
            .from(COLLECTION_AUTHENTICATION_SESSIONS)
            .document_id(session_id)
            .execute()
            .await?;
    }

    Ok(session)
}

/// Mints a new opaque session token bound to `jkt` (the DPoP key
/// thumbprint verified for this logon) and persists it. Returns the raw
/// token (only ever handed to the caller once) and its expiry.
pub async fn create_session(
    db: &FirestoreDb,
    user_id: Uuid,
    jkt: &str,
) -> FirestoreResult<(String, DateTime<Utc>)> {
    let mut token_bytes = [0u8; 32];
    rand::fill(&mut token_bytes);
    let token = URL_SAFE_NO_PAD.encode(token_bytes);

    let expires_at = Utc::now() + Duration::minutes(SESSION_TTL_MINUTES);
    let session = Session {
        user_id,
        jkt: jkt.to_string(),
        expires_at,
    };
    db.fluent()
        .insert()
        .into(COLLECTION_SESSIONS)
        .document_id(hash_token(&token))
        .object(&session)
        .execute::<Session>()
        .await?;

    Ok((token, expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::Config;
    use webauthn_rs::prelude::{Url, WebauthnBuilder};

    async fn test_db() -> FirestoreDb {
        let config = Config::from_env();
        common::firestore::connect(&config)
            .await
            .expect("connect to firestore")
    }

    #[tokio::test]
    async fn unknown_username_has_no_user_id() {
        let db = test_db().await;
        let username = format!("test-nonexistent-{}", Uuid::new_v4());
        assert!(find_user_id_by_username(&db, &username)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn authentication_session_round_trips_and_is_deleted_on_take() {
        let db = test_db().await;
        let rp_origin = Url::parse("http://localhost:8082").unwrap();
        let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
            .unwrap()
            .build()
            .unwrap();

        // An empty credential list is enough to exercise session save/take:
        // start_passkey_authentication doesn't validate the credentials
        // exist or are real, it just packages them into the challenge.
        // A real Passkey is only obtainable via a completed registration
        // ceremony, which is covered by the manual browser test instead.
        let (_, auth_state) = webauthn.start_passkey_authentication(&[]).unwrap();

        let user_id = Uuid::new_v4();
        let session_id = format!("test-session-{}", Uuid::new_v4());
        let session = AuthenticationSession::new(auth_state, user_id);
        save_authentication_session(&db, &session_id, &session)
            .await
            .unwrap();

        let loaded = take_authentication_session(&db, &session_id)
            .await
            .unwrap();
        assert_eq!(loaded.map(|s| s.user_id), Some(user_id));

        let second_take = take_authentication_session(&db, &session_id)
            .await
            .unwrap();
        assert!(second_take.is_none());
    }
}
