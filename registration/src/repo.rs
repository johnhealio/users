use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use common::firestore::{
    COLLECTION_CREDENTIALS, COLLECTION_REGISTRATION_SESSIONS, COLLECTION_USERNAMES,
    COLLECTION_USERS,
};
use common::models::{StoredCredential, User, UsernameLock};
use firestore::{FirestoreDb, FirestoreResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{CredentialID, Passkey, PasskeyRegistration};

const REGISTRATION_SESSION_TTL_MINUTES: i64 = 5;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationSession {
    pub state: PasskeyRegistration,
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub expires_at: DateTime<Utc>,
}

impl RegistrationSession {
    pub fn new(state: PasskeyRegistration, user_id: Uuid, username: String, display_name: String) -> Self {
        Self {
            state,
            user_id,
            username,
            display_name,
            expires_at: Utc::now() + Duration::minutes(REGISTRATION_SESSION_TTL_MINUTES),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

pub fn encode_credential_id(id: &CredentialID) -> String {
    URL_SAFE_NO_PAD.encode(id.as_ref())
}

pub async fn username_exists(db: &FirestoreDb, username: &str) -> FirestoreResult<bool> {
    let existing: Option<UsernameLock> = db
        .fluent()
        .select()
        .by_id_in(COLLECTION_USERNAMES)
        .obj()
        .one(username)
        .await?;
    Ok(existing.is_some())
}

pub async fn save_registration_session(
    db: &FirestoreDb,
    session_id: &str,
    session: &RegistrationSession,
) -> FirestoreResult<()> {
    db.fluent()
        .insert()
        .into(COLLECTION_REGISTRATION_SESSIONS)
        .document_id(session_id)
        .object(session)
        .execute::<RegistrationSession>()
        .await?;
    Ok(())
}

/// Loads and deletes the session in one step: a registration ceremony can
/// only ever be completed once.
pub async fn take_registration_session(
    db: &FirestoreDb,
    session_id: &str,
) -> FirestoreResult<Option<RegistrationSession>> {
    let session: Option<RegistrationSession> = db
        .fluent()
        .select()
        .by_id_in(COLLECTION_REGISTRATION_SESSIONS)
        .obj()
        .one(session_id)
        .await?;

    if session.is_some() {
        db.fluent()
            .delete()
            .from(COLLECTION_REGISTRATION_SESSIONS)
            .document_id(session_id)
            .execute()
            .await?;
    }

    Ok(session)
}

/// Persists the newly registered user. `usernames/{username}` is written
/// first: Firestore's create semantics reject the write if the document
/// already exists, which is what actually enforces uniqueness under
/// concurrent registrations (the earlier `username_exists` check is only a
/// fast-path, not a correctness guarantee).
pub async fn complete_registration(
    db: &FirestoreDb,
    user: &User,
    passkey: &Passkey,
) -> FirestoreResult<()> {
    db.fluent()
        .insert()
        .into(COLLECTION_USERNAMES)
        .document_id(&user.username)
        .object(&UsernameLock {
            user_id: user.user_id,
        })
        .execute::<UsernameLock>()
        .await?;

    db.fluent()
        .insert()
        .into(COLLECTION_USERS)
        .document_id(user.user_id.to_string())
        .object(user)
        .execute::<User>()
        .await?;

    let parent_path = db.parent_path(COLLECTION_USERS, user.user_id.to_string())?;
    let stored = StoredCredential {
        passkey: passkey.clone(),
        created_at: Utc::now(),
    };
    db.fluent()
        .insert()
        .into(COLLECTION_CREDENTIALS)
        .document_id(encode_credential_id(passkey.cred_id()))
        .parent(&parent_path)
        .object(&stored)
        .execute::<StoredCredential>()
        .await?;

    Ok(())
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
    async fn username_exists_is_false_for_unknown_user() {
        let db = test_db().await;
        let username = format!("test-nonexistent-{}", Uuid::new_v4());
        assert!(!username_exists(&db, &username).await.unwrap());
    }

    #[tokio::test]
    async fn registration_session_round_trips_and_is_deleted_on_take() {
        let db = test_db().await;
        let rp_origin = Url::parse("http://localhost:8081").unwrap();
        let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
            .unwrap()
            .build()
            .unwrap();
        let user_id = Uuid::new_v4();
        let (_, reg_state) = webauthn
            .start_passkey_registration(user_id, "tester", "Tester", None)
            .unwrap();

        let session_id = format!("test-session-{}", Uuid::new_v4());
        let session = RegistrationSession::new(reg_state, user_id, "tester".into(), "Tester".into());
        save_registration_session(&db, &session_id, &session)
            .await
            .unwrap();

        let loaded = take_registration_session(&db, &session_id).await.unwrap();
        assert_eq!(loaded.map(|s| s.user_id), Some(user_id));

        let second_take = take_registration_session(&db, &session_id).await.unwrap();
        assert!(second_take.is_none());
    }
}
