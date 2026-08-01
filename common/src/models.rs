use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Document stored at `users/{user_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

/// Document stored at `usernames/{username}`, used only to enforce
/// username uniqueness (Firestore has no unique-constraint support).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameLock {
    pub user_id: Uuid,
}

/// Document stored at `users/{user_id}/credentials/{credential_id}`.
/// Wraps a `webauthn-rs` `Passkey`, which is itself `serde`-serializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub passkey: webauthn_rs::prelude::Passkey,
    pub created_at: DateTime<Utc>,
}

/// Document stored at `sessions/{session::hash_token(token)}`. Written by
/// logon, read/deleted by logout, and (later) read by the authorization
/// function — shared across functions, unlike `webauthn.rs`'s pattern of
/// deliberate per-function duplication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub user_id: Uuid,
    pub jkt: String,
    pub expires_at: DateTime<Utc>,
}
