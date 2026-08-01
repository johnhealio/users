use crate::config::Config;
use firestore::{FirestoreDb, FirestoreDbOptions};

pub const COLLECTION_USERNAMES: &str = "usernames";
pub const COLLECTION_USERS: &str = "users";
pub const COLLECTION_CREDENTIALS: &str = "credentials";
pub const COLLECTION_REGISTRATION_SESSIONS: &str = "registration_sessions";
pub const COLLECTION_AUTHENTICATION_SESSIONS: &str = "authentication_sessions";

/// Connects to the named Firestore database configured for this deployment
/// (never the `(default)` database — this project doesn't have one).
pub async fn connect(config: &Config) -> Result<FirestoreDb, firestore::errors::FirestoreError> {
    let options = FirestoreDbOptions::new(config.gcp_project.clone())
        .with_database_id(config.firestore_database_id.clone());
    FirestoreDb::with_options(options).await
}
