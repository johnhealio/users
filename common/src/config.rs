use std::env;

/// Shared runtime configuration, loaded from environment variables so the
/// same binary works locally and on Cloud Run without code changes.
#[derive(Debug, Clone)]
pub struct Config {
    pub gcp_project: String,
    pub firestore_database_id: String,
    pub port: u16,
    pub rp_id: String,
    pub rp_origin: String,
    /// Base URL of the authorization service, used by any function that
    /// needs to check what a session is allowed to do.
    pub authorization_url: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            gcp_project: env::var("GOOGLE_CLOUD_PROJECT")
                .expect("GOOGLE_CLOUD_PROJECT must be set"),
            firestore_database_id: env::var("FIRESTORE_DATABASE_ID")
                .unwrap_or_else(|_| "users-dev".to_string()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8081),
            rp_id: env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            rp_origin: env::var("RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8081".to_string()),
            authorization_url: env::var("AUTHORIZATION_URL")
                .unwrap_or_else(|_| "http://localhost:8084".to_string()),
        }
    }
}
