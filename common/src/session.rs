use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use firestore::FirestoreDb;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::dpop::{self, DpopError};
use crate::firestore::COLLECTION_SESSIONS;
use crate::models::Session;

/// Doc IDs in `sessions` are a hash of the opaque token, not the token
/// itself, so a Firestore read/leak doesn't hand out live bearer-equivalent
/// secrets.
pub fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

#[derive(Debug)]
pub struct AuthenticatedSession {
    pub user_id: Uuid,
    pub token: String,
    pub token_hash: String,
}

#[derive(Debug)]
pub enum SessionError {
    InvalidAuthorizationScheme,
    SessionNotFound,
    SessionExpired,
    /// The DPoP proof was well-formed and correctly signed, but by a
    /// different key than the one bound to this session at logon — this is
    /// the actual point of DPoP: a stolen token alone isn't enough.
    KeyMismatch,
    Dpop(DpopError),
    Firestore(firestore::errors::FirestoreError),
}

impl From<firestore::errors::FirestoreError> for SessionError {
    fn from(e: firestore::errors::FirestoreError) -> Self {
        SessionError::Firestore(e)
    }
}

/// Loads the session named by a raw opaque token and checks it hasn't
/// expired. Doesn't verify a DPoP proof — callers that need proof-of-
/// possession (i.e. anything talking directly to a browser) should use
/// [`authenticate`] instead; this is for server-to-server checks where the
/// browser's proof was already verified once, at the API the browser's
/// request actually landed on.
pub async fn load_active_session(db: &FirestoreDb, token: &str) -> Result<Session, SessionError> {
    let token_hash = hash_token(token);
    let session: Option<Session> = db
        .fluent()
        .select()
        .by_id_in(COLLECTION_SESSIONS)
        .obj()
        .one(&token_hash)
        .await?;
    let session = session.ok_or(SessionError::SessionNotFound)?;

    if session.expires_at < Utc::now() {
        return Err(SessionError::SessionExpired);
    }

    Ok(session)
}

/// Authenticates a request against an existing session: parses the
/// `Authorization: DPoP <token>` header (RFC 9449), loads the session it
/// names, verifies the accompanying DPoP proof, and checks the proof's key
/// thumbprint matches the one bound to the session at logon.
pub async fn authenticate(
    db: &FirestoreDb,
    authorization_header: &str,
    dpop_proof: &str,
    expected_htm: &str,
    expected_htu: &str,
) -> Result<AuthenticatedSession, SessionError> {
    let token = parse_dpop_authorization(authorization_header)?;
    let session = load_active_session(db, token).await?;

    let verified = dpop::verify_proof(db, dpop_proof, expected_htm, expected_htu)
        .await
        .map_err(SessionError::Dpop)?;

    if verified.jkt != session.jkt {
        return Err(SessionError::KeyMismatch);
    }

    Ok(AuthenticatedSession {
        user_id: session.user_id,
        token: token.to_string(),
        token_hash: hash_token(token),
    })
}

fn parse_dpop_authorization(header: &str) -> Result<&str, SessionError> {
    let mut parts = header.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let token = parts
        .next()
        .filter(|t| !t.is_empty())
        .ok_or(SessionError::InvalidAuthorizationScheme)?;
    if !scheme.eq_ignore_ascii_case("DPoP") {
        return Err(SessionError::InvalidAuthorizationScheme);
    }
    Ok(token)
}
