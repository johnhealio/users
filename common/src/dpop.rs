use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use firestore::FirestoreDb;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::firestore::COLLECTION_DPOP_REPLAY;

/// How far a proof's `iat` may drift from the server's clock before it's
/// rejected as stale. Also bounds how long a `jti` needs to be remembered
/// for replay detection.
const IAT_TOLERANCE_SECONDS: i64 = 60;

#[derive(Debug, Serialize, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DpopReplayMarker {
    created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct VerifiedProof {
    /// RFC 7638 JWK thumbprint of the public key that signed this proof.
    pub jkt: String,
}

#[derive(Debug)]
pub enum DpopError {
    MissingOrMalformedHeader,
    UnsupportedType,
    UnsupportedAlgorithm,
    UnsupportedKeyType,
    /// Signature verification or claims decoding failed (jsonwebtoken
    /// combines both into a single `decode()` result).
    InvalidProof(jsonwebtoken::errors::Error),
    MethodMismatch,
    UrlMismatch,
    StaleProof,
    Replayed,
    Firestore(firestore::errors::FirestoreError),
}

impl From<firestore::errors::FirestoreError> for DpopError {
    fn from(e: firestore::errors::FirestoreError) -> Self {
        DpopError::Firestore(e)
    }
}

/// Verifies a DPoP proof (RFC 9449) attached to a request, and returns the
/// thumbprint of the key that signed it.
///
/// The proof is self-verifying: its header carries the public key it was
/// signed with, so signature verification alone only proves possession of
/// that key at signing time — not that the key is trusted. Trust comes
/// from the caller binding the returned `jkt` to something (a session, in
/// this project) and requiring the same key on every later use of it.
pub async fn verify_proof(
    db: &FirestoreDb,
    proof: &str,
    expected_htm: &str,
    expected_htu: &str,
) -> Result<VerifiedProof, DpopError> {
    let header = decode_header(proof).map_err(|_| DpopError::MissingOrMalformedHeader)?;

    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(DpopError::UnsupportedType);
    }
    if header.alg != Algorithm::ES256 {
        return Err(DpopError::UnsupportedAlgorithm);
    }
    let jwk = header.jwk.ok_or(DpopError::MissingOrMalformedHeader)?;
    let (x, y) = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) if ec.curve == EllipticCurve::P256 => {
            (ec.x.clone(), ec.y.clone())
        }
        _ => return Err(DpopError::UnsupportedKeyType),
    };

    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(DpopError::InvalidProof)?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let claims = decode::<DpopClaims>(proof, &decoding_key, &validation)
        .map_err(DpopError::InvalidProof)?
        .claims;

    if claims.htm != expected_htm {
        return Err(DpopError::MethodMismatch);
    }
    if claims.htu != expected_htu {
        return Err(DpopError::UrlMismatch);
    }
    if (Utc::now().timestamp() - claims.iat).abs() > IAT_TOLERANCE_SECONDS {
        return Err(DpopError::StaleProof);
    }

    // Replay defense: Firestore's create semantics reject this write if a
    // document with this jti already exists — same trick used for
    // usernames/{username} uniqueness in registration/src/repo.rs.
    let insert_result = db
        .fluent()
        .insert()
        .into(COLLECTION_DPOP_REPLAY)
        .document_id(&claims.jti)
        .object(&DpopReplayMarker {
            created_at: Utc::now(),
        })
        .execute::<DpopReplayMarker>()
        .await;

    if let Err(e) = insert_result {
        return Err(if format!("{e:?}").contains("AlreadyExists") {
            DpopError::Replayed
        } else {
            DpopError::Firestore(e)
        });
    }

    Ok(VerifiedProof {
        jkt: jwk_thumbprint(&x, &y),
    })
}

/// RFC 7638 JWK thumbprint for an EC P-256 key: SHA-256 of the canonical
/// JSON representation, with members in exactly this order (no whitespace).
pub fn jwk_thumbprint(x: &str, y: &str) -> String {
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    use serde_json::json;
    use uuid::Uuid;

    async fn test_db() -> FirestoreDb {
        let config = Config::from_env();
        crate::firestore::connect(&config)
            .await
            .expect("connect to firestore")
    }

    struct TestKey {
        signing_key: SigningKey,
        jwk: Jwk,
    }

    fn generate_test_key() -> TestKey {
        let signing_key = SigningKey::random(&mut OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let jwk: Jwk =
            serde_json::from_value(json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
                .unwrap();
        TestKey { signing_key, jwk }
    }

    fn sign_proof(key: &TestKey, jti: &str, htm: &str, htu: &str, iat: i64) -> String {
        sign_proof_with_header_jwk(key, &key.jwk.clone(), jti, htm, htu, iat)
    }

    fn sign_proof_with_header_jwk(
        key: &TestKey,
        header_jwk: &Jwk,
        jti: &str,
        htm: &str,
        htu: &str,
        iat: i64,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(header_jwk.clone());
        let claims = DpopClaims {
            jti: jti.to_string(),
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat,
        };
        let der = key.signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        encode(&header, &claims, &EncodingKey::from_ec_der(&der)).unwrap()
    }

    fn test_jti() -> String {
        format!("test-jti-{}", Uuid::new_v4())
    }

    #[tokio::test]
    async fn valid_proof_is_accepted_and_returns_matching_jkt() {
        let db = test_db().await;
        let key = generate_test_key();
        let proof = sign_proof(
            &key,
            &test_jti(),
            "POST",
            "http://localhost/test",
            Utc::now().timestamp(),
        );

        let verified = verify_proof(&db, &proof, "POST", "http://localhost/test")
            .await
            .expect("valid proof should verify");

        let (x, y) = match &key.jwk.algorithm {
            AlgorithmParameters::EllipticCurve(ec) => (ec.x.clone(), ec.y.clone()),
            _ => unreachable!(),
        };
        assert_eq!(verified.jkt, jwk_thumbprint(&x, &y));
    }

    #[tokio::test]
    async fn wrong_method_is_rejected() {
        let db = test_db().await;
        let key = generate_test_key();
        let proof = sign_proof(
            &key,
            &test_jti(),
            "GET",
            "http://localhost/test",
            Utc::now().timestamp(),
        );

        let result = verify_proof(&db, &proof, "POST", "http://localhost/test").await;
        assert!(matches!(result, Err(DpopError::MethodMismatch)));
    }

    #[tokio::test]
    async fn wrong_url_is_rejected() {
        let db = test_db().await;
        let key = generate_test_key();
        let proof = sign_proof(
            &key,
            &test_jti(),
            "POST",
            "http://localhost/other",
            Utc::now().timestamp(),
        );

        let result = verify_proof(&db, &proof, "POST", "http://localhost/test").await;
        assert!(matches!(result, Err(DpopError::UrlMismatch)));
    }

    #[tokio::test]
    async fn stale_iat_is_rejected() {
        let db = test_db().await;
        let key = generate_test_key();
        let stale_iat = Utc::now().timestamp() - 3600;
        let proof = sign_proof(&key, &test_jti(), "POST", "http://localhost/test", stale_iat);

        let result = verify_proof(&db, &proof, "POST", "http://localhost/test").await;
        assert!(matches!(result, Err(DpopError::StaleProof)));
    }

    #[tokio::test]
    async fn replayed_jti_is_rejected_on_second_use() {
        let db = test_db().await;
        let key = generate_test_key();
        let jti = test_jti();
        let iat = Utc::now().timestamp();

        let proof1 = sign_proof(&key, &jti, "POST", "http://localhost/test", iat);
        let first = verify_proof(&db, &proof1, "POST", "http://localhost/test").await;
        assert!(first.is_ok());

        // Same jti again, even re-signed with a fresh iat, must be rejected.
        let proof2 = sign_proof(&key, &jti, "POST", "http://localhost/test", iat);
        let second = verify_proof(&db, &proof2, "POST", "http://localhost/test").await;
        assert!(matches!(second, Err(DpopError::Replayed)));
    }

    #[tokio::test]
    async fn forged_signature_is_rejected() {
        let db = test_db().await;
        let key = generate_test_key();
        let attacker_key = generate_test_key();

        // Header claims to carry `key`'s public JWK, but is actually signed
        // by `attacker_key`'s private key: an attacker who doesn't hold
        // `key`'s private key trying to pass off someone else's identity.
        let proof = sign_proof_with_header_jwk(
            &attacker_key,
            &key.jwk,
            &test_jti(),
            "POST",
            "http://localhost/test",
            Utc::now().timestamp(),
        );

        let result = verify_proof(&db, &proof, "POST", "http://localhost/test").await;
        assert!(matches!(result, Err(DpopError::InvalidProof(_))));
    }
}
