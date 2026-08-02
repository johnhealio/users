//! One-off dev tool: mints a throwaway admin session bound to a key it
//! generates itself, uses it to call the real running `admin` service
//! (register the `check1` function, grant it to `joejones`), then revokes
//! its own admin grant and deletes the session — same bootstrap mechanism
//! `admin`'s own tests use (`make_admin` + `seed_session`), just pointed at
//! the live service instead of a spawned test instance.
//!
//! Requires `admin`, `authorization`, and the backends it fronts already
//! running behind the local nginx proxy at RP_ORIGIN. Run with:
//!   cargo run --example bootstrap_admin -p admin

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use common::firestore::{COLLECTION_FUNCTIONS, COLLECTION_SESSIONS, COLLECTION_USERS};
use common::models::{Attributes, Session};
use common::session::hash_token;
use common::Config;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePrivateKey;
use serde::Serialize;
use uuid::Uuid;

const RP_ORIGIN: &str = "http://localhost:8080";
const GRANT_FUNCTION_ID: &str = "check1";
const GRANT_TO_USER_ID: &str = "bfbc6c74-eaf1-4e6c-8935-bf50e9e42730"; // joejones

#[derive(Serialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
}

fn sign_proof(signing_key: &SigningKey, jwk: &Jwk, htm: &str, htu: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk.clone());
    let claims = DpopClaims {
        jti: Uuid::new_v4().to_string(),
        htm: htm.to_string(),
        htu: htu.to_string(),
        iat: Utc::now().timestamp(),
    };
    let der = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    encode(&header, &claims, &EncodingKey::from_ec_der(&der)).unwrap()
}

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let db = common::firestore::connect(&config)
        .await
        .expect("connect to firestore");

    // 1. Generate a throwaway DPoP keypair and its JWK thumbprint.
    let signing_key = SigningKey::random(&mut OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y
    }))
    .unwrap();
    let jkt = common::dpop::jwk_thumbprint(&x, &y);

    // 2. Seed a live session for a fresh bootstrap-admin user, bound to
    //    that key.
    let bootstrap_user_id = Uuid::new_v4();
    let token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&token);
    db.fluent()
        .insert()
        .into(COLLECTION_SESSIONS)
        .document_id(&token_hash)
        .object(&Session {
            user_id: bootstrap_user_id,
            jkt,
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        })
        .execute::<Session>()
        .await
        .expect("seed session");

    // 3. Grant that user the "admin" function directly (the one grant that
    //    has to be seeded outside the API, since nothing is admin yet).
    let admin_parent = db.parent_path(COLLECTION_FUNCTIONS, "admin").unwrap();
    db.fluent()
        .insert()
        .into(COLLECTION_USERS)
        .document_id(bootstrap_user_id.to_string())
        .parent(&admin_parent)
        .object(&Attributes::new())
        .execute::<Attributes>()
        .await
        .expect("grant bootstrap admin");
    println!("bootstrap admin user {bootstrap_user_id} granted admin");

    let client = reqwest::Client::new();
    let authed = |method: &str, path: &str| {
        let url = format!("{RP_ORIGIN}{path}");
        let proof = sign_proof(&signing_key, &jwk, method, &url);
        client
            .post(&url)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
    };

    // 4. Register the check1 function.
    let res = authed("POST", "/api/admin/functions")
        .json(&serde_json::json!({
            "function_id": GRANT_FUNCTION_ID,
            "name": "Check1",
            "description": "Demo authorization-gated function #1"
        }))
        .send()
        .await
        .expect("call admin/functions");
    println!("register check1 function: {}", res.status());
    assert!(res.status().is_success());

    // 5. Grant joejones access to it.
    let joejones_id: Uuid = GRANT_TO_USER_ID.parse().unwrap();
    let res = authed("POST", "/api/admin/grants")
        .json(&serde_json::json!({
            "function_id": GRANT_FUNCTION_ID,
            "user_id": joejones_id,
            "attributes": {}
        }))
        .send()
        .await
        .expect("call admin/grants");
    println!("grant check1 to joejones: {}", res.status());
    assert!(res.status().is_success());

    // 6. Clean up the bootstrap identity — it was only ever a means to make
    //    the two calls above through the real API instead of writing their
    //    target documents directly.
    db.fluent()
        .delete()
        .from(COLLECTION_USERS)
        .parent(&admin_parent)
        .document_id(bootstrap_user_id.to_string())
        .execute()
        .await
        .expect("revoke bootstrap admin");
    db.fluent()
        .delete()
        .from(COLLECTION_SESSIONS)
        .document_id(&token_hash)
        .execute()
        .await
        .expect("delete bootstrap session");
    println!("bootstrap admin identity revoked");
}
