//! One-off verification of the three new admin endpoints
//! (`/api/admin/users/list`, `/api/admin/users/groups`,
//! `/api/admin/groups/functions`) against the real running `admin`
//! service, using the same throwaway-bootstrap-admin technique as
//! `bootstrap_admin.rs`.
//!
//! Run with: cargo run --example verify_new_endpoints -p admin

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
const JOEJONES_ID: &str = "bfbc6c74-eaf1-4e6c-8935-bf50e9e42730";

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

    let signing_key = SigningKey::random(&mut OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y
    }))
    .unwrap();
    let jkt = common::dpop::jwk_thumbprint(&x, &y);

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

    let client = reqwest::Client::new();
    let authed = |method: &str, path: &str| {
        let url = format!("{RP_ORIGIN}{path}");
        let proof = sign_proof(&signing_key, &jwk, method, &url);
        client
            .post(&url)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
    };

    // 1. users/list should include joejones.
    let res = authed("POST", "/api/admin/users/list")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let has_joejones = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["username"] == "joejones");
    println!("users/list includes joejones: {has_joejones}");
    assert!(has_joejones);

    // 2. Create a throwaway test group, add joejones, verify via
    //    users/groups.
    let group_id = format!("verify-group-{}", Uuid::new_v4());
    let res = authed("POST", "/api/admin/groups")
        .json(&serde_json::json!({"group_id": group_id, "name": "Verify Group"}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    let res = authed("POST", "/api/admin/groups/members/add")
        .json(&serde_json::json!({"group_id": group_id, "user_id": JOEJONES_ID}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    let res = authed("POST", "/api/admin/users/groups")
        .json(&serde_json::json!({"user_id": JOEJONES_ID}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let in_group = body["group_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == &group_id);
    println!("users/groups shows joejones in {group_id}: {in_group}");
    assert!(in_group);

    // 3. Grant a throwaway test function to that group, verify via
    //    groups/functions, revoke, verify gone.
    let function_id = format!("verify-fn-{}", Uuid::new_v4());
    let res = authed("POST", "/api/admin/grants")
        .json(&serde_json::json!({"function_id": function_id, "group_id": group_id, "attributes": {}}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    let res = authed("POST", "/api/admin/groups/functions")
        .json(&serde_json::json!({"group_id": group_id}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let has_grant = body["functions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["function_id"] == function_id);
    println!("groups/functions shows {function_id} granted: {has_grant}");
    assert!(has_grant);

    let res = authed("POST", "/api/admin/grants/revoke")
        .json(&serde_json::json!({"function_id": function_id, "group_id": group_id}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    let res = authed("POST", "/api/admin/groups/functions")
        .json(&serde_json::json!({"group_id": group_id}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let has_grant_after_revoke = body["functions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["function_id"] == function_id);
    println!("groups/functions shows {function_id} granted after revoke: {has_grant_after_revoke}");
    assert!(!has_grant_after_revoke);

    // 4. Clean up: remove joejones from the throwaway group again.
    let res = authed("POST", "/api/admin/groups/members/remove")
        .json(&serde_json::json!({"group_id": group_id, "user_id": JOEJONES_ID}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    // 5. Revoke the bootstrap identity.
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
    println!("all checks passed; bootstrap admin identity revoked");
}
