// Shared DPoP (RFC 9449) browser-side helpers: encoding, the IndexedDB-held
// keypair, and proof construction. Loaded as a classic script (not a
// module) by every function's page, so these are plain globals — same
// no-build-step style as the rest of this project's JS.

function bufferEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const DPOP_DB_NAME = "auth-keys";
const DPOP_STORE_NAME = "keypairs";
const DPOP_KEY_ID = "dpop";

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DPOP_DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(DPOP_STORE_NAME);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Read-only: a missing keypair should surface as "no active session" to
// the caller, not silently mint a new, unbound one. Used by every page
// except logon.
async function getDpopKeyPair() {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(DPOP_STORE_NAME, "readonly").objectStore(DPOP_STORE_NAME).get(DPOP_KEY_ID);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// A session's DPoP binding is permanent for that session's lifetime, so the
// same keypair must be reproducible across page loads — hence IndexedDB
// rather than an in-memory-only key. Used by logon, where the keypair is
// first generated.
async function getOrCreateDpopKeyPair() {
  const existing = await getDpopKeyPair();
  if (existing) return existing;

  // extractable: true is required so the public key can be exported to a
  // JWK for the proof header. This is a known, minor relaxation from a
  // fully non-extractable private key.
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const db = await openKeyDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(DPOP_STORE_NAME, "readwrite");
    tx.objectStore(DPOP_STORE_NAME).put(keyPair, DPOP_KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  return keyPair;
}

async function clearDpopKeyPair() {
  const db = await openKeyDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(DPOP_STORE_NAME, "readwrite");
    tx.objectStore(DPOP_STORE_NAME).delete(DPOP_KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function base64urlFromString(str) {
  return bufferEncode(new TextEncoder().encode(str).buffer);
}

async function buildDpopProof(keyPair, htm, htu) {
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
  };
  const payload = {
    jti: crypto.randomUUID(),
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
  };

  const signingInput = `${base64urlFromString(JSON.stringify(header))}.${base64urlFromString(JSON.stringify(payload))}`;
  // WebCrypto's ECDSA signatures are raw (r||s), which is exactly the
  // format JWS/ES256 expects — no DER conversion needed.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${bufferEncode(signature)}`;
}
