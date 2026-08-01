function bufferDecode(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

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

// A session's DPoP binding is permanent for that session's lifetime, so the
// same keypair must be reproducible across page loads — hence IndexedDB
// rather than an in-memory-only key.
async function getOrCreateDpopKeyPair() {
  const db = await openKeyDb();

  const existing = await new Promise((resolve, reject) => {
    const req = db.transaction(DPOP_STORE_NAME, "readonly").objectStore(DPOP_STORE_NAME).get(DPOP_KEY_ID);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  if (existing) return existing;

  // extractable: true is required so the public key can be exported to a
  // JWK for the proof header. This is a known, minor relaxation from a
  // fully non-extractable private key.
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  await new Promise((resolve, reject) => {
    const tx = db.transaction(DPOP_STORE_NAME, "readwrite");
    tx.objectStore(DPOP_STORE_NAME).put(keyPair, DPOP_KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  return keyPair;
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

async function loadNav() {
  const res = await fetch("/common/nav.html");
  document.getElementById("nav-placeholder").innerHTML = await res.text();
}

function setStatus(message, isError) {
  const el = document.getElementById("status");
  el.textContent = message;
  el.classList.toggle("status--error", Boolean(isError));
}

async function logon(username) {
  const startRes = await fetch("/api/logon/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  });
  if (!startRes.ok) {
    const body = await startRes.json().catch(() => ({}));
    throw new Error(body.error || `logon start failed (${startRes.status})`);
  }
  const { session_id: sessionId, publicKey } = await startRes.json();

  const publicKeyOptions = {
    ...publicKey,
    challenge: bufferDecode(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map((cred) => ({
      ...cred,
      id: bufferDecode(cred.id),
    })),
  };

  const credential = await navigator.credentials.get({ publicKey: publicKeyOptions });

  const finishUrl = `${window.location.origin}/api/logon/finish`;
  const keyPair = await getOrCreateDpopKeyPair();
  const dpopProof = await buildDpopProof(keyPair, "POST", finishUrl);

  const finishRes = await fetch("/api/logon/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json", DPoP: dpopProof },
    body: JSON.stringify({
      session_id: sessionId,
      credential: {
        id: credential.id,
        rawId: bufferEncode(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: bufferEncode(credential.response.authenticatorData),
          clientDataJSON: bufferEncode(credential.response.clientDataJSON),
          signature: bufferEncode(credential.response.signature),
          userHandle: credential.response.userHandle
            ? bufferEncode(credential.response.userHandle)
            : null,
        },
      },
    }),
  });
  if (!finishRes.ok) {
    const body = await finishRes.json().catch(() => ({}));
    throw new Error(body.error || `logon finish failed (${finishRes.status})`);
  }
  return finishRes.json();
}

loadNav();

document.getElementById("logon-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitBtn = document.getElementById("submit-btn");
  const username = document.getElementById("username").value;

  submitBtn.disabled = true;
  setStatus("Waiting for your authenticator…", false);
  try {
    const result = await logon(username);
    // DPoP requires attaching a fresh signed proof per request, so the raw
    // token alone (e.g. in a cookie) wouldn't be usable on its own by
    // future protected calls anyway — kept in sessionStorage for now,
    // alongside the IndexedDB-held key that proves possession of it.
    sessionStorage.setItem("access_token", result.access_token);
    sessionStorage.setItem("access_token_expires_at", result.expires_at);
    setStatus(`Logged on as ${result.username}.`, false);
  } catch (err) {
    setStatus(err.message || String(err), true);
  } finally {
    submitBtn.disabled = false;
  }
});
