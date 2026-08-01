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

// Same DB/store/key names logon's index.js uses: on a shared production
// origin this reads the keypair logon created; locally, on a different
// port, this is a separate IndexedDB with nothing in it (see the plan for
// why local browser click-through for logout isn't expected to work yet).
async function getDpopKeyPair() {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(DPOP_STORE_NAME, "readonly").objectStore(DPOP_STORE_NAME).get(DPOP_KEY_ID);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
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

async function logout() {
  const accessToken = sessionStorage.getItem("access_token");
  const keyPair = await getDpopKeyPair();
  if (!accessToken || !keyPair) {
    throw new Error("No active session found in this browser.");
  }

  const logoutUrl = `${window.location.origin}/api/logout`;
  const dpopProof = await buildDpopProof(keyPair, "POST", logoutUrl);

  const res = await fetch("/api/logout", {
    method: "POST",
    headers: {
      Authorization: `DPoP ${accessToken}`,
      DPoP: dpopProof,
    },
  });
  if (!res.ok && res.status !== 204) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `logout failed (${res.status})`);
  }

  sessionStorage.removeItem("access_token");
  sessionStorage.removeItem("access_token_expires_at");
  await clearDpopKeyPair();
}

loadNav();

document.getElementById("logout-btn").addEventListener("click", async () => {
  const btn = document.getElementById("logout-btn");
  btn.disabled = true;
  setStatus("Logging out…", false);
  try {
    await logout();
    setStatus("Logged out.", false);
  } catch (err) {
    setStatus(err.message || String(err), true);
  } finally {
    btn.disabled = false;
  }
});
