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

// Same DB/store/key names logon's index.js uses — see logout/static/index.js
// for why this only works on a shared production origin, not locally.
async function getDpopKeyPair() {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(DPOP_STORE_NAME, "readonly").objectStore(DPOP_STORE_NAME).get(DPOP_KEY_ID);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
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

async function checkAccess() {
  const accessToken = sessionStorage.getItem("access_token");
  const keyPair = await getDpopKeyPair();
  if (!accessToken || !keyPair) {
    throw new Error("No active session found in this browser.");
  }

  const checkUrl = `${window.location.origin}/api/check`;
  const dpopProof = await buildDpopProof(keyPair, "POST", checkUrl);

  const res = await fetch("/api/check", {
    method: "POST",
    headers: {
      Authorization: `DPoP ${accessToken}`,
      DPoP: dpopProof,
    },
  });
  const body = await res.json();
  if (!res.ok) {
    throw new Error(body.error || `check failed (${res.status})`);
  }
  return body;
}

loadNav();

document.getElementById("check-btn").addEventListener("click", async () => {
  const btn = document.getElementById("check-btn");
  btn.disabled = true;
  setStatus("Checking…", false);
  try {
    const result = await checkAccess();
    if (result.authorized) {
      setStatus(`Authorized. Attributes: ${JSON.stringify(result.attributes || {})}`, false);
    } else {
      setStatus(`Not authorized: ${result.reason || "no reason given"}`, true);
    }
  } catch (err) {
    setStatus(err.message || String(err), true);
  } finally {
    btn.disabled = false;
  }
});
