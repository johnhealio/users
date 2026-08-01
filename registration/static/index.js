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

async function loadNav() {
  const res = await fetch("/common/nav.html");
  document.getElementById("nav-placeholder").innerHTML = await res.text();
}

function setStatus(message, isError) {
  const el = document.getElementById("status");
  el.textContent = message;
  el.classList.toggle("status--error", Boolean(isError));
}

async function register(username, displayName) {
  const startRes = await fetch("/api/register/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, display_name: displayName }),
  });
  if (!startRes.ok) {
    const body = await startRes.json().catch(() => ({}));
    throw new Error(body.error || `registration start failed (${startRes.status})`);
  }
  const { session_id: sessionId, publicKey } = await startRes.json();

  const publicKeyOptions = {
    ...publicKey,
    challenge: bufferDecode(publicKey.challenge),
    user: { ...publicKey.user, id: bufferDecode(publicKey.user.id) },
    excludeCredentials: (publicKey.excludeCredentials || []).map((cred) => ({
      ...cred,
      id: bufferDecode(cred.id),
    })),
  };

  const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

  const finishRes = await fetch("/api/register/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      credential: {
        id: credential.id,
        rawId: bufferEncode(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufferEncode(credential.response.attestationObject),
          clientDataJSON: bufferEncode(credential.response.clientDataJSON),
          transports: credential.response.getTransports ? credential.response.getTransports() : undefined,
        },
      },
    }),
  });
  if (!finishRes.ok) {
    const body = await finishRes.json().catch(() => ({}));
    throw new Error(body.error || `registration finish failed (${finishRes.status})`);
  }
  return finishRes.json();
}

loadNav();

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitBtn = document.getElementById("submit-btn");
  const username = document.getElementById("username").value;
  const displayName = document.getElementById("display_name").value;

  submitBtn.disabled = true;
  setStatus("Waiting for your authenticator…", false);
  try {
    const result = await register(username, displayName);
    setStatus(`Registered ${result.username}. You can now use your passkey to log on.`, false);
  } catch (err) {
    setStatus(err.message || String(err), true);
  } finally {
    submitBtn.disabled = false;
  }
});
