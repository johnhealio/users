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
