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

  const checkUrl = `${window.location.origin}/api/check2`;
  const dpopProof = await buildDpopProof(keyPair, "POST", checkUrl);

  const res = await fetch("/api/check2", {
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
