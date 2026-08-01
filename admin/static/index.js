async function loadNav() {
  const res = await fetch("/common/nav.html");
  document.getElementById("nav-placeholder").innerHTML = await res.text();
}

function setStatus(elementId, message, isError) {
  const el = document.getElementById(elementId);
  el.textContent = message;
  el.classList.toggle("status--error", Boolean(isError));
}

// Shared by every action on this page: builds a fresh DPoP proof for the
// given path and POSTs with the session's Authorization/DPoP headers, same
// shape as every other function's single action, just reused nine times.
async function adminRequest(path, body) {
  const accessToken = sessionStorage.getItem("access_token");
  const keyPair = await getDpopKeyPair();
  if (!accessToken || !keyPair) {
    throw new Error("No active session found in this browser.");
  }

  const url = `${window.location.origin}${path}`;
  const dpopProof = await buildDpopProof(keyPair, "POST", url);

  const res = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `DPoP ${accessToken}`,
      DPoP: dpopProof,
    },
    body: JSON.stringify(body),
  });

  if (res.status === 204) return null;
  const responseBody = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(responseBody.error || `request failed (${res.status})`);
  }
  return responseBody;
}

loadNav();

// --- Functions ---

async function refreshFunctions() {
  const result = await adminRequest("/api/admin/functions/list", {});
  const list = document.getElementById("functions-list");
  list.innerHTML = "";
  for (const fn of result.functions) {
    const li = document.createElement("li");
    li.textContent = `${fn.function_id} — ${fn.name}: ${fn.description}`;
    list.appendChild(li);
  }
}

document.getElementById("function-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const function_id = document.getElementById("function-id").value;
  const name = document.getElementById("function-name").value;
  const description = document.getElementById("function-description").value;
  try {
    await adminRequest("/api/admin/functions", { function_id, name, description });
    setStatus("functions-status", `Registered ${function_id}.`, false);
    await refreshFunctions();
  } catch (err) {
    setStatus("functions-status", err.message || String(err), true);
  }
});

document.getElementById("functions-refresh").addEventListener("click", async () => {
  try {
    await refreshFunctions();
  } catch (err) {
    setStatus("functions-status", err.message || String(err), true);
  }
});

// --- Groups ---

async function refreshGroups() {
  const result = await adminRequest("/api/admin/groups/list", {});
  const list = document.getElementById("groups-list");
  list.innerHTML = "";
  for (const g of result.groups) {
    const li = document.createElement("li");
    li.textContent = `${g.group_id} — ${g.name}`;
    list.appendChild(li);
  }
}

document.getElementById("group-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const group_id = document.getElementById("group-id").value;
  const name = document.getElementById("group-name").value;
  try {
    await adminRequest("/api/admin/groups", { group_id, name });
    setStatus("groups-status", `Created ${group_id}.`, false);
    await refreshGroups();
  } catch (err) {
    setStatus("groups-status", err.message || String(err), true);
  }
});

document.getElementById("groups-refresh").addEventListener("click", async () => {
  try {
    await refreshGroups();
  } catch (err) {
    setStatus("groups-status", err.message || String(err), true);
  }
});

// --- Group membership ---

async function listMembers(groupId) {
  const result = await adminRequest("/api/admin/groups/members/list", { group_id: groupId });
  const list = document.getElementById("members-list");
  list.innerHTML = "";
  for (const userId of result.user_ids) {
    const li = document.createElement("li");
    li.textContent = userId;
    list.appendChild(li);
  }
}

document.getElementById("member-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const group_id = document.getElementById("member-group-id").value;
  const user_id = document.getElementById("member-user-id").value;
  try {
    await adminRequest("/api/admin/groups/members/add", { group_id, user_id });
    setStatus("members-status", `Added ${user_id} to ${group_id}.`, false);
    await listMembers(group_id);
  } catch (err) {
    setStatus("members-status", err.message || String(err), true);
  }
});

document.getElementById("member-remove-btn").addEventListener("click", async () => {
  const group_id = document.getElementById("member-group-id").value;
  const user_id = document.getElementById("member-user-id").value;
  try {
    await adminRequest("/api/admin/groups/members/remove", { group_id, user_id });
    setStatus("members-status", `Removed ${user_id} from ${group_id}.`, false);
    await listMembers(group_id);
  } catch (err) {
    setStatus("members-status", err.message || String(err), true);
  }
});

document.getElementById("member-list-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const group_id = document.getElementById("member-list-group-id").value;
  try {
    await listMembers(group_id);
    setStatus("members-status", `Listed members of ${group_id}.`, false);
  } catch (err) {
    setStatus("members-status", err.message || String(err), true);
  }
});

// --- Grants ---

async function listGrants(functionId) {
  const result = await adminRequest("/api/admin/grants/list", { function_id: functionId });
  const list = document.getElementById("grants-list");
  list.innerHTML = "";
  for (const g of result.groups) {
    const li = document.createElement("li");
    li.textContent = `group ${g.group_id}: ${JSON.stringify(g.attributes)}`;
    list.appendChild(li);
  }
  for (const u of result.users) {
    const li = document.createElement("li");
    li.textContent = `user ${u.user_id}: ${JSON.stringify(u.attributes)}`;
    list.appendChild(li);
  }
}

document.getElementById("grant-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const function_id = document.getElementById("grant-function-id").value;
  const group_id = document.getElementById("grant-group-id").value || undefined;
  const user_id = document.getElementById("grant-user-id").value || undefined;
  let attributes;
  try {
    attributes = JSON.parse(document.getElementById("grant-attributes").value || "{}");
  } catch (err) {
    setStatus("grants-status", "attributes must be valid JSON", true);
    return;
  }
  try {
    await adminRequest("/api/admin/grants", { function_id, group_id, user_id, attributes });
    setStatus("grants-status", "Grant set.", false);
    await listGrants(function_id);
  } catch (err) {
    setStatus("grants-status", err.message || String(err), true);
  }
});

document.getElementById("grant-revoke-btn").addEventListener("click", async () => {
  const function_id = document.getElementById("grant-function-id").value;
  const group_id = document.getElementById("grant-group-id").value || undefined;
  const user_id = document.getElementById("grant-user-id").value || undefined;
  try {
    await adminRequest("/api/admin/grants/revoke", { function_id, group_id, user_id });
    setStatus("grants-status", "Grant revoked.", false);
    await listGrants(function_id);
  } catch (err) {
    setStatus("grants-status", err.message || String(err), true);
  }
});

document.getElementById("grant-list-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const function_id = document.getElementById("grant-list-function-id").value;
  try {
    await listGrants(function_id);
    setStatus("grants-status", `Listed grants for ${function_id}.`, false);
  } catch (err) {
    setStatus("grants-status", err.message || String(err), true);
  }
});
