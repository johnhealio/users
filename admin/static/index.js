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

// --- Users ---
//
// Click a user in the list to reveal every group as a checkbox, checked
// for the groups they're currently in. Toggling a checkbox adds/removes
// that one membership immediately (existing groups/members/add|remove
// endpoints) and re-renders from a fresh read.

let selectedUserId = null;

function renderPickerSelection(listId, selectedId) {
  for (const li of document.getElementById(listId).children) {
    li.classList.toggle("selected", li.dataset.id === selectedId);
  }
}

async function refreshUsers() {
  const result = await adminRequest("/api/admin/users/list", {});
  const list = document.getElementById("users-list");
  list.innerHTML = "";
  for (const user of result.users) {
    const li = document.createElement("li");
    li.textContent = `${user.username} (${user.display_name})`;
    li.dataset.id = user.user_id;
    li.addEventListener("click", () => selectUser(user.user_id, user.username));
    list.appendChild(li);
  }
  renderPickerSelection("users-list", selectedUserId);
}

async function selectUser(userId, username) {
  selectedUserId = userId;
  renderPickerSelection("users-list", selectedUserId);
  document.getElementById("user-detail").hidden = false;
  document.getElementById("user-detail-heading").textContent = `${username}'s groups`;
  await renderUserGroupsChecklist();
}

async function renderUserGroupsChecklist() {
  const [groupsResult, membershipResult] = await Promise.all([
    adminRequest("/api/admin/groups/list", {}),
    adminRequest("/api/admin/users/groups", { user_id: selectedUserId }),
  ]);
  const memberOf = new Set(membershipResult.group_ids);

  const checklist = document.getElementById("user-groups-checklist");
  checklist.innerHTML = "";
  for (const group of groupsResult.groups) {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = memberOf.has(group.group_id);
    checkbox.addEventListener("change", async () => {
      const path = checkbox.checked
        ? "/api/admin/groups/members/add"
        : "/api/admin/groups/members/remove";
      try {
        await adminRequest(path, { group_id: group.group_id, user_id: selectedUserId });
        setStatus("users-status", `Updated ${group.group_id} membership.`, false);
      } catch (err) {
        setStatus("users-status", err.message || String(err), true);
        checkbox.checked = !checkbox.checked;
      }
    });
    label.appendChild(checkbox);
    label.append(` ${group.group_id} — ${group.name}`);
    li.appendChild(label);
    checklist.appendChild(li);
  }
}

document.getElementById("users-refresh").addEventListener("click", async () => {
  try {
    await refreshUsers();
  } catch (err) {
    setStatus("users-status", err.message || String(err), true);
  }
});

// --- Groups ---
//
// Click a group in the list to reveal every function as a checkbox,
// checked for the functions currently granted to that group. Toggling a
// checkbox sets/revokes that one grant (with {} attributes — use the raw
// Grants form below for anything needing custom attributes or a
// direct-to-user grant) and re-renders from a fresh read.

let selectedGroupId = null;

async function refreshGroups() {
  const result = await adminRequest("/api/admin/groups/list", {});
  const list = document.getElementById("groups-list");
  list.innerHTML = "";
  for (const g of result.groups) {
    const li = document.createElement("li");
    li.textContent = `${g.group_id} — ${g.name}`;
    li.dataset.id = g.group_id;
    li.addEventListener("click", () => selectGroup(g.group_id));
    list.appendChild(li);
  }
  renderPickerSelection("groups-list", selectedGroupId);
}

async function selectGroup(groupId) {
  selectedGroupId = groupId;
  renderPickerSelection("groups-list", selectedGroupId);
  document.getElementById("group-detail").hidden = false;
  document.getElementById("group-detail-heading").textContent = `${groupId}'s functions`;
  await renderGroupFunctionsChecklist();
}

async function renderGroupFunctionsChecklist() {
  const [functionsResult, grantsResult] = await Promise.all([
    adminRequest("/api/admin/functions/list", {}),
    adminRequest("/api/admin/groups/functions", { group_id: selectedGroupId }),
  ]);
  const granted = new Set(grantsResult.functions.map((f) => f.function_id));

  const checklist = document.getElementById("group-functions-checklist");
  checklist.innerHTML = "";
  for (const fn of functionsResult.functions) {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = granted.has(fn.function_id);
    checkbox.addEventListener("change", async () => {
      try {
        if (checkbox.checked) {
          await adminRequest("/api/admin/grants", {
            function_id: fn.function_id,
            group_id: selectedGroupId,
            attributes: {},
          });
        } else {
          await adminRequest("/api/admin/grants/revoke", {
            function_id: fn.function_id,
            group_id: selectedGroupId,
          });
        }
        setStatus("groups-status", `Updated ${fn.function_id} grant.`, false);
      } catch (err) {
        setStatus("groups-status", err.message || String(err), true);
        checkbox.checked = !checkbox.checked;
      }
    });
    label.appendChild(checkbox);
    label.append(` ${fn.function_id} — ${fn.name}`);
    li.appendChild(label);
    checklist.appendChild(li);
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
