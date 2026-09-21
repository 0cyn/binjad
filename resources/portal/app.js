const api = `${location.pathname.replace(/\/$/, "")}/api`;

let authorization = "";
let loginMode = "basic";
let currentView = "overview";
let runtimeLine = "local daemon";
let contextDocument = null;
let toolDocumentation = null;

const titles = {
  overview: "Service overview",
  access: "Access control",
  projects: "Project catalog",
  configuration: "Daemon configuration",
  "enabled-tools": "Enabled tools",
  context: "MCP context view",
  tools: "MCP tool calls",
};

const toolPacks = [
  {
    name: "Core Workflow",
    description: "Projects and uploads, file and BinaryView lifecycle, analysis and jobs, persistence, functions, disassembly, decompilation, strings, symbols, memory, and data context.",
  },
  {
    name: "Project Management & Documents",
    description: "Project metadata, folders and files, server-side imports, and direct text or JSON document reading.",
    input: "cfg-tool-project-management",
  },
  {
    name: "Function Analysis",
    description: "IL, callers and callees, code references, and stack layout.",
    input: "cfg-tool-function-analysis",
  },
  {
    name: "Binary Data",
    description: "Imports, exports, entry points, sections, segments, data variables, relocations, and data references.",
    input: "cfg-tool-binary-data",
  },
  {
    name: "Search",
    description: "Comments, bytes, instructions, IL, constants, and project-wide analysis search.",
    input: "cfg-tool-search",
  },
  {
    name: "Types & Signatures",
    description: "Named-type inspection and editing, prototypes, calling conventions, and function-variable names and types.",
    input: "cfg-tool-types",
  },
  {
    name: "Annotations & Symbols",
    description: "Comments, user symbols, bookmarks, tags, and namespaced custom metadata.",
    input: "cfg-tool-annotations",
  },
  {
    name: "Binary Editing",
    description: "Functions, entry points, typed data, sections, segments, rebasing, memory-map preview, and strings.",
    input: "cfg-tool-binary-editing",
  },
  {
    name: "Transactions & History",
    description: "Explicit mutation transactions, rollback, undo, and redo.",
    input: "cfg-tool-history",
  },
  {
    name: "Diffing",
    description: "Google BinDiff comparisons, matched and unmatched function exploration, and explicit metadata porting into the primary view.",
    input: "cfg-tool-diffing",
  },
  {
    name: "KernelCache",
    description: "Images, dependencies, symbols, and selective image loading.",
    input: "cfg-tool-kernel-cache",
  },
  {
    name: "SharedCache",
    description: "Images, regions, entries, symbols, and selective loading.",
    input: "cfg-tool-shared-cache",
  },
  {
    name: "Debugger",
    description: "Admin-only target control, process state, memory, registers, and breakpoints.",
    input: "cfg-tool-debugger",
  },
];

function renderEnabledToolPacks() {
  $("#enabled-tool-packs").innerHTML = toolPacks.map((pack, index) => `
    <details class="tool-pack">
      <summary>
        <span class="tool-pack-copy">
          <b>${escapeHtml(pack.name)}</b>
          <small>${escapeHtml(pack.description)}</small>
        </span>
        <span class="tool-pack-control">
          <span id="tool-pack-count-${index}" class="tool-pack-count">loading tools</span>
          ${pack.input
            ? `<input id="${pack.input}" class="tool-pack-checkbox" type="checkbox" aria-label="Enable ${escapeHtml(pack.name)}">`
            : '<span class="badge">always on</span>'}
        </span>
      </summary>
      <div id="tool-pack-tools-${index}" class="tool-pack-tools">
        <span class="meta">Tool inventory is loading.</span>
      </div>
    </details>
  `).join("");
  document.querySelectorAll(".tool-pack-checkbox").forEach((checkbox) => {
    checkbox.addEventListener("click", (event) => event.stopPropagation());
  });
}

function renderEnabledToolLists() {
  if (!toolDocumentation) return;
  toolPacks.forEach((pack, index) => {
    const tools = toolDocumentation.tools
      .filter((tool) => tool.pack === pack.name)
      .sort((left, right) => left.name.localeCompare(right.name));
    $(`#tool-pack-count-${index}`).textContent = `${tools.length} tools`;
    $(`#tool-pack-tools-${index}`).innerHTML = tools.length
      ? `<ul>${tools.map((tool) => `<li title="${escapeHtml(tool.description)}"><code>${escapeHtml(tool.name)}</code></li>`).join("")}</ul>`
      : '<span class="meta">No tools are defined for this pack.</span>';
  });
}

const $ = (selector) => document.querySelector(selector);

function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character],
  );
}

function base64Utf8(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function toast(message, bad = false) {
  const element = $("#toast");
  element.textContent = message;
  element.className = bad ? "toast bad" : "toast";
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.add("hidden"), 4500);
}

async function call(path, options = {}) {
  const request = {...options};
  request.headers = {
    ...(request.headers || {}),
    ...(authorization ? {Authorization: authorization} : {}),
  };
  if (request.body) {
    request.headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${api}${path}`, request);
  const text = await response.text();
  let value = {};
  try {
    value = text ? JSON.parse(text) : {};
  } catch {
    value = {error: text || String(response.status)};
  }
  if (!response.ok) {
    const validation = (value.result?.errors || [])
      .map((item) => `${item.path}: ${item.message}`)
      .join("\n");
    throw new Error(value.error || validation || String(response.status));
  }
  return value;
}

function selectLoginTab(mode) {
  loginMode = mode;
  $("#basic-tab").classList.toggle("on", mode === "basic");
  $("#bearer-tab").classList.toggle("on", mode === "bearer");
  $("#basic-login").classList.toggle("hidden", mode !== "basic");
  $("#bearer-login").classList.toggle("hidden", mode !== "bearer");
}

async function loadBootstrapState() {
  try {
    const value = await call("/bootstrap");
    $("#bootstrap").classList.toggle("hidden", !value.result);
    if (!value.result) {
      try {
        await enterPanel();
      } catch {
        // Authentication is still required in the normal configuration.
      }
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function bootstrapAdministrator() {
  try {
    await call("/bootstrap", {
      method: "POST",
      body: JSON.stringify({
        credential: $("#boot-credential").value,
        username: $("#boot-user").value,
        password: $("#boot-password").value,
      }),
    });
    $("#bootstrap").classList.add("hidden");
    toast("Administrator created");
  } catch (error) {
    toast(error.message, true);
  }
}

async function login() {
  if (loginMode === "basic") {
    authorization = `Basic ${base64Utf8(`${$("#login-user").value}:${$("#login-password").value}`)}`;
  } else {
    authorization = `Bearer ${$("#login-token").value.trim()}`;
  }

  try {
    await enterPanel();
  } catch (error) {
    authorization = "";
    toast(error.message, true);
  }
}

async function enterPanel() {
  await refreshStatus();
  $("#gate").classList.add("hidden");
  $("#app").classList.remove("hidden");
  await Promise.all([
    loadAccounts(),
    loadTokens(),
    loadProjects(),
    loadConfiguration(),
  ]);
}

function logout() {
  authorization = "";
  $("#app").classList.add("hidden");
  $("#gate").classList.remove("hidden");
  $("#login-password").value = "";
  $("#login-token").value = "";
}

function showView(id, button) {
  currentView = id;
  document.querySelectorAll(".view").forEach((element) => {
    element.classList.toggle("hidden", element.id !== id);
  });
  document.querySelectorAll(".nav button").forEach((element) => {
    element.classList.toggle("on", element === button);
  });
  $("#view-title").textContent = titles[id];
  renderBreadcrumb();
  if (id === "context" && !contextDocument) loadContext();
  if (id === "tools" && !toolDocumentation) loadToolDocumentation();
  if (id === "enabled-tools") {
    if (toolDocumentation) renderEnabledToolLists();
    else loadToolDocumentation();
  }
}

function renderBreadcrumb() {
  const section = ["enabled-tools", "context", "tools"].includes(currentView)
    ? "MCP"
    : currentView === "projects" ? "Services" : "System";
  $("#mode-line").textContent = `${section} / ${runtimeLine}`;
}

function setRestartRequired(required) {
  $("#restart-badge").classList.toggle("hidden", !required);
  $("#restart-badge").classList.toggle("warn", required);
  $("#config-warning").classList.toggle("hidden", !required);
  $("#config-state").textContent = required ? "Restart required" : "Active";
}

async function refreshStatus() {
  const value = await call("/status");
  const status = value.result;
  const runtime = status.runtime;

  $("#m-sessions").textContent = runtime.analysis_sessions;
  $("#m-items").textContent = runtime.open_items;
  $("#m-active").textContent = runtime.active_analyses;
  $("#m-queued").textContent = runtime.queued_analyses;
  $("#m-workers").textContent = runtime.allocated_workers;
  $("#m-budget").textContent = runtime.worker_budget;
  runtimeLine = `${status.mode} daemon / v${status.version}`;
  renderBreadcrumb();
  $("#actor").textContent = `${status.actor.username} · ${status.actor.role}`;
  $("#project-backend").textContent = status.mode === "local"
    ? "Local commercial"
    : "Collaboration";
  setRestartRequired(status.restart_required);

  $("#runtime-list").innerHTML = `
    <div class="row"><span>Logical CPUs</span><b>${runtime.logical_cpu_count}</b></div>
    <div class="row"><span>Worker budget</span><b>${runtime.worker_budget}</b></div>
    <div class="row"><span>Detached jobs</span><b>${runtime.jobs}</b></div>
    <div class="row"><span>Projects</span><b>${runtime.projects}</b></div>
  `;
}

async function refreshAll() {
  try {
    await Promise.all([
      refreshStatus(),
      loadAccounts(),
      loadTokens(),
      loadProjects(),
    ]);
    toast("Dashboard refreshed");
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadAccounts() {
  try {
    const value = await call("/accounts");
    const rows = value.result.map((account) => `
      <tr>
        <td>${escapeHtml(account.username)}</td>
        <td>${escapeHtml(account.role)}</td>
        <td><span class="meta">${escapeHtml(account.id.slice(0, 12))}</span></td>
        <td class="actions">
          <button class="quiet" data-action="edit-account" data-id="${account.id}" data-role="${account.role}">Edit</button>
          <button class="danger" data-action="delete-account" data-id="${account.id}">Delete</button>
        </td>
      </tr>
    `).join("");
    $("#accounts-list").innerHTML = rows
      ? `<div class="table-wrap"><table><thead><tr><th>Username</th><th>Role</th><th>ID</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : '<div class="row meta">No accounts</div>';
  } catch (error) {
    $("#accounts-list").innerHTML = `<div class="meta">${escapeHtml(error.message)}</div>`;
  }
}

async function createAccount() {
  try {
    await call("/accounts", {
      method: "POST",
      body: JSON.stringify({
        username: $("#account-name").value,
        password: $("#account-password").value,
        role: $("#account-role").value,
      }),
    });
    $("#account-password").value = "";
    await loadAccounts();
    toast("Account created");
  } catch (error) {
    toast(error.message, true);
  }
}

async function editAccount(id, currentRole) {
  const role = prompt("Role: portal-admin or self-service", currentRole);
  if (role === null) return;
  const password = prompt("New password (leave blank to keep current)", "");
  const body = {role};
  if (password) body.password = password;
  try {
    await call(`/accounts/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
    await loadAccounts();
    toast("Account updated");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteAccount(id) {
  if (!confirm("Delete this account and revoke its tokens?")) return;
  try {
    await call(`/accounts/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: JSON.stringify({tokens: "revoke"}),
    });
    await loadAccounts();
    toast("Account deleted");
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadTokens() {
  try {
    const value = await call("/tokens");
    const rows = value.result.map((token) => `
      <tr>
        <td>${escapeHtml(token.label || "unlabeled")}</td>
        <td>${escapeHtml(token.role)}</td>
        <td>${token.expires_at ? new Date(token.expires_at * 1000).toLocaleString() : "Never"}</td>
        <td><button class="danger" data-action="revoke-token" data-id="${token.id}">Revoke</button></td>
      </tr>
    `).join("");
    $("#tokens-list").innerHTML = rows
      ? `<div class="table-wrap"><table><thead><tr><th>Label</th><th>Role</th><th>Expires</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : '<div class="row meta">No tokens</div>';
  } catch (error) {
    $("#tokens-list").innerHTML = `<div class="meta">${escapeHtml(error.message)}</div>`;
  }
}

async function issueToken() {
  const body = {
    label: $("#token-label").value || undefined,
    role: $("#token-role").value,
  };
  if ($("#token-ttl").value !== "") {
    body.ttl_seconds = Number($("#token-ttl").value);
  }
  try {
    const value = await call("/tokens", {
      method: "POST",
      body: JSON.stringify(body),
    });
    $("#token-secret").textContent = value.result.token;
    $("#issued-token").classList.remove("hidden");
    await loadTokens();
    toast("Token issued; copy it now");
  } catch (error) {
    toast(error.message, true);
  }
}

async function copyToken() {
  try {
    await navigator.clipboard.writeText($("#token-secret").textContent);
    toast("Token copied");
  } catch {
    toast("Clipboard unavailable", true);
  }
}

async function revokeToken(id) {
  if (!confirm("Revoke this token and tear down its sessions?")) return;
  try {
    await call(`/tokens/${encodeURIComponent(id)}`, {method: "DELETE"});
    await loadTokens();
    toast("Token revoked");
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadProjects() {
  try {
    const value = await call("/projects");
    const rows = value.result.map((project) => `
      <tr>
        <td>${escapeHtml(project.name)}</td>
        <td>${escapeHtml(project.description || "")}</td>
        <td><span class="meta">${escapeHtml(project.project)}</span></td>
        <td><button class="danger" data-action="delete-project" data-id="${project.project}">Delete</button></td>
      </tr>
    `).join("");
    $("#projects-list").innerHTML = rows
      ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Description</th><th>Reference</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : '<div class="row meta">No local projects discovered</div>';
  } catch (error) {
    $("#projects-list").innerHTML = `<div class="meta">${escapeHtml(error.message)}</div>`;
  }
}

async function deleteProject(id) {
  if (!confirm("Permanently delete this closed project and all of its files?")) return;
  try {
    await call(`/projects/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: JSON.stringify({delete: true}),
    });
    await Promise.all([loadProjects(), refreshStatus()]);
    toast("Project deleted");
  } catch (error) {
    toast(error.message, true);
  }
}

function put(selector, value) {
  const element = $(selector);
  if (element) element.value = value ?? "";
}

function numberValue(selector) {
  return Number($(selector).value);
}

function fillConfiguration(configuration) {
  put("#cfg-mode", configuration.mode ?? "auto");
  put("#cfg-port", configuration.listener?.port ?? 8712);
  put("#cfg-cpu", configuration.cpu?.percentage ?? 75);
  put("#cfg-fairness", configuration.cpu?.fairness ?? "job");
  put("#cfg-subdivision", configuration.cpu?.subdivision ?? "serial");
  put("#cfg-session-ttl", configuration.sessions?.ttl_seconds ?? 1800);
  put("#cfg-detach", configuration.jobs?.detach_after_seconds ?? 30);
  put("#cfg-grace", configuration.jobs?.cancellation_grace_seconds ?? 5);
  put("#cfg-token-ttl", configuration.authentication?.default_token_ttl_seconds ?? 604800);
  put("#cfg-upload-max", configuration.uploads?.max_bytes ?? 4294967296);
  put("#cfg-upload-memory", configuration.uploads?.memory_threshold_bytes ?? 268435456);
  put("#cfg-upload-ttl", configuration.uploads?.url_ttl_seconds ?? 3600);
  $("#cfg-upload-auth").checked = Boolean(
    configuration.uploads?.require_bearer_authentication,
  );
  put("#cfg-roots", (configuration.projects?.roots || []).join("\n"));
  put("#cfg-default-root", configuration.projects?.default_root ?? "");
  put("#cfg-spool", configuration.storage?.spool_path ?? "");
  $("#cfg-infinite").checked = Boolean(configuration.authentication?.allow_infinite_tokens);
  $("#cfg-arbitrary").checked = configuration.projects?.allow_arbitrary_paths ?? true;
  $("#cfg-unauthenticated").checked = Boolean(
    configuration.http?.very_dangerous_unauthenticated_portal,
  );
  const tools = configuration.tools || {};
  const legacyPlugins = configuration.plugins || {};
  $("#cfg-tool-project-management").checked = tools.project_management ?? true;
  $("#cfg-tool-function-analysis").checked = tools.function_analysis ?? true;
  $("#cfg-tool-binary-data").checked = tools.binary_data ?? true;
  $("#cfg-tool-search").checked = tools.search ?? true;
  $("#cfg-tool-types").checked = tools.types ?? true;
  $("#cfg-tool-annotations").checked = tools.annotations ?? true;
  $("#cfg-tool-binary-editing").checked = tools.binary_editing ?? true;
  $("#cfg-tool-history").checked = tools.history ?? true;
  $("#cfg-tool-diffing").checked = tools.diffing ?? true;
  $("#cfg-tool-kernel-cache").checked = tools.kernel_cache ?? legacyPlugins.kernel_cache ?? true;
  $("#cfg-tool-shared-cache").checked = tools.shared_cache ?? legacyPlugins.shared_cache ?? true;
  $("#cfg-tool-debugger").checked = tools.debugger ?? legacyPlugins.debugger ?? true;
  $("#config-json").value = JSON.stringify(configuration, null, 2);
}

function mergeConfiguration() {
  let configuration;
  try {
    configuration = JSON.parse($("#config-json").value);
  } catch (error) {
    throw new Error(`Advanced JSON: ${error.message}`);
  }

  configuration.listener ||= {};
  configuration.cpu ||= {};
  configuration.sessions ||= {};
  configuration.jobs ||= {};
  configuration.authentication ||= {};
  configuration.uploads ||= {};
  configuration.projects ||= {};
  configuration.storage ||= {};
  configuration.http ||= {};
  configuration.tools ||= {};

  configuration.mode = $("#cfg-mode").value;
  configuration.listener.port = numberValue("#cfg-port");
  configuration.cpu.percentage = numberValue("#cfg-cpu");
  configuration.cpu.fairness = $("#cfg-fairness").value;
  configuration.cpu.subdivision = $("#cfg-subdivision").value;
  configuration.sessions.ttl_seconds = numberValue("#cfg-session-ttl");
  configuration.jobs.detach_after_seconds = numberValue("#cfg-detach");
  configuration.jobs.cancellation_grace_seconds = numberValue("#cfg-grace");
  configuration.authentication.default_token_ttl_seconds = numberValue("#cfg-token-ttl");
  configuration.authentication.allow_infinite_tokens = $("#cfg-infinite").checked;
  configuration.uploads.max_bytes = numberValue("#cfg-upload-max");
  configuration.uploads.memory_threshold_bytes = numberValue("#cfg-upload-memory");
  configuration.uploads.url_ttl_seconds = numberValue("#cfg-upload-ttl");
  configuration.uploads.require_bearer_authentication = $("#cfg-upload-auth").checked;
  configuration.projects.roots = $("#cfg-roots").value
    .split("\n")
    .map((value) => value.trim())
    .filter(Boolean);
  configuration.projects.default_root = $("#cfg-default-root").value;
  configuration.projects.allow_arbitrary_paths = $("#cfg-arbitrary").checked;
  configuration.http.very_dangerous_unauthenticated_portal =
    $("#cfg-unauthenticated").checked;
  configuration.storage.spool_path = $("#cfg-spool").value;
  configuration.tools.project_management = $("#cfg-tool-project-management").checked;
  configuration.tools.function_analysis = $("#cfg-tool-function-analysis").checked;
  configuration.tools.binary_data = $("#cfg-tool-binary-data").checked;
  configuration.tools.search = $("#cfg-tool-search").checked;
  configuration.tools.types = $("#cfg-tool-types").checked;
  configuration.tools.annotations = $("#cfg-tool-annotations").checked;
  configuration.tools.binary_editing = $("#cfg-tool-binary-editing").checked;
  configuration.tools.history = $("#cfg-tool-history").checked;
  configuration.tools.diffing = $("#cfg-tool-diffing").checked;
  configuration.tools.kernel_cache = $("#cfg-tool-kernel-cache").checked;
  configuration.tools.shared_cache = $("#cfg-tool-shared-cache").checked;
  configuration.tools.debugger = $("#cfg-tool-debugger").checked;
  delete configuration.plugins;
  return configuration;
}

async function loadConfiguration() {
  try {
    const value = await call("/config");
    fillConfiguration(value.result.configuration);
    setRestartRequired(value.result.restart_required);
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveConfiguration() {
  try {
    const configuration = mergeConfiguration();
    const value = await call("/config", {
      method: "PUT",
      body: JSON.stringify(configuration, null, 2),
    });
    $("#config-json").value = JSON.stringify(configuration, null, 2);
    setRestartRequired(value.result.restart_required);
    toast(value.result.restart_required
      ? "Configuration saved; restart required"
      : "Configuration matches running service");
  } catch (error) {
    toast(error.message, true);
  }
}

function mcpSelection(prefix) {
  return {
    protocol: $(`#mcp-${prefix}-protocol`).value,
    role: $(`#mcp-${prefix}-role`).value,
  };
}

function summaryChips(items) {
  return items.map(([label, value]) => `
    <div class="summary-chip"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>
  `).join("");
}

async function copyText(value, message) {
  try {
    await navigator.clipboard.writeText(value);
    toast(message);
  } catch {
    toast("Clipboard unavailable", true);
  }
}

async function loadContext() {
  const selection = mcpSelection("context");
  try {
    const value = await call("/mcp/context", {
      method: "POST",
      body: JSON.stringify({
        ...selection,
        client: $("#mcp-client-name").value.trim() || "binjad",
      }),
    });
    contextDocument = value.result;
    const options = contextDocument.runningOptions;
    $("#context-summary").innerHTML = summaryChips([
      ["Protocol", contextDocument.protocolVersion],
      ["Role", contextDocument.role],
      ["Mode", contextDocument.mode],
      ["Tools", contextDocument.openCodeProjection.tools.length],
      ["Enabled packs", Object.values(options.tools || {}).filter(Boolean).length],
    ]);
    $("#mcp-wire-context").innerHTML = contextDocument.mcpWire.map((entry, index) => `
      <details class="document" ${index === 0 ? "open" : ""}>
        <summary><code>${escapeHtml(entry.method)}</code><button class="quiet" data-action="copy-wire-context" data-index="${index}">Copy</button></summary>
        <pre class="code-document">${escapeHtml(entry.payload)}</pre>
      </details>
    `).join("");
    $("#opencode-boundary").textContent = contextDocument.openCodeProjection.boundary;
    $("#opencode-context").textContent = JSON.stringify(
      contextDocument.openCodeProjection,
      null,
      2,
    );
  } catch (error) {
    toast(error.message, true);
  }
}

function renderFailureContracts() {
  const contracts = toolDocumentation?.failureContracts || {};
  $("#failure-contracts").innerHTML = Object.entries(contracts).map(([id, contract]) => `
    <div class="failure-contract" id="failure-${escapeHtml(id)}">
      <code>${escapeHtml(id)}</code>
      <p>${escapeHtml(contract.when)}</p>
      <div class="meta">${escapeHtml(contract.surface)}</div>
    </div>
  `).join("");
}

function renderToolDocumentation() {
  if (!toolDocumentation) return;
  const query = $("#tool-filter").value.trim().toLowerCase();
  const tools = toolDocumentation.tools.filter((tool) =>
    !query || `${tool.name} ${tool.pack} ${tool.category} ${tool.description}`.toLowerCase().includes(query)
  );
  $("#tool-docs-summary").innerHTML = summaryChips([
    ["Protocol", toolDocumentation.protocolVersion],
    ["Role", toolDocumentation.role],
    ["Mode", toolDocumentation.mode],
    ["Available", `${toolDocumentation.availableCount} / ${toolDocumentation.totalCount}`],
    ["Filter results", tools.length],
  ]);
  $("#tool-docs-list").innerHTML = tools.map((tool) => `
    <article class="block tool-document ${tool.available ? "" : "tool-unavailable"}" data-tool="${escapeHtml(tool.name)}">
      <div class="block-head tool-title">
        <div><h2><code>${escapeHtml(tool.name)}</code></h2><div class="meta">${escapeHtml(tool.pack)} / ${escapeHtml(tool.category)} / ${tool.available ? "available" : "not advertised"}</div></div>
        <button class="quiet" data-action="copy-tool-schema" data-tool="${escapeHtml(tool.name)}">Copy schema</button>
      </div>
      <div class="tool-description">${escapeHtml(tool.description)}</div>
      ${tool.available ? "" : `<div class="tool-availability">${escapeHtml(tool.availability)}</div>`}
      <details class="tool-detail">
        <summary>Input schema</summary>
        <pre class="code-document">${escapeHtml(JSON.stringify(tool.inputSchema, null, 2))}</pre>
      </details>
      <details class="tool-detail">
        <summary>Failure modes (${tool.failureModes.length})</summary>
        <div class="failure-links">${tool.failureModes.map((id) => {
          const contract = toolDocumentation.failureContracts[id];
          return `<div><code>${escapeHtml(id)}</code><span>${escapeHtml(contract?.when || "")}</span></div>`;
        }).join("")}</div>
      </details>
    </article>
  `).join("") || '<article class="block empty-state">No tools match this filter.</article>';
  renderFailureContracts();
}

async function loadToolDocumentation() {
  try {
    const value = await call("/mcp/tools", {
      method: "POST",
      body: JSON.stringify(mcpSelection("tools")),
    });
    toolDocumentation = value.result;
    renderEnabledToolLists();
    renderToolDocumentation();
  } catch (error) {
    toast(error.message, true);
  }
}

const actions = {
  bootstrap: bootstrapAdministrator,
  login,
  logout,
  "refresh-all": refreshAll,
  "create-account": createAccount,
  "load-accounts": loadAccounts,
  "issue-token": issueToken,
  "copy-token": copyToken,
  "load-tokens": loadTokens,
  "load-projects": loadProjects,
  "load-config": loadConfiguration,
  "save-config": saveConfiguration,
  "load-context": loadContext,
  "load-tool-docs": loadToolDocumentation,
};

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "login-tab") {
    selectLoginTab(button.dataset.mode);
  } else if (action === "show-view") {
    showView(button.dataset.view, button);
  } else if (action === "edit-account") {
    editAccount(button.dataset.id, button.dataset.role);
  } else if (action === "delete-account") {
    deleteAccount(button.dataset.id);
  } else if (action === "revoke-token") {
    revokeToken(button.dataset.id);
  } else if (action === "delete-project") {
    deleteProject(button.dataset.id);
  } else if (action === "copy-wire-context" && contextDocument) {
    copyText(contextDocument.mcpWire[Number(button.dataset.index)].payload, "MCP payload copied");
  } else if (action === "copy-opencode-context" && contextDocument) {
    copyText(JSON.stringify(contextDocument.openCodeProjection, null, 2), "OpenCode projection copied");
  } else if (action === "copy-tool-schema" && toolDocumentation) {
    const tool = toolDocumentation.tools.find((item) => item.name === button.dataset.tool);
    if (tool) copyText(JSON.stringify(tool.inputSchema, null, 2), "Tool schema copied");
  } else if (actions[action]) {
    actions[action]();
  }
});

document.addEventListener("change", (event) => {
  if (event.target.matches("#mcp-context-protocol, #mcp-context-role")) {
    contextDocument = null;
    loadContext();
  }
  if (event.target.matches("#mcp-tools-protocol, #mcp-tools-role")) {
    toolDocumentation = null;
    loadToolDocumentation();
  }
});

document.addEventListener("input", (event) => {
  if (event.target.matches("#tool-filter")) renderToolDocumentation();
});

renderEnabledToolPacks();
loadBootstrapState();
