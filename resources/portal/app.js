const api = `${location.pathname.replace(/\/$/, "")}/api`;

let authorization = "";
let currentView = "overview";
let contextDocument = null;
let toolDocumentation = null;
let toolConfigurationKey = "";
let serverVersion = "";
let pollTimer = null;
let polling = false;
let memoryPollTimer = null;
let memoryPolling = false;
let memoryAbortController = null;

const memoryStatusMeta = document.querySelector('meta[name="binjad-status-path"]');
const configuredMemoryStatusPath = memoryStatusMeta?.dataset.configuredPath || "";
const fallbackMemoryStatusPath = memoryStatusMeta?.content || "/healthz/status";
const usableMemoryStatusPath = (value) => value.startsWith("/") && !value.includes("{{");
let memoryStatusPath = "/healthz/status";
if (usableMemoryStatusPath(configuredMemoryStatusPath)) {
  memoryStatusPath = configuredMemoryStatusPath;
} else if (usableMemoryStatusPath(fallbackMemoryStatusPath)) {
  memoryStatusPath = fallbackMemoryStatusPath;
}
const memorySamples = [];
const memorySampleInterval = 5000;
const memoryWindow = 5 * 60 * 1000;

const titles = {
  overview: "Service overview",
  access: "Account/Token",
  projects: "Project catalog",
  configuration: "Configuration",
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
    key: "project_management",
  },
  {
    name: "Function Analysis",
    description: "IL, callers and callees, code references, and stack layout.",
    input: "cfg-tool-function-analysis",
    key: "function_analysis",
  },
  {
    name: "Binary Data",
    description: "Imports, exports, entry points, sections, segments, data variables, relocations, and data references.",
    input: "cfg-tool-binary-data",
    key: "binary_data",
  },
  {
    name: "Search",
    description: "Comments, bytes, instructions, IL, constants, and project-wide analysis search.",
    input: "cfg-tool-search",
    key: "search",
  },
  {
    name: "Types & Signatures",
    description: "Named-type inspection and editing, prototypes, calling conventions, and function-variable names and types.",
    input: "cfg-tool-types",
    key: "types",
  },
  {
    name: "Annotations & Symbols",
    description: "Comments, user symbols, bookmarks, tags, and namespaced custom metadata.",
    input: "cfg-tool-annotations",
    key: "annotations",
  },
  {
    name: "Binary Editing",
    description: "Functions, entry points, typed data, sections, segments, rebasing, memory-map preview, and strings.",
    input: "cfg-tool-binary-editing",
    key: "binary_editing",
  },
  {
    name: "Transactions & History",
    description: "Explicit mutation transactions, rollback, undo, and redo.",
    input: "cfg-tool-history",
    key: "history",
  },
  {
    name: "Header Parsing",
    description: "Mach-O, ELF, and PE header summaries, linked libraries, load commands, program headers, dynamic entries, and data directories.",
    input: "cfg-tool-header-parsing",
    key: "header_parsing",
  },
  {
    name: "URL Generation",
    description: "Binary Ninja links for owned paths, saved project BNDBs, remote files, and context-relative navigation expressions.",
    input: "cfg-tool-url-generation",
    key: "url_generation",
  },
  {
    name: "Diffing",
    description: "Google BinDiff comparisons, matched and unmatched function exploration, and explicit metadata porting into the primary view.",
    input: "cfg-tool-diffing",
    key: "diffing",
  },
  {
    name: "KernelCache",
    description: "Images, dependencies, symbols, and selective image loading.",
    input: "cfg-tool-kernel-cache",
    key: "kernel_cache",
  },
  {
    name: "SharedCache",
    description: "Images, regions, entries, symbols, and selective loading.",
    input: "cfg-tool-shared-cache",
    key: "shared_cache",
  },
  {
    name: "Debugger",
    description: "Admin-only target control, process state, memory, registers, and breakpoints.",
    input: "cfg-tool-debugger",
    key: "debugger",
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
            ? `<input id="${pack.input}" class="tool-pack-checkbox" type="checkbox" aria-label="Enable ${escapeHtml(pack.name)}" title="Turn ${escapeHtml(pack.name)} MCP tools on or off immediately.">`
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

function formatMemoryBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = value >= 100 || unit === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toLocaleString(undefined, {maximumFractionDigits: digits})} ${units[unit]}`;
}

function renderMemoryChart(now = Date.now()) {
  const line = $("#memory-line");
  const area = $("#memory-area");
  const point = $("#memory-point");
  const empty = $("#memory-chart-empty");
  const current = memorySamples.at(-1);
  if (!current) {
    $("#memory-current").textContent = "—";
    $("#memory-scale-high").textContent = "—";
    $("#memory-scale-low").textContent = "—";
    $("#memory-updated").textContent = "Waiting for data";
    $("#memory-chart-description").textContent = "Waiting for the first memory sample.";
    line.classList.add("hidden");
    area.classList.add("hidden");
    point.classList.add("hidden");
    empty.classList.remove("hidden");
    return;
  }

  const values = memorySamples.map((sample) => sample.bytes);
  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const spread = maximum - minimum;
  const padding = Math.max(spread * 0.2, maximum * 0.03, 1024 * 1024);
  const low = Math.max(0, minimum - padding);
  const high = Math.max(low + 1, maximum + padding);
  const cutoff = now - memoryWindow;
  const points = memorySamples.map((sample) => ({
    x: 4 + Math.max(0, Math.min(1, (sample.time - cutoff) / memoryWindow)) * 592,
    y: 170 - ((sample.bytes - low) / (high - low)) * 160,
  }));
  const visiblePoints = points.length === 1 ? [{x: Math.max(0, points[0].x - 1), y: points[0].y}, points[0]] : points;
  const linePath = visiblePoints.map((item, index) => `${index ? "L" : "M"}${item.x.toFixed(2)},${item.y.toFixed(2)}`).join(" ");
  const areaPath = `${linePath} L${visiblePoints.at(-1).x.toFixed(2)},170 L${visiblePoints[0].x.toFixed(2)},170 Z`;
  const latestPoint = points.at(-1);

  line.setAttribute("d", linePath);
  area.setAttribute("d", areaPath);
  point.setAttribute("cx", latestPoint.x.toFixed(2));
  point.setAttribute("cy", latestPoint.y.toFixed(2));
  line.classList.remove("hidden");
  area.classList.remove("hidden");
  point.classList.remove("hidden");
  empty.classList.add("hidden");
  $("#memory-current").textContent = formatMemoryBytes(current.bytes);
  $("#memory-scale-high").textContent = formatMemoryBytes(high);
  $("#memory-scale-low").textContent = formatMemoryBytes(low);
  $("#memory-updated").textContent = `Updated ${new Date(current.time).toLocaleTimeString()}`;
  $("#memory-chart-description").textContent =
    `Current managed process memory is ${formatMemoryBytes(current.bytes)}. `
    + `The chart contains ${memorySamples.length} samples from the last five minutes.`;
}

function addMemorySample(value, time = Date.now()) {
  const bytes = Number(value);
  if (!Number.isSafeInteger(bytes) || bytes < 0) return false;
  memorySamples.push({bytes, time});
  const cutoff = time - memoryWindow;
  while (memorySamples.length && memorySamples[0].time < cutoff) memorySamples.shift();
  $("#memory-panel").classList.remove("stale");
  renderMemoryChart(time);
  return true;
}

function resetMemoryChart() {
  memorySamples.length = 0;
  $("#memory-panel").classList.remove("stale");
  renderMemoryChart();
}

function markMemoryUnavailable() {
  $("#memory-panel").classList.add("stale");
  $("#memory-updated").textContent = "Update unavailable";
}

async function pollMemory() {
  if (!authorization || memoryPolling || document.hidden) return;
  memoryPolling = true;
  const controller = new AbortController();
  memoryAbortController = controller;
  const timeout = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(memoryStatusPath, {
      cache: "no-store",
      credentials: "same-origin",
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(String(response.status));
    const status = await response.json();
    if (!addMemorySample(status.memory_bytes)) throw new Error("invalid memory value");
  } catch {
    if (authorization) markMemoryUnavailable();
  } finally {
    clearTimeout(timeout);
    if (memoryAbortController === controller) memoryAbortController = null;
    memoryPolling = false;
  }
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

async function loadSetupState() {
  try {
    const value = await call("/setup");
    $("#setup").classList.toggle("hidden", !value.result);
  } catch (error) {
    toast(error.message, true);
  }
}

async function setupAccount() {
  try {
    await call("/setup", {
      method: "POST",
      body: JSON.stringify({
        username: $("#setup-user").value,
        password: $("#setup-password").value,
      }),
    });
    $("#login-user").value = $("#setup-user").value;
    $("#setup-password").value = "";
    $("#setup").classList.add("hidden");
    toast("Account created; log in to create the MCP token");
  } catch (error) {
    toast(error.message, true);
  }
}

async function login() {
  authorization = `Basic ${base64Utf8(`${$("#login-user").value}:${$("#login-password").value}`)}`;

  try {
    await enterPanel();
  } catch (error) {
    authorization = "";
    toast(error.message, true);
  }
}

async function enterPanel() {
  resetMemoryChart();
  await refreshStatus();
  $("#gate").classList.add("hidden");
  $("#app").classList.remove("hidden");
  await loadConfiguration();
  startPolling();
}

function logout() {
  stopPolling();
  resetMemoryChart();
  authorization = "";
  contextDocument = null;
  toolDocumentation = null;
  toolConfigurationKey = "";
  serverVersion = "";
  $("#app").classList.add("hidden");
  $("#gate").classList.remove("hidden");
  $("#login-password").value = "";
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
  if (id === "context") loadContext();
  if (id === "tools") loadToolDocumentation();
  if (id === "enabled-tools") {
    loadToolConfiguration(true);
    loadToolDocumentation();
  }
}

function setRestartRequired(required) {
  $("#restart-badge").classList.toggle("hidden", !required);
  $("#restart-badge").classList.toggle("warn", required);
  $("#config-warning").classList.toggle("hidden", !required);
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
  if (!memorySamples.length) addMemorySample(runtime.memory_bytes);
  $("#actor").textContent = status.actor.username;
  $("#account-username").textContent = status.actor.username;
  renderToken(status.token);
  renderProjects(status.projects);
  const toolsChanged = fillToolConfiguration(status.tools);
  const versionChanged = serverVersion !== "" && serverVersion !== status.version;
  serverVersion = status.version;
  setRestartRequired(status.restart_required);

  $("#runtime-list").innerHTML = `
    <div class="row"><span>Logical CPUs</span><b>${runtime.logical_cpu_count}</b></div>
    <div class="row"><span>Worker budget</span><b>${runtime.worker_budget}</b></div>
    <div class="row"><span>Detached jobs</span><b>${runtime.jobs}</b></div>
    <div class="row"><span>Projects</span><b>${runtime.projects}</b></div>
  `;
  return toolsChanged || versionChanged;
}

async function refreshVisibleMcpDocumentation() {
  contextDocument = null;
  toolDocumentation = null;
  if (currentView === "context") await loadContext(true);
  if (["tools", "enabled-tools"].includes(currentView)) {
    await loadToolDocumentation(true);
  }
}

async function refreshAll() {
  try {
    if (await refreshStatus()) await refreshVisibleMcpDocumentation();
    toast("Dashboard refreshed");
  } catch (error) {
    toast(error.message, true);
  }
}

async function changePassword() {
  try {
    await call("/account", {
      method: "PATCH",
      body: JSON.stringify({
        password: $("#account-password").value,
      }),
    });
    $("#account-password").value = "";
    logout();
    toast("Password changed; log in again");
  } catch (error) {
    toast(error.message, true);
  }
}

function renderToken(token) {
  $("#token-status").innerHTML = token
    ? `<div class="row"><span>Created</span><b>${new Date(token.created_at * 1000).toLocaleString()}</b></div>
       <div class="row"><span>Expires</span><b>${token.expires_at ? new Date(token.expires_at * 1000).toLocaleString() : "Never"}</b></div>
       <button class="danger top-gap" data-action="revoke-token">Revoke token</button>`
    : '<div class="row meta">No MCP token. Create one to connect a client.</div>';
}

async function loadToken(silent = false) {
  try {
    const value = await call("/token");
    renderToken(value.result);
  } catch (error) {
    if (!silent) $("#token-status").innerHTML = `<div class="meta">${escapeHtml(error.message)}</div>`;
  }
}

async function rotateToken() {
  const ttl = $("#token-never").checked ? 0 : Number($("#token-ttl").value);
  if (!Number.isSafeInteger(ttl) || ttl < 0 || (!$("#token-never").checked && ttl === 0)) {
    toast("TTL must be a positive whole number, or select Never expires", true);
    return;
  }
  try {
    const value = await call("/token", {
      method: "POST",
      body: JSON.stringify({ttl_seconds: ttl}),
    });
    $("#token-secret").textContent = value.result.token;
    $("#issued-token").classList.remove("hidden");
    await loadToken();
    toast("Token created; copy it now");
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

async function revokeToken() {
  if (!confirm("Revoke this token and tear down its sessions?")) return;
  try {
    await call("/token", {method: "DELETE"});
    await loadToken();
    toast("Token revoked");
  } catch (error) {
    toast(error.message, true);
  }
}

function renderProjects(projects) {
  const rows = projects.map((project) => `
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
}

function toggleProjectCreate() {
  const form = $("#project-create");
  form.classList.toggle("hidden");
  if (!form.classList.contains("hidden")) $("#project-name").focus();
}

async function createProject() {
  const name = $("#project-name").value.trim();
  if (!name) {
    toast("Project name is required", true);
    return;
  }
  try {
    await call("/projects", {
      method: "POST",
      body: JSON.stringify({
        name,
        path: $("#project-path").value.trim(),
        description: $("#project-description").value,
      }),
    });
    $("#project-name").value = "";
    $("#project-path").value = "";
    $("#project-description").value = "";
    $("#project-create").classList.add("hidden");
    await refreshStatus();
    toast("Project created");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteProject(id) {
  if (!confirm("Permanently delete this closed project and all of its files?")) return;
  try {
    await call(`/projects/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: JSON.stringify({delete: true}),
    });
    await refreshStatus();
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

function fillToolConfiguration(tools = {}) {
  const discoveryMode = tools.discovery_mode ?? "full";
  const nextKey = `${discoveryMode}|${toolPacks
    .filter((pack) => pack.input)
    .map((pack) => `${pack.key}:${Boolean(tools[pack.key])}`)
    .join("|")}`;
  const changed = toolConfigurationKey !== "" && toolConfigurationKey !== nextKey;
  toolConfigurationKey = nextKey;
  for (const pack of toolPacks) {
    if (!pack.input) continue;
    const input = $(`#${pack.input}`);
    if (Object.hasOwn(tools, pack.key)) input.checked = Boolean(tools[pack.key]);
  }
  return changed;
}

async function loadToolConfiguration(silent = false) {
  try {
    const value = await call("/tools");
    fillToolConfiguration(value.result.tools);
    setRestartRequired(value.result.restart_required ?? $("#restart-badge").classList.contains("warn"));
  } catch (error) {
    if (!silent) toast(error.message, true);
  }
}

async function updateToolPack(input) {
  const pack = toolPacks.find((item) => item.input === input.id);
  if (!pack) return;
  const enabled = input.checked;
  input.disabled = true;
  try {
    const value = await call("/tools", {
      method: "PATCH",
      body: JSON.stringify({[pack.key]: enabled}),
    });
    fillToolConfiguration(value.result.tools);
    setRestartRequired(value.result.restart_required);
    contextDocument = null;
    toolDocumentation = null;
    await Promise.all([
      currentView === "context" ? loadContext(true) : Promise.resolve(),
      ["tools", "enabled-tools"].includes(currentView)
        ? loadToolDocumentation(true)
        : Promise.resolve(),
    ]);
  } catch (error) {
    input.checked = !enabled;
    toast(error.message, true);
  } finally {
    input.disabled = false;
  }
}

function fillConfiguration(configuration) {
  put("#cfg-binary-ninja", configuration.binary_ninja?.installation_dir ?? "");
  put("#cfg-port", configuration.listener?.port ?? 8712);
  put("#cfg-cpu", configuration.cpu?.percentage ?? 75);
  put("#cfg-fairness", configuration.cpu?.fairness ?? "job");
  put("#cfg-subdivision", configuration.cpu?.subdivision ?? "serial");
  put("#cfg-session-ttl", configuration.sessions?.ttl_seconds ?? 1800);
  put("#cfg-detach", configuration.jobs?.detach_after_seconds ?? 30);
  put("#cfg-grace", configuration.jobs?.cancellation_grace_seconds ?? 5);
  put("#cfg-upload-max", configuration.uploads?.max_bytes ?? 4294967296);
  put("#cfg-upload-memory", configuration.uploads?.memory_threshold_bytes ?? 268435456);
  put("#cfg-upload-ttl", configuration.uploads?.url_ttl_seconds ?? 3600);
  $("#cfg-upload-auth").checked = Boolean(
    configuration.uploads?.require_bearer_authentication,
  );
  put("#cfg-roots", (configuration.projects?.roots || []).join("\n"));
  put("#cfg-default-root", configuration.projects?.default_root ?? "");
  put("#cfg-spool", configuration.storage?.spool_path ?? "");
  $("#cfg-arbitrary").checked = configuration.projects?.allow_arbitrary_paths ?? true;
  $("#cfg-project-registration").checked = configuration.projects?.allow_project_registration ?? false;
  const tools = configuration.tools || {};
  const legacyPlugins = configuration.plugins || {};
  $("#cfg-reduced-surface").checked = (tools.discovery_mode ?? "full") === "brokered";
  fillToolConfiguration({
    discovery_mode: tools.discovery_mode ?? "full",
    project_management: tools.project_management ?? true,
    function_analysis: tools.function_analysis ?? true,
    binary_data: tools.binary_data ?? true,
    search: tools.search ?? true,
    types: tools.types ?? true,
    annotations: tools.annotations ?? true,
    binary_editing: tools.binary_editing ?? true,
    history: tools.history ?? true,
    header_parsing: tools.header_parsing ?? true,
    url_generation: tools.url_generation ?? true,
    diffing: tools.diffing ?? true,
    kernel_cache: tools.kernel_cache ?? legacyPlugins.kernel_cache ?? true,
    shared_cache: tools.shared_cache ?? legacyPlugins.shared_cache ?? true,
    debugger: tools.debugger ?? legacyPlugins.debugger ?? true,
  });
  $("#config-json").value = JSON.stringify(configuration, null, 2);
}

function mergeConfiguration() {
  let configuration;
  try {
    configuration = JSON.parse($("#config-json").value);
  } catch (error) {
    throw new Error(`Advanced JSON: ${error.message}`);
  }

  configuration.binary_ninja ||= {};
  configuration.listener ||= {};
  configuration.cpu ||= {};
  configuration.sessions ||= {};
  configuration.jobs ||= {};
  configuration.uploads ||= {};
  configuration.projects ||= {};
  configuration.storage ||= {};
  configuration.http ||= {};
  configuration.tools ||= {};

  configuration.binary_ninja.installation_dir = $("#cfg-binary-ninja").value;
  configuration.listener.port = numberValue("#cfg-port");
  configuration.cpu.percentage = numberValue("#cfg-cpu");
  configuration.cpu.fairness = $("#cfg-fairness").value;
  configuration.cpu.subdivision = $("#cfg-subdivision").value;
  configuration.sessions.ttl_seconds = numberValue("#cfg-session-ttl");
  configuration.jobs.detach_after_seconds = numberValue("#cfg-detach");
  configuration.jobs.cancellation_grace_seconds = numberValue("#cfg-grace");
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
  configuration.projects.allow_project_registration = $("#cfg-project-registration").checked;
  configuration.storage.spool_path = $("#cfg-spool").value;
  configuration.tools.discovery_mode = $("#cfg-reduced-surface").checked ? "brokered" : "full";
  configuration.tools.project_management = $("#cfg-tool-project-management").checked;
  configuration.tools.function_analysis = $("#cfg-tool-function-analysis").checked;
  configuration.tools.binary_data = $("#cfg-tool-binary-data").checked;
  configuration.tools.search = $("#cfg-tool-search").checked;
  configuration.tools.types = $("#cfg-tool-types").checked;
  configuration.tools.annotations = $("#cfg-tool-annotations").checked;
  configuration.tools.binary_editing = $("#cfg-tool-binary-editing").checked;
  configuration.tools.history = $("#cfg-tool-history").checked;
  configuration.tools.header_parsing = $("#cfg-tool-header-parsing").checked;
  configuration.tools.url_generation = $("#cfg-tool-url-generation").checked;
  configuration.tools.diffing = $("#cfg-tool-diffing").checked;
  configuration.tools.kernel_cache = $("#cfg-tool-kernel-cache").checked;
  configuration.tools.shared_cache = $("#cfg-tool-shared-cache").checked;
  configuration.tools.debugger = $("#cfg-tool-debugger").checked;
  delete configuration.mode;
  delete configuration.authentication;
  delete configuration.collaboration;
  delete configuration.http.very_dangerous_unauthenticated_portal;
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
    contextDocument = null;
    toolDocumentation = null;
    await Promise.all([
      currentView === "context" ? loadContext(true) : Promise.resolve(),
      ["tools", "enabled-tools"].includes(currentView)
        ? loadToolDocumentation(true)
        : Promise.resolve(),
    ]);
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
  };
}

async function copyText(value, message) {
  try {
    await navigator.clipboard.writeText(value);
    toast(message);
  } catch {
    toast("Clipboard unavailable", true);
  }
}

async function loadContext(silent = false) {
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
    const projection = JSON.stringify(
      contextDocument.openCodeProjection,
      null,
      2,
    );
    $("#opencode-context").textContent = projection;
    const bytes = new TextEncoder().encode(projection).length;
    const kilobytes = bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
    const tokens = Math.ceil(projection.length / 4).toLocaleString();
    $("#model-context-size").textContent = `${kilobytes} | ~${tokens} tokens`;
  } catch (error) {
    if (!silent) toast(error.message, true);
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
  const tools = toolDocumentation.tools.filter((tool) => tool.available).filter((tool) =>
    !query || `${tool.name} ${tool.pack} ${tool.category} ${tool.description}`.toLowerCase().includes(query)
  );
  $("#tool-docs-list").innerHTML = tools.map((tool) => `
    <article class="block tool-document" data-tool="${escapeHtml(tool.name)}">
      <div class="block-head tool-title">
        <h2><code>${escapeHtml(tool.name)}</code></h2>
        <button class="quiet" data-action="copy-tool-schema" data-tool="${escapeHtml(tool.name)}">Copy schema</button>
      </div>
      <div class="tool-description">${escapeHtml(tool.description)}</div>
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

async function loadToolDocumentation(silent = false) {
  try {
    const value = await call("/mcp/tools", {
      method: "POST",
      body: JSON.stringify(mcpSelection("tools")),
    });
    toolDocumentation = value.result;
    renderEnabledToolLists();
    renderToolDocumentation();
  } catch (error) {
    if (!silent) toast(error.message, true);
  }
}

async function pollState() {
  if (!authorization || polling || document.hidden) return;
  polling = true;
  try {
    if (await refreshStatus()) await refreshVisibleMcpDocumentation();
  } catch {
    // Keep the last rendered state and retry on the next poll.
  } finally {
    polling = false;
  }
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(pollState, 10000);
  memoryPollTimer = setInterval(pollMemory, memorySampleInterval);
}

function stopPolling() {
  if (pollTimer !== null) clearInterval(pollTimer);
  pollTimer = null;
  if (memoryPollTimer !== null) clearInterval(memoryPollTimer);
  memoryPollTimer = null;
  if (memoryAbortController !== null) memoryAbortController.abort();
  memoryAbortController = null;
  polling = false;
  memoryPolling = false;
}

const actions = {
  setup: setupAccount,
  logout,
  "refresh-all": refreshAll,
  "change-password": changePassword,
  "rotate-token": rotateToken,
  "copy-token": copyToken,
  "toggle-project-create": toggleProjectCreate,
  "create-project": createProject,
  "load-config": loadConfiguration,
  "save-config": saveConfiguration,
};

$("#login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  login();
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "show-view") {
    showView(button.dataset.view, button);
  } else if (action === "revoke-token") {
    revokeToken();
  } else if (action === "delete-project") {
    deleteProject(button.dataset.id);
  } else if (action === "copy-opencode-context" && contextDocument) {
    copyText(JSON.stringify(contextDocument.openCodeProjection, null, 2), "Model view copied");
  } else if (action === "copy-tool-schema" && toolDocumentation) {
    const tool = toolDocumentation.tools.find((item) => item.name === button.dataset.tool);
    if (tool) copyText(JSON.stringify(tool.inputSchema, null, 2), "Tool schema copied");
  } else if (actions[action]) {
    actions[action]();
  }
});

document.addEventListener("change", (event) => {
  if (event.target.matches("#token-never")) {
    $("#token-ttl").disabled = event.target.checked;
  }
  if (event.target.matches("#mcp-context-protocol")) {
    contextDocument = null;
    loadContext();
  }
  if (event.target.matches("#mcp-tools-protocol")) {
    toolDocumentation = null;
    loadToolDocumentation();
  }
  if (event.target.matches("#mcp-client-name")) {
    contextDocument = null;
    loadContext();
  }
  if (event.target.matches(".tool-pack-checkbox")) updateToolPack(event.target);
});

document.addEventListener("input", (event) => {
  if (event.target.matches("#tool-filter")) renderToolDocumentation();
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    pollState();
    pollMemory();
  }
});

renderEnabledToolPacks();
loadSetupState();
