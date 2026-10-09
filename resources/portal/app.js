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
let restartInProgress = false;
let projectCatalog = [];
let activeProject = "";
let projectContents = null;
let currentProjectFolder = "";
let projectLoadSequence = 0;
let projectDocumentSequence = 0;
const selectedProjectFiles = new Set();
let sessionCatalog = [];
let activeRecoverySession = "";
let recoverySessionDetails = null;
let sessionLoadSequence = 0;

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
  projects: "Projects",
  sessions: "Sessions",
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
    description: "Project metadata, folders and files, server-side imports, capability downloads, and direct text or JSON document reading.",
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

function ionIcon(name) {
  return `<svg class="ion-icon" aria-hidden="true"><use href="#ion-${escapeHtml(name)}"></use></svg>`;
}

function projectIconButton(action, icon, label, extraClass = "", attributes = "") {
  const classes = `icon-button${extraClass ? ` ${extraClass}` : ""}`;
  return `<button type="button" class="${classes}" data-action="${escapeHtml(action)}"
                  aria-label="${escapeHtml(label)}" data-tooltip="${escapeHtml(label)}" ${attributes}>
            ${ionIcon(icon)}
          </button>`;
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
  renderMemoryChart(time);
  return true;
}

function resetMemoryChart() {
  memorySamples.length = 0;
  renderMemoryChart();
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
    // Keep the last rendered chart and retry on the next sample interval.
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
  projectCatalog = [];
  activeProject = "";
  projectContents = null;
  currentProjectFolder = "";
  selectedProjectFiles.clear();
  projectLoadSequence += 1;
  projectDocumentSequence += 1;
  sessionCatalog = [];
  activeRecoverySession = "";
  recoverySessionDetails = null;
  sessionLoadSequence += 1;
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
  if (id === "projects") activateProjectView();
  if (id === "sessions") activateSessionsView();
}

function setRestartRequired(required) {
  const button = $("#restart-daemon");
  button.classList.toggle("hidden", !required);
  if (!restartInProgress) {
    button.disabled = false;
    button.textContent = "Restart daemon";
  }
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

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForRestart(portalUrl, retryAfterSeconds) {
  const destination = new URL(portalUrl, location.href);
  const destinationPath = destination.pathname.replace(/\/$/, "");
  const currentPath = location.pathname.replace(/\/$/, "");
  if (destination.origin !== location.origin) {
    const delay = Math.max(1000, (Number(retryAfterSeconds) + 2) * 1000);
    toast("Daemon restart requested. The portal will open at its configured URL.");
    setTimeout(() => location.assign(destination.href), delay);
    return;
  }

  const statusUrl = `${destination.origin}${destinationPath}/api/status`;
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    await wait(1000);
    try {
      const response = await fetch(statusUrl, {
        cache: "no-store",
        headers: {Authorization: authorization},
      });
      if (!response.ok) continue;
      const value = await response.json();
      if (value.result?.restart_required !== false) continue;
      if (destinationPath !== currentPath) {
        location.assign(destination.href);
        return;
      }
      await refreshStatus();
      await loadConfiguration();
      restartInProgress = false;
      setRestartRequired(false);
      startPolling();
      toast("Daemon restarted");
      return;
    } catch {
      // The managed service is still restarting.
    }
  }

  restartInProgress = false;
  setRestartRequired(true);
  startPolling();
  toast("The daemon did not return. Reload the portal after you check the service.", true);
}

async function restartDaemon() {
  if (restartInProgress) return;
  if (!confirm("Restart the daemon now?\n\nThis closes active sessions and jobs. Save all analysis changes before you continue.")) return;

  restartInProgress = true;
  stopPolling();
  const button = $("#restart-daemon");
  button.disabled = true;
  button.textContent = "Restarting…";
  try {
    const value = await call("/restart", {
      method: "POST",
      body: "{}",
    });
    toast("Daemon restart requested");
    await waitForRestart(value.result.portal_url, value.result.retry_after_seconds);
  } catch (error) {
    restartInProgress = false;
    setRestartRequired(true);
    startPolling();
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
  projectCatalog = [...projects].sort((left, right) =>
    left.name.localeCompare(right.name) || left.project.localeCompare(right.project));
  if (activeProject && !projectCatalog.some((project) => project.project === activeProject)) {
    activeProject = "";
    projectContents = null;
    currentProjectFolder = "";
    selectedProjectFiles.clear();
  }
  renderProjectSidebar();
  if (currentView === "projects" && !activeProject && projectCatalog.length) {
    selectProject(projectCatalog[0].project);
  } else if (!activeProject) {
    $("#project-empty").textContent = projectCatalog.length
      ? "Select a project from the right."
      : "Create a project to start.";
    showProjectPanel("empty");
  } else if (projectContents) {
    const current = projectCatalog.find((project) => project.project === activeProject);
    if (current) {
      projectContents.project = {...projectContents.project, ...current};
      $("#project-detail-name").textContent = current.name;
      $("#project-detail-description").textContent = current.description || "";
    }
  }
}

function renderProjectSidebar() {
  $("#projects-list").innerHTML = projectCatalog.length
    ? projectCatalog.map((project) => `
        <button class="project-list-item${project.project === activeProject ? " on" : ""}"
                data-action="select-project" data-id="${escapeHtml(project.project)}">
          <strong>${escapeHtml(project.name)}</strong>
          <span>${escapeHtml(project.description || "")}</span>
        </button>
      `).join("")
    : '<div class="project-list-empty">No projects</div>';
}

function showProjectPanel(state) {
  $("#project-empty").classList.toggle("hidden", state !== "empty");
  $("#project-loading").classList.toggle("hidden", state !== "loading");
  $("#project-detail").classList.toggle("hidden", state !== "detail");
}

function activateProjectView() {
  if (!activeProject && projectCatalog.length) {
    selectProject(projectCatalog[0].project);
  } else if (activeProject && !projectContents) {
    loadProjectContents(true);
  } else if (!activeProject) {
    showProjectPanel("empty");
  }
}

async function selectProject(reference) {
  if (!projectCatalog.some((project) => project.project === reference)) return;
  activeProject = reference;
  projectContents = null;
  currentProjectFolder = "";
  selectedProjectFiles.clear();
  renderProjectSidebar();
  await loadProjectContents(true);
}

async function loadProjectContents(resetFolder = false) {
  if (!activeProject) {
    showProjectPanel("empty");
    return;
  }
  if (resetFolder) currentProjectFolder = "";
  const reference = activeProject;
  const sequence = ++projectLoadSequence;
  showProjectPanel("loading");
  try {
    const value = await call(`/projects/${encodeURIComponent(reference)}/contents`);
    if (sequence !== projectLoadSequence || activeProject !== reference) return;
    projectContents = value.result;
    const filePaths = new Set(projectContents.files.map((file) => file.path));
    for (const path of selectedProjectFiles) {
      if (!filePaths.has(path)) selectedProjectFiles.delete(path);
    }
    if (currentProjectFolder
        && !projectContents.folders.some((folder) => folder.path === currentProjectFolder)) {
      currentProjectFolder = "";
    }
    renderProjectContents();
    showProjectPanel("detail");
  } catch (error) {
    if (sequence !== projectLoadSequence || activeProject !== reference) return;
    projectContents = null;
    $("#project-empty").textContent = "This project could not be loaded.";
    showProjectPanel("empty");
    toast(error.message, true);
  }
}

function projectFilePresentation(path) {
  const lower = path.toLowerCase();
  if (lower.endsWith(".bndb")) {
    return {icon: "file-tray-full-outline", label: "Binary Ninja database", format: "bndb", readable: false};
  }
  if (lower.endsWith(".md")) {
    return {icon: "reader-outline", label: "Markdown document", format: "markdown", readable: true};
  }
  if (lower.endsWith(".txt")) {
    return {icon: "document-outline", label: "Text document", format: "text", readable: true};
  }
  if (lower.endsWith(".json")) {
    return {icon: "document-outline", label: "JSON document", format: "json", readable: true};
  }
  return {icon: "document-outline", label: "Document", format: "document", readable: false};
}

function formatProjectDate(timestamp) {
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) return "—";
  return new Date(timestamp * 1000).toLocaleString();
}

function highlightJson(content) {
  const pattern = /("(?:\\u[0-9a-fA-F]{4}|\\[^u]|[^\\"])*")(\s*:)?|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false)\b|\bnull\b/g;
  let output = "";
  let offset = 0;
  for (const match of content.matchAll(pattern)) {
    output += escapeHtml(content.slice(offset, match.index));
    const token = match[0];
    let kind = "number";
    if (match[1]) kind = match[2] ? "key" : "string";
    else if (token === "true" || token === "false") kind = "boolean";
    else if (token === "null") kind = "null";
    if (match[1] && match[2]) {
      output += `<span class="json-${kind}">${escapeHtml(match[1])}</span>${escapeHtml(match[2])}`;
    } else {
      output += `<span class="json-${kind}">${escapeHtml(token)}</span>`;
    }
    offset = match.index + token.length;
  }
  return output + escapeHtml(content.slice(offset));
}

const codeKeywords = new Set([
  "abstract", "alignas", "alignof", "and", "as", "async", "await", "base", "bool", "boolean", "break",
  "case", "catch", "char", "class", "const", "constexpr", "continue", "crate", "def", "default", "defer",
  "delete", "do", "double", "dyn", "else", "enum", "except", "export", "extends", "extern", "false",
  "final", "finally", "float", "fn", "for", "foreach", "from", "func", "function", "global", "go", "goto",
  "if", "impl", "import", "in", "inline", "instanceof", "int", "interface", "is", "lambda", "let", "long",
  "match", "mod", "mutable", "namespace", "native", "new", "nil", "None", "nonlocal", "not", "null",
  "object", "operator", "or", "override", "package", "pass", "private", "protected", "protocol", "public",
  "raise", "readonly", "ref", "register", "repeat", "return", "self", "short", "signed", "sizeof", "static",
  "str", "struct", "super", "switch", "synchronized", "template", "this", "throw", "throws", "trait", "true",
  "try", "type", "typedef", "typename", "typeof", "union", "unsafe", "unsigned", "use", "using", "var",
  "virtual", "void", "volatile", "where", "while", "with", "yield",
]);

const codeLiterals = new Set(["true", "false", "null", "nil", "None", "undefined", "NaN", "Infinity"]);

function highlightCode(content, language = "") {
  const normalized = language.trim().toLowerCase();
  if (normalized === "json" || normalized === "jsonc") return highlightJson(content);
  const pattern = /\/\*[\s\S]*?\*\/|\/\/[^\n]*|<!--[\s\S]*?-->|#[^\n]*|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'|`(?:\\[\s\S]|[^`\\])*`|-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b[A-Za-z_$][\w$]*\b/g;
  let output = "";
  let offset = 0;
  for (const match of content.matchAll(pattern)) {
    output += escapeHtml(content.slice(offset, match.index));
    const token = match[0];
    let kind = "";
    if (token.startsWith("/*") || token.startsWith("//") || token.startsWith("<!--")) {
      kind = "comment";
    } else if (token.startsWith("#")) {
      kind = ["c", "h", "cpp", "c++", "cc", "cxx", "objc", "objective-c"].includes(normalized)
        ? "directive"
        : "comment";
    } else if (token.startsWith('"') || token.startsWith("'") || token.startsWith("`")) {
      kind = "string";
    } else if (/^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d)/.test(token)) {
      kind = "number";
    } else if (codeLiterals.has(token)) {
      kind = "literal";
    } else if (codeKeywords.has(token)) {
      kind = "keyword";
    } else if (/^\s*\(/.test(content.slice(match.index + token.length))) {
      kind = "function";
    } else if (/^[A-Z]/.test(token)) {
      kind = "type";
    }
    output += kind ? `<span class="code-${kind}">${escapeHtml(token)}</span>` : escapeHtml(token);
    offset = match.index + token.length;
  }
  return output + escapeHtml(content.slice(offset));
}

function safeMarkdownHref(value) {
  const requested = value.trim();
  if (requested.startsWith("#")) {
    return /^#[\p{L}\p{N}_.:-]+$/u.test(requested) ? {href: requested, newWindow: false} : null;
  }
  try {
    const parsed = new URL(requested, location.href);
    if (parsed.protocol === "binaryninja:") return {href: requested, newWindow: false};
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return {href: parsed.href, newWindow: true};
  } catch {
    return null;
  }
}

function restoreMarkdownFragments(value, fragments) {
  let output = value;
  for (let pass = 0; pass <= fragments.length && output.includes("\0"); pass += 1) {
    output = output.replace(/\0(\d+)\0/g, (_, index) => fragments[Number(index)] ?? "");
  }
  return output;
}

function renderMarkdownInline(text) {
  const fragments = [];
  const stash = (html) => `\0${fragments.push(html) - 1}\0`;
  let source = text;
  source = source.replace(/`([^`\n]+)`/g, (_, code) => stash(`<code>${escapeHtml(code)}</code>`));
  source = source.replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, (_, label) =>
    stash(`<span class="markdown-image-label">${escapeHtml(label || "Image")}</span>`));
  source = source.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, href) => {
    const safe = safeMarkdownHref(href);
    if (!safe) return label;
    const target = safe.newWindow ? ' target="_blank" rel="noopener noreferrer"' : "";
    return stash(`<a href="${escapeHtml(safe.href)}"${target}>${escapeHtml(label)}</a>`);
  });
  let output = escapeHtml(source);
  output = output.replace(/~~([^~]+)~~/g, "<del>$1</del>");
  output = output.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  output = output.replace(/__([^_]+)__/g, "<strong>$1</strong>");
  output = output.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  return restoreMarkdownFragments(output, fragments);
}

function markdownCells(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
}

function markdownTableDelimiter(line) {
  const cells = markdownCells(line);
  return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell));
}

function markdownHeadingLabel(value) {
  return value
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[*_~]/g, "")
    .replace(/<[^>]*>/g, "")
    .trim();
}

function markdownHeadingId(label, counts) {
  const base = label.normalize("NFKD").toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-+|-+$/g, "") || "section";
  const count = counts.get(base) || 0;
  counts.set(base, count + 1);
  return count ? `${base}-${count + 1}` : base;
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\r\n?/g, "\n").split("\n");
  const output = [];
  const headings = [];
  const headingCounts = new Map();
  let paragraph = [];
  let list = null;
  const flushParagraph = () => {
    if (!paragraph.length) return;
    output.push(`<p>${renderMarkdownInline(paragraph.join(" "))}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (!list) return;
    output.push(`<${list.tag}>${list.items.map((item) => `<li>${renderMarkdownInline(item)}</li>`).join("")}</${list.tag}>`);
    list = null;
  };
  const flush = () => {
    flushParagraph();
    flushList();
  };

  for (let index = 0; index < lines.length;) {
    const line = lines[index];
    const fence = line.match(/^\s*```\s*([^\s`]*)\s*$/);
    if (fence) {
      flush();
      const code = [];
      const language = fence[1].toLowerCase().replace(/[^a-z0-9_+#.-]/g, "");
      index += 1;
      while (index < lines.length && !/^\s*```\s*$/.test(lines[index])) {
        code.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      const languageAttribute = language ? ` data-language="${escapeHtml(language)}"` : "";
      output.push(`<pre class="markdown-code-block"${languageAttribute}><code>${highlightCode(code.join("\n"), language)}</code></pre>`);
      continue;
    }

    if (index + 1 < lines.length && line.includes("|") && markdownTableDelimiter(lines[index + 1])) {
      flush();
      const headings = markdownCells(line);
      const delimiters = markdownCells(lines[index + 1]);
      const alignments = delimiters.map((cell) =>
        cell.startsWith(":") && cell.endsWith(":") ? "center" : cell.endsWith(":") ? "right" : "left");
      index += 2;
      const rows = [];
      while (index < lines.length && lines[index].trim() && lines[index].includes("|")) {
        rows.push(markdownCells(lines[index]));
        index += 1;
      }
      const heading = headings.map((cell, column) =>
        `<th class="align-${alignments[column] || "left"}">${renderMarkdownInline(cell)}</th>`).join("");
      const body = rows.map((row) => `<tr>${headings.map((_, column) =>
        `<td class="align-${alignments[column] || "left"}">${renderMarkdownInline(row[column] || "")}</td>`).join("")}</tr>`).join("");
      output.push(`<table><thead><tr>${heading}</tr></thead><tbody>${body}</tbody></table>`);
      continue;
    }

    if (!line.trim()) {
      flush();
      index += 1;
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      flush();
      const level = heading[1].length;
      const source = heading[2].trim();
      const label = markdownHeadingLabel(source) || `Section ${headings.length + 1}`;
      const id = markdownHeadingId(label, headingCounts);
      headings.push({level, label, id});
      output.push(`<h${level} id="${escapeHtml(id)}">${renderMarkdownInline(source)}</h${level}>`);
      index += 1;
      continue;
    }

    if (/^\s{0,3}(?:(?:-\s*){3,}|(?:\*\s*){3,}|(?:_\s*){3,})$/.test(line)) {
      flush();
      output.push("<hr>");
      index += 1;
      continue;
    }

    if (/^\s*>/.test(line)) {
      flush();
      const quote = [];
      while (index < lines.length && /^\s*>/.test(lines[index])) {
        quote.push(lines[index].replace(/^\s*>\s?/, ""));
        index += 1;
      }
      output.push(`<blockquote><p>${renderMarkdownInline(quote.join(" "))}</p></blockquote>`);
      continue;
    }

    const unordered = line.match(/^\s*[-+*]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
    if (unordered || ordered) {
      flushParagraph();
      const tag = ordered ? "ol" : "ul";
      if (list?.tag !== tag) flushList();
      if (!list) list = {tag, items: []};
      list.items.push((ordered || unordered)[1]);
      index += 1;
      continue;
    }

    flushList();
    paragraph.push(line.trim());
    index += 1;
  }
  flush();
  const body = output.join("");
  if (!headings.length) return {html: body, toc: ""};
  const minimumLevel = Math.min(...headings.map((heading) => heading.level));
  const items = headings.map((heading) =>
    `<li class="toc-depth-${Math.min(5, heading.level - minimumLevel)}"><a href="#${escapeHtml(heading.id)}">${escapeHtml(heading.label)}</a></li>`).join("");
  return {
    html: body,
    toc: `<nav class="markdown-toc" aria-label="Table of contents"><strong>Contents</strong><ol>${items}</ol></nav>`,
  };
}

function updateProjectReaderToc() {
  const content = $("#project-reader-content");
  const toc = $("#project-reader-toc");
  if (toc.classList.contains("hidden")) return;
  const headings = [...content.querySelectorAll(".project-reader-markdown h1[id], .project-reader-markdown h2[id], .project-reader-markdown h3[id], .project-reader-markdown h4[id], .project-reader-markdown h5[id], .project-reader-markdown h6[id]")];
  if (!headings.length) return;
  const threshold = content.getBoundingClientRect().top + 32;
  let active = headings[0];
  for (const heading of headings) {
    if (heading.getBoundingClientRect().top > threshold) break;
    active = heading;
  }
  if (toc.dataset.activeHeading === active.id) return;
  toc.dataset.activeHeading = active.id;
  let activeLink = null;
  for (const link of toc.querySelectorAll("a[href^='#']")) {
    const selected = link.getAttribute("href") === `#${active.id}`;
    link.classList.toggle("active", selected);
    if (selected) activeLink = link;
  }
  if (activeLink) {
    const top = activeLink.offsetTop;
    const bottom = top + activeLink.offsetHeight;
    if (top < toc.scrollTop || bottom > toc.scrollTop + toc.clientHeight) {
      toc.scrollTo({top: Math.max(0, top - toc.clientHeight / 3), behavior: "smooth"});
    }
  }
}

function renderProjectDocument(document) {
  const content = $("#project-reader-content");
  const main = $("#project-reader-main");
  const toc = $("#project-reader-toc");
  const kindLabel = document.kind === "json" ? "JSON" : document.kind === "markdown" ? "Markdown" : "Text";
  $("#project-reader-title").textContent = document.path.split("/").at(-1) || document.path;
  $("#project-reader-meta").textContent = `${kindLabel} · ${formatMemoryBytes(document.size)}`;
  main.classList.remove("has-toc");
  toc.classList.add("hidden");
  delete toc.dataset.activeHeading;
  toc.replaceChildren();
  if (document.kind === "markdown") {
    const rendered = renderMarkdown(document.content);
    content.innerHTML = `<article class="project-reader-markdown">${rendered.html}</article>`;
    if (rendered.toc) {
      toc.innerHTML = rendered.toc;
      toc.classList.remove("hidden");
      main.classList.add("has-toc");
      requestAnimationFrame(updateProjectReaderToc);
    }
  } else if (document.kind === "json") {
    content.innerHTML = `<pre class="project-reader-code project-reader-json"><code>${highlightJson(document.content)}</code></pre>`;
  } else {
    content.innerHTML = `<pre class="project-reader-code">${escapeHtml(document.content)}</pre>`;
  }
}

async function openProjectDocument(path) {
  if (!activeProject) return;
  const project = activeProject;
  const sequence = ++projectDocumentSequence;
  const dialog = $("#project-reader-dialog");
  $("#project-reader-title").textContent = path.split("/").at(-1) || path;
  $("#project-reader-meta").textContent = path;
  $("#project-reader-main").classList.remove("has-toc");
  $("#project-reader-toc").classList.add("hidden");
  delete $("#project-reader-toc").dataset.activeHeading;
  $("#project-reader-toc").replaceChildren();
  $("#project-reader-content").innerHTML = '<div class="project-reader-message">Loading document…</div>';
  if (!dialog.open) dialog.showModal();
  try {
    const value = await call(`/projects/${encodeURIComponent(project)}/documents`, {
      method: "POST",
      body: JSON.stringify({path}),
    });
    if (sequence !== projectDocumentSequence || !dialog.open || activeProject !== project) return;
    renderProjectDocument(value.result);
  } catch (error) {
    if (sequence !== projectDocumentSequence || !dialog.open) return;
    $("#project-reader-content").innerHTML = `<div class="project-reader-message bad">${escapeHtml(error.message)}</div>`;
    toast(error.message, true);
  }
}

function renderProjectBreadcrumbs() {
  const parts = currentProjectFolder ? currentProjectFolder.split("/") : [];
  const breadcrumbs = [{name: projectContents.project.name, path: ""}];
  let path = "";
  for (const part of parts) {
    path = path ? `${path}/${part}` : part;
    breadcrumbs.push({name: part, path});
  }
  $("#project-breadcrumbs").innerHTML = breadcrumbs.map((item) => `
    <button data-action="navigate-project-folder" data-path="${escapeHtml(item.path)}">${escapeHtml(item.name)}</button>
  `).join("");
}

function renderProjectContents() {
  if (!projectContents) return;
  $("#project-detail-name").textContent = projectContents.project.name;
  $("#project-detail-description").textContent = projectContents.project.description || "";
  renderProjectBreadcrumbs();

  const folders = projectContents.folders
    .filter((folder) => (folder.parent || "") === currentProjectFolder)
    .sort((left, right) => left.name.localeCompare(right.name));
  const files = projectContents.files
    .filter((file) => (file.folder || "") === currentProjectFolder)
    .sort((left, right) => left.name.localeCompare(right.name));
  if (!folders.length && !files.length) {
    $("#project-entries").innerHTML = '<div class="project-entry-empty">This folder is empty.</div>';
    updateSelectedProjectFiles();
    return;
  }

  const allVisibleSelected = files.length > 0 && files.every((file) => selectedProjectFiles.has(file.path));
  const folderRows = folders.map((folder) => `
    <tr>
      <td></td>
      <td><div class="project-entry-name">
        <span class="project-entry-kind folder" role="img" aria-label="Folder" data-tooltip="Folder">${ionIcon("folder-open-outline")}</span>
        <button data-action="navigate-project-folder" data-path="${escapeHtml(folder.path)}">${escapeHtml(folder.name)}</button>
      </div></td>
      <td class="project-entry-description">${escapeHtml(folder.description || "")}</td>
      <td>—</td>
      <td class="project-entry-actions">
        ${projectIconButton("download-project-folder", "download-outline", "Download folder", "", `data-path="${escapeHtml(folder.path)}"`)}
        ${projectIconButton("edit-project-folder", "create-outline", "Edit folder", "", `data-path="${escapeHtml(folder.path)}"`)}
        ${projectIconButton("delete-project-folder", "trash-outline", "Delete folder", "", `data-path="${escapeHtml(folder.path)}"`)}
      </td>
    </tr>
  `).join("");
  const fileRows = files.map((file) => {
    const presentation = projectFilePresentation(file.path);
    const fileName = presentation.readable
      ? `<button data-action="open-project-document" data-path="${escapeHtml(file.path)}" title="${escapeHtml(file.path)}">${escapeHtml(file.name)}</button>`
      : `<span title="${escapeHtml(file.path)}">${escapeHtml(file.name)}</span>`;
    return `
      <tr>
        <td><input class="project-file-select" type="checkbox" data-path="${escapeHtml(file.path)}"
                   aria-label="Select ${escapeHtml(file.name)}" ${selectedProjectFiles.has(file.path) ? "checked" : ""}></td>
        <td><div class="project-entry-name">
          <span class="project-entry-kind" data-format="${escapeHtml(presentation.format)}" role="img" aria-label="${escapeHtml(presentation.label)}" data-tooltip="${escapeHtml(presentation.label)}">${ionIcon(presentation.icon)}</span>
          ${fileName}
        </div></td>
        <td class="project-entry-description">${escapeHtml(file.description || "")}</td>
        <td class="meta">${escapeHtml(formatProjectDate(file.created_at))}</td>
        <td class="project-entry-actions">
          ${projectIconButton("download-project-file", "download-outline", "Download file", "", `data-path="${escapeHtml(file.path)}"`)}
          ${projectIconButton("edit-project-file", "create-outline", "Edit file", "", `data-path="${escapeHtml(file.path)}"`)}
          ${projectIconButton("delete-project-file", "trash-outline", "Delete file", "", `data-path="${escapeHtml(file.path)}"`)}
        </td>
      </tr>`;
  }).join("");
  $("#project-entries").innerHTML = `
    <table>
      <thead><tr>
        <th><input id="project-file-select-all" type="checkbox" aria-label="Select all files in this folder"
                   ${allVisibleSelected ? "checked" : ""} ${files.length ? "" : "disabled"}></th>
        <th>Name</th><th>Description</th><th>Created</th><th></th>
      </tr></thead>
      <tbody>${folderRows}${fileRows}</tbody>
    </table>`;
  updateSelectedProjectFiles();
}

function updateSelectedProjectFiles() {
  const button = $("#download-selected-files");
  const count = selectedProjectFiles.size;
  button.disabled = count === 0;
  const label = count ? `Download ${count} selected ${count === 1 ? "file" : "files"}` : "Download selected files";
  button.setAttribute("aria-label", label);
  button.dataset.tooltip = label;
  button.innerHTML = `${ionIcon("download-outline")}${count ? `<span class="icon-button-badge">${count}</span>` : ""}`;
}

function navigateProjectFolder(path) {
  if (!projectContents) return;
  if (path && !projectContents.folders.some((folder) => folder.path === path)) return;
  currentProjectFolder = path;
  renderProjectContents();
}

function folderOptions(selected = "", excluded = "") {
  const folders = (projectContents?.folders || [])
    .filter((folder) => !excluded || (folder.path !== excluded && !folder.path.startsWith(`${excluded}/`)))
    .sort((left, right) => left.path.localeCompare(right.path));
  return [
    `<option value="" ${selected ? "" : "selected"}>Project root</option>`,
    ...folders.map((folder) => `<option value="${escapeHtml(folder.path)}" ${folder.path === selected ? "selected" : ""}>${escapeHtml(folder.path)}</option>`),
  ].join("");
}

function closeDialog(element) {
  const dialog = element?.closest("dialog");
  if (dialog?.open) dialog.close();
}

function openProjectCreate() {
  $("#project-create-form").reset();
  $("#project-create-dialog").showModal();
  $("#project-name").focus();
}

async function submitProjectCreate() {
  const name = $("#project-name").value.trim();
  if (!name) {
    toast("Project name is required", true);
    return;
  }
  try {
    const value = await call("/projects", {
      method: "POST",
      body: JSON.stringify({
        name,
        path: $("#project-path").value.trim(),
        description: $("#project-description").value,
      }),
    });
    $("#project-create-dialog").close();
    activeProject = value.result.project;
    projectContents = null;
    await refreshStatus();
    await loadProjectContents(true);
    toast("Project created");
  } catch (error) {
    toast(error.message, true);
  }
}

function openProjectEdit() {
  if (!projectContents) return;
  $("#project-edit-name").value = projectContents.project.name;
  $("#project-edit-description").value = projectContents.project.description || "";
  $("#project-edit-dialog").showModal();
  $("#project-edit-name").focus();
}

async function submitProjectEdit() {
  if (!activeProject || !projectContents) return;
  const name = $("#project-edit-name").value.trim();
  if (!name) {
    toast("Project name is required", true);
    return;
  }
  try {
    const value = await call(`/projects/${encodeURIComponent(activeProject)}`, {
      method: "PATCH",
      body: JSON.stringify({name, description: $("#project-edit-description").value}),
    });
    projectContents.project = value.result;
    const item = projectCatalog.find((project) => project.project === activeProject);
    if (item) Object.assign(item, value.result);
    $("#project-edit-dialog").close();
    renderProjectSidebar();
    renderProjectContents();
    toast("Project updated");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteProject() {
  if (!activeProject) return;
  if (!confirm("Permanently delete this closed project and all of its files?")) return;
  try {
    await call(`/projects/${encodeURIComponent(activeProject)}`, {
      method: "DELETE",
      body: JSON.stringify({delete: true}),
    });
    activeProject = "";
    projectContents = null;
    currentProjectFolder = "";
    selectedProjectFiles.clear();
    await refreshStatus();
    toast("Project deleted");
  } catch (error) {
    toast(error.message, true);
  }
}

function openProjectFolder(path = "") {
  if (!projectContents) return;
  const dialog = $("#project-folder-dialog");
  dialog.dataset.path = path;
  const folder = path ? projectContents.folders.find((item) => item.path === path) : null;
  $("#project-folder-dialog-title").textContent = folder ? "Edit folder" : "New folder";
  $("#project-folder-name").value = folder?.name || "";
  $("#project-folder-description").value = folder?.description || "";
  $("#project-folder-parent").innerHTML = folderOptions(folder?.parent || currentProjectFolder, folder?.path || "");
  dialog.showModal();
  $("#project-folder-name").focus();
}

async function submitProjectFolder() {
  if (!activeProject || !projectContents) return;
  const dialog = $("#project-folder-dialog");
  const path = dialog.dataset.path || "";
  const name = $("#project-folder-name").value.trim();
  if (!name) {
    toast("Folder name is required", true);
    return;
  }
  const body = {
    name,
    description: $("#project-folder-description").value,
    parent: $("#project-folder-parent").value || null,
  };
  if (path) body.path = path;
  try {
    await call(`/projects/${encodeURIComponent(activeProject)}/folders`, {
      method: path ? "PATCH" : "POST",
      body: JSON.stringify(body),
    });
    dialog.close();
    await loadProjectContents(false);
    toast(path ? "Folder updated" : "Folder created");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteProjectFolder(path) {
  if (!activeProject || !confirm(`Delete “${path}” and all of its contents?`)) return;
  try {
    await call(`/projects/${encodeURIComponent(activeProject)}/folders`, {
      method: "DELETE",
      body: JSON.stringify({path, recursive: true}),
    });
    await loadProjectContents(false);
    toast("Folder deleted");
  } catch (error) {
    toast(error.message, true);
  }
}

function openProjectFile(path) {
  if (!projectContents) return;
  const file = projectContents.files.find((item) => item.path === path);
  if (!file) return;
  const dialog = $("#project-file-dialog");
  dialog.dataset.path = path;
  $("#project-file-name").value = file.name;
  $("#project-file-description").value = file.description || "";
  $("#project-file-folder").innerHTML = folderOptions(file.folder || "");
  dialog.showModal();
  $("#project-file-name").focus();
}

async function submitProjectFile() {
  if (!activeProject || !projectContents) return;
  const dialog = $("#project-file-dialog");
  const path = dialog.dataset.path || "";
  const name = $("#project-file-name").value.trim();
  if (!path || !name) {
    toast("File name is required", true);
    return;
  }
  try {
    await call(`/projects/${encodeURIComponent(activeProject)}/files`, {
      method: "PATCH",
      body: JSON.stringify({
        path,
        name,
        description: $("#project-file-description").value,
        folder: $("#project-file-folder").value || null,
      }),
    });
    selectedProjectFiles.delete(path);
    dialog.close();
    await loadProjectContents(false);
    toast("File updated");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteProjectFile(path) {
  if (!activeProject || !confirm(`Delete “${path}” from this project?`)) return;
  try {
    await call(`/projects/${encodeURIComponent(activeProject)}/files`, {
      method: "DELETE",
      body: JSON.stringify({path, delete: true}),
    });
    selectedProjectFiles.delete(path);
    await loadProjectContents(false);
    toast("File deleted");
  } catch (error) {
    toast(error.message, true);
  }
}

async function prepareProjectDownload(kind, paths = []) {
  if (!activeProject) return;
  try {
    toast("Preparing download…");
    const value = await call(`/projects/${encodeURIComponent(activeProject)}/downloads`, {
      method: "POST",
      body: JSON.stringify({kind, paths}),
    });
    const link = document.createElement("a");
    link.href = value.result.url;
    link.download = value.result.filename;
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
    toast("Download ready");
  } catch (error) {
    toast(error.message, true);
  }
}

function openProjectImport() {
  if (!projectContents) return;
  $("#project-import-form").reset();
  $("#project-import-folder").innerHTML = folderOptions(currentProjectFolder);
  $("#project-import-dialog").showModal();
}

async function submitProjectImport() {
  if (!activeProject || !projectContents) return;
  const source = $("#project-import-source").files[0];
  const filename = $("#project-import-name").value.trim();
  if (!source || !filename) {
    toast("Select a file and provide its project name", true);
    return;
  }
  const submit = $("#project-import-submit");
  submit.disabled = true;
  submit.classList.add("busy");
  submit.setAttribute("aria-label", "Importing file");
  submit.dataset.tooltip = "Importing file";
  submit.innerHTML = ionIcon("refresh-outline");
  try {
    const issued = await call(`/projects/${encodeURIComponent(activeProject)}/uploads`, {
      method: "POST",
      body: JSON.stringify({filename}),
    });
    const transferred = await fetch(issued.result.url, {
      method: "PUT",
      headers: {"Content-Type": "application/octet-stream"},
      body: source,
    });
    if (!transferred.ok) {
      let message = `Upload failed with HTTP ${transferred.status}`;
      try {
        const failure = await transferred.json();
        if (failure.error) message = failure.error;
      } catch {
        // Keep the HTTP status message.
      }
      throw new Error(message);
    }
    await call(`/projects/${encodeURIComponent(activeProject)}/uploads/commit`, {
      method: "POST",
      body: JSON.stringify({
        id: issued.result.id,
        folder: $("#project-import-folder").value || null,
        description: $("#project-import-description").value,
      }),
    });
    $("#project-import-dialog").close();
    await loadProjectContents(false);
    toast("File imported");
  } catch (error) {
    toast(error.message, true);
  } finally {
    submit.disabled = false;
    submit.classList.remove("busy");
    submit.setAttribute("aria-label", "Import file");
    submit.dataset.tooltip = "Import file";
    submit.innerHTML = ionIcon("cloud-upload-outline");
  }
}

function formatInactiveDuration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 60) return "less than a minute";
  if (value < 3600) return `${Math.floor(value / 60)} min`;
  if (value < 86400) return `${Math.floor(value / 3600)} hr`;
  return `${Math.floor(value / 86400)} days`;
}

function sessionTitle(session) {
  return `Session from ${new Date(session.created_at * 1000).toLocaleString()}`;
}

function renderRecoverySidebar() {
  $("#sessions-list").innerHTML = sessionCatalog.length
    ? sessionCatalog.map((session) => {
      const items = `${session.open_items} open ${session.open_items === 1 ? "item" : "items"}`;
      const jobs = session.jobs ? ` · ${session.jobs} ${session.jobs === 1 ? "job" : "jobs"}` : "";
      const active = session.active_jobs ? ` · ${session.active_jobs} active` : "";
      return `
        <button class="project-list-item${session.analysis_session === activeRecoverySession ? " on" : ""}"
                data-action="select-recovery-session" data-id="${escapeHtml(session.analysis_session)}">
          <strong>${escapeHtml(sessionTitle(session))}</strong>
          <span>${escapeHtml(`${items}${jobs}${active} · idle ${formatInactiveDuration(session.inactive_seconds)}`)}</span>
        </button>`;
    }).join("")
    : '<div class="project-list-empty">No recoverable sessions</div>';
}

function showRecoveryPanel(state) {
  $("#session-empty").classList.toggle("hidden", state !== "empty");
  $("#session-loading").classList.toggle("hidden", state !== "loading");
  $("#session-detail").classList.toggle("hidden", state !== "detail");
}

function activateSessionsView() {
  if (!sessionCatalog.length) {
    refreshRecoverySessions();
  } else if (!activeRecoverySession) {
    selectRecoverySession(sessionCatalog[0].analysis_session);
  } else if (!recoverySessionDetails) {
    loadRecoverySessionDetails();
  }
}

async function refreshRecoverySessions(silent = false) {
  const sequence = ++sessionLoadSequence;
  try {
    const value = await call("/sessions");
    if (sequence !== sessionLoadSequence) return;
    sessionCatalog = [...value.result].sort((left, right) => right.created_at - left.created_at);
    if (activeRecoverySession
        && !sessionCatalog.some((session) => session.analysis_session === activeRecoverySession)) {
      activeRecoverySession = "";
      recoverySessionDetails = null;
    }
    renderRecoverySidebar();
    if (currentView !== "sessions") return;
    if (!activeRecoverySession && sessionCatalog.length) {
      await selectRecoverySession(sessionCatalog[0].analysis_session);
    } else if (activeRecoverySession) {
      await loadRecoverySessionDetails(silent);
    } else {
      $("#session-empty").textContent = "No recoverable sessions.";
      showRecoveryPanel("empty");
    }
  } catch (error) {
    if (sequence !== sessionLoadSequence) return;
    if (!silent) toast(error.message, true);
    if (!sessionCatalog.length) {
      $("#session-empty").textContent = "Sessions could not be loaded.";
      showRecoveryPanel("empty");
    }
  }
}

async function selectRecoverySession(reference) {
  if (!sessionCatalog.some((session) => session.analysis_session === reference)) return;
  activeRecoverySession = reference;
  recoverySessionDetails = null;
  renderRecoverySidebar();
  await loadRecoverySessionDetails();
}

function recoveryViewChanges(view) {
  const changes = [];
  if (view.modified) changes.push("file modified");
  if (view.analysis_changed) changes.push("analysis changed");
  return changes.length ? changes.join(" · ") : "clean";
}

function renderRecoveryView(view, item) {
  const metadata = [view.view_type, view.architecture, view.platform].filter(Boolean).join(" · ");
  let status = view.created ? "Status unavailable" : "Not materialized";
  if (view.status_available) {
    status = `${view.analysis_state} · ${recoveryViewChanges(view)}`;
    if (view.total) status += ` · ${view.completed}/${view.total}`;
  } else if (view.error) {
    status = view.error;
  }
  const actions = [];
  if (view.created) {
    if (view.analysis_state === "running") {
      actions.push(projectIconButton("abort-recovery-view", "stop-circle-outline", "Abort analysis", "",
        `data-view="${escapeHtml(view.binary_view)}"`));
    } else {
      actions.push(projectIconButton("save-recovery-view", "save-outline", "Save BinaryView", "",
        `data-view="${escapeHtml(view.binary_view)}"`));
      actions.push(projectIconButton("save-as-recovery-view", "create-outline", "Save BinaryView as", "",
        `data-view="${escapeHtml(view.binary_view)}" data-item="${escapeHtml(item.open_item)}"`));
    }
  }
  return `
    <div class="session-view-row">
      <div class="session-view-copy">
        <strong>${escapeHtml(metadata || view.view_type)}</strong>
        <span>${escapeHtml(status)}</span>
      </div>
      <div class="session-view-actions">${actions.join("")}</div>
    </div>`;
}

function renderRecoveryItem(item) {
  const leaf = item.source.split("/").at(-1) || item.source;
  const origin = item.source_kind === "local_project" ? "Project file" : "Local path";
  const views = item.binary_views.map((view) => renderRecoveryView(view, item)).join("")
    || '<div class="session-recovery-empty">No BinaryView candidates.</div>';
  return `
    <article class="session-item">
      <header class="session-item-head">
        <div class="session-source-copy">
          <strong title="${escapeHtml(item.source)}">${escapeHtml(leaf)}</strong>
          <span>${escapeHtml(origin)} · ${escapeHtml(item.source)}</span>
        </div>
        <div class="session-item-actions">
          ${projectIconButton("close-recovery-item", "close-outline", "Close clean file", "",
            `data-item="${escapeHtml(item.open_item)}"`)}
          ${projectIconButton("discard-recovery-item", "trash-outline", "Discard and close file", "",
            `data-item="${escapeHtml(item.open_item)}"`)}
        </div>
      </header>
      <div class="session-view-list">${views}</div>
    </article>`;
}

function renderRecoveryJob(job) {
  const active = job.state === "queued" || job.state === "running";
  const detail = job.progress
    ? `${job.progress.phase}${job.progress.message ? ` · ${job.progress.message}` : ""}`
    : job.state;
  return `
    <div class="session-job-row">
      <div class="session-job-copy">
        <strong>${escapeHtml(job.operation)}</strong>
        <span>${escapeHtml(`${job.state} · ${detail}`)}</span>
      </div>
      <div class="session-view-actions">
        ${active ? projectIconButton("cancel-recovery-job", "stop-circle-outline", "Cancel job", "",
          `data-job="${escapeHtml(job.job)}"`) : ""}
      </div>
    </div>`;
}

function renderRecoverySession() {
  if (!recoverySessionDetails) return;
  const summary = recoverySessionDetails.session;
  $("#session-detail-name").textContent = sessionTitle(summary);
  $("#session-detail-description").textContent = `${summary.legacy ? "Legacy" : "Modern"} · idle ${formatInactiveDuration(summary.inactive_seconds)} · ${summary.open_items} open items · ${summary.jobs} jobs`;
  const items = recoverySessionDetails.open_items.map(renderRecoveryItem).join("")
    || '<div class="session-recovery-empty">No open files remain in this session.</div>';
  const jobs = recoverySessionDetails.jobs.map(renderRecoveryJob).join("")
    || '<div class="session-recovery-empty">No jobs belong to this session.</div>';
  $("#session-recovery-content").innerHTML = `
    <section class="session-recovery-group">
      <div class="session-recovery-group-title"><strong>Open files</strong><span>${recoverySessionDetails.open_items.length}</span></div>
      ${items}
    </section>
    <section class="session-recovery-group">
      <div class="session-recovery-group-title"><strong>Jobs</strong><span>${recoverySessionDetails.jobs.length}</span></div>
      <div class="session-job-list">${jobs}</div>
    </section>`;
  const recoverable = recoverySessionDetails.open_items.some((item) => item.binary_views.some((view) =>
    view.created && view.status_available && view.analysis_state !== "running"
      && (view.modified || view.analysis_changed)));
  $("#save-session-views").disabled = !recoverable;
  showRecoveryPanel("detail");
}

async function loadRecoverySessionDetails(silent = false) {
  if (!activeRecoverySession) {
    showRecoveryPanel("empty");
    return;
  }
  const reference = activeRecoverySession;
  const sequence = ++sessionLoadSequence;
  if (!recoverySessionDetails) showRecoveryPanel("loading");
  try {
    const value = await call(`/sessions/${encodeURIComponent(reference)}`);
    if (sequence !== sessionLoadSequence || activeRecoverySession !== reference) return;
    recoverySessionDetails = value.result;
    renderRecoverySession();
  } catch (error) {
    if (sequence !== sessionLoadSequence || activeRecoverySession !== reference) return;
    recoverySessionDetails = null;
    if (!silent) toast(error.message, true);
    $("#session-empty").textContent = "This session could not be loaded.";
    showRecoveryPanel("empty");
  }
}

async function saveRecoveryView(binaryView, destination) {
  if (!activeRecoverySession) return;
  try {
    toast("Saving BinaryView…");
    const body = {binary_view: binaryView};
    if (destination) body.destination = destination;
    const value = await call(`/sessions/${encodeURIComponent(activeRecoverySession)}/save`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    toast(`Saved to ${value.result.destination}`);
    await refreshRecoverySessions(true);
  } catch (error) {
    toast(error.message, true);
  }
}

function openRecoverySaveAs(binaryView, openItem) {
  if (!recoverySessionDetails) return;
  const item = recoverySessionDetails.open_items.find((candidate) => candidate.open_item === openItem);
  if (!item) return;
  const dialog = $("#session-save-as-dialog");
  dialog.dataset.view = binaryView;
  const source = item.source;
  const suggestion = source.toLowerCase().endsWith(".bndb")
    ? `${source.slice(0, -5)}.recovered.bndb`
    : `${source}.bndb`;
  $("#session-save-as-source").textContent = item.source_kind === "local_project"
    ? "Use a project-relative destination path."
    : "Use an absolute destination path.";
  $("#session-save-as-destination").value = suggestion;
  dialog.showModal();
  $("#session-save-as-destination").focus();
  $("#session-save-as-destination").select();
}

async function submitRecoverySaveAs() {
  const dialog = $("#session-save-as-dialog");
  const binaryView = dialog.dataset.view || "";
  const destination = $("#session-save-as-destination").value.trim();
  if (!binaryView || !destination) {
    toast("A save destination is required", true);
    return;
  }
  dialog.close();
  await saveRecoveryView(binaryView, destination);
}

async function saveAllRecoveryViews() {
  if (!activeRecoverySession) return;
  try {
    toast("Saving changed files…");
    const value = await call(`/sessions/${encodeURIComponent(activeRecoverySession)}/save-all`, {
      method: "POST",
      body: "{}",
    });
    const result = value.result;
    const message = `Saved ${result.saved.length}; skipped ${result.skipped}; failed ${result.failed.length}`;
    toast(message, result.failed.length > 0);
    await refreshRecoverySessions(true);
  } catch (error) {
    toast(error.message, true);
  }
}

async function abortRecoveryView(binaryView) {
  if (!activeRecoverySession) return;
  try {
    await call(`/sessions/${encodeURIComponent(activeRecoverySession)}/abort`, {
      method: "POST",
      body: JSON.stringify({binary_view: binaryView}),
    });
    toast("Analysis abort requested");
    await refreshRecoverySessions(true);
  } catch (error) {
    toast(error.message, true);
  }
}

async function cancelRecoveryJob(job) {
  if (!activeRecoverySession) return;
  try {
    await call(`/sessions/${encodeURIComponent(activeRecoverySession)}/jobs/cancel`, {
      method: "POST",
      body: JSON.stringify({job}),
    });
    toast("Job cancellation requested");
    await refreshRecoverySessions(true);
  } catch (error) {
    toast(error.message, true);
  }
}

async function closeRecoveryItem(openItem, discard) {
  if (!activeRecoverySession) return;
  if (discard && !confirm("Discard every unsaved change in this file and close it?")) return;
  try {
    await call(`/sessions/${encodeURIComponent(activeRecoverySession)}/items/close`, {
      method: "POST",
      body: JSON.stringify({open_item: openItem, discard}),
    });
    toast(discard ? "File discarded and closed" : "Clean file closed");
    await refreshRecoverySessions(true);
  } catch (error) {
    toast(error.message, true);
  }
}

async function forceCloseRecoverySession() {
  if (!activeRecoverySession) return;
  if (!confirm("Force close this session?\n\nThis cancels its jobs and discards all remaining unsaved file changes.")) return;
  const reference = activeRecoverySession;
  try {
    await call(`/sessions/${encodeURIComponent(reference)}`, {
      method: "DELETE",
      body: JSON.stringify({force: true}),
    });
    activeRecoverySession = "";
    recoverySessionDetails = null;
    await refreshRecoverySessions(true);
    toast("Session force closed");
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
    setRestartRequired(value.result.restart_required ?? !$("#restart-daemon").classList.contains("hidden"));
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
  delete configuration.uploads.require_bearer_authentication;
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
      ? "Configuration saved. Select Restart daemon to apply it."
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
    if (currentView === "sessions") await refreshRecoverySessions(true);
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
  logout,
  "refresh-all": refreshAll,
  "change-password": changePassword,
  "rotate-token": rotateToken,
  "copy-token": copyToken,
  "load-config": loadConfiguration,
  "save-config": saveConfiguration,
  "restart-daemon": restartDaemon,
};

$("#login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  login();
});

document.addEventListener("click", (event) => {
  const readerLink = event.target.closest("#project-reader-main a");
  if (readerLink) {
    const href = readerLink.getAttribute("href") || "";
    if (href.startsWith("#")) {
      event.preventDefault();
      let id = href.slice(1);
      try {
        id = decodeURIComponent(id);
      } catch {
        return;
      }
      const target = document.getElementById(id);
      if (target?.closest("#project-reader-content")) {
        target.scrollIntoView({behavior: "smooth", block: "start"});
      }
    }
    return;
  }
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "show-view") {
    showView(button.dataset.view, button);
  } else if (action === "revoke-token") {
    revokeToken();
  } else if (action === "create-project") {
    openProjectCreate();
  } else if (action === "select-project") {
    selectProject(button.dataset.id);
  } else if (action === "edit-project") {
    openProjectEdit();
  } else if (action === "delete-project") {
    deleteProject();
  } else if (action === "navigate-project-folder") {
    navigateProjectFolder(button.dataset.path || "");
  } else if (action === "open-project-document") {
    openProjectDocument(button.dataset.path);
  } else if (action === "create-project-folder") {
    openProjectFolder();
  } else if (action === "refresh-project") {
    loadProjectContents(false);
  } else if (action === "edit-project-folder") {
    openProjectFolder(button.dataset.path);
  } else if (action === "delete-project-folder") {
    deleteProjectFolder(button.dataset.path);
  } else if (action === "edit-project-file") {
    openProjectFile(button.dataset.path);
  } else if (action === "delete-project-file") {
    deleteProjectFile(button.dataset.path);
  } else if (action === "download-project") {
    prepareProjectDownload("project");
  } else if (action === "download-project-folder") {
    prepareProjectDownload("folder", [button.dataset.path]);
  } else if (action === "download-project-file") {
    prepareProjectDownload("file", [button.dataset.path]);
  } else if (action === "download-selected-files") {
    prepareProjectDownload("files", [...selectedProjectFiles]);
  } else if (action === "import-project-file") {
    openProjectImport();
  } else if (action === "close-dialog") {
    closeDialog(button);
  } else if (action === "select-recovery-session") {
    selectRecoverySession(button.dataset.id);
  } else if (action === "refresh-sessions") {
    refreshRecoverySessions();
  } else if (action === "refresh-session") {
    loadRecoverySessionDetails();
  } else if (action === "save-recovery-view") {
    saveRecoveryView(button.dataset.view);
  } else if (action === "save-as-recovery-view") {
    openRecoverySaveAs(button.dataset.view, button.dataset.item);
  } else if (action === "save-session-views") {
    saveAllRecoveryViews();
  } else if (action === "abort-recovery-view") {
    abortRecoveryView(button.dataset.view);
  } else if (action === "cancel-recovery-job") {
    cancelRecoveryJob(button.dataset.job);
  } else if (action === "close-recovery-item") {
    closeRecoveryItem(button.dataset.item, false);
  } else if (action === "discard-recovery-item") {
    closeRecoveryItem(button.dataset.item, true);
  } else if (action === "force-close-session") {
    forceCloseRecoverySession();
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
  if (event.target.matches(".project-file-select")) {
    if (event.target.checked) selectedProjectFiles.add(event.target.dataset.path);
    else selectedProjectFiles.delete(event.target.dataset.path);
    updateSelectedProjectFiles();
  }
  if (event.target.matches("#project-file-select-all") && projectContents) {
    const visibleFiles = projectContents.files.filter((file) => (file.folder || "") === currentProjectFolder);
    for (const file of visibleFiles) {
      if (event.target.checked) selectedProjectFiles.add(file.path);
      else selectedProjectFiles.delete(file.path);
    }
    renderProjectContents();
  }
  if (event.target.matches("#project-import-source")) {
    const file = event.target.files[0];
    if (file) $("#project-import-name").value = file.name;
  }
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

$("#project-create-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitProjectCreate();
});

$("#project-edit-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitProjectEdit();
});

$("#project-folder-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitProjectFolder();
});

$("#project-file-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitProjectFile();
});

$("#project-import-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitProjectImport();
});

$("#session-save-as-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitRecoverySaveAs();
});

$("#project-reader-dialog").addEventListener("close", () => {
  projectDocumentSequence += 1;
  $("#project-reader-main").classList.remove("has-toc");
  $("#project-reader-toc").classList.add("hidden");
  delete $("#project-reader-toc").dataset.activeHeading;
  $("#project-reader-toc").replaceChildren();
  $("#project-reader-content").replaceChildren();
});

$("#project-reader-content").addEventListener("scroll", updateProjectReaderToc, {passive: true});

$("#project-reader-dialog").addEventListener("click", (event) => {
  const dialog = event.currentTarget;
  if (event.target !== dialog) return;
  const bounds = dialog.getBoundingClientRect();
  const outside = event.clientX < bounds.left || event.clientX > bounds.right
    || event.clientY < bounds.top || event.clientY > bounds.bottom;
  if (outside) dialog.close();
});

renderEnabledToolPacks();

try {
  const onboardedUsername = sessionStorage.getItem("binjad-onboarded-username");
  if (onboardedUsername) {
    $("#login-user").value = onboardedUsername;
    sessionStorage.removeItem("binjad-onboarded-username");
  }
} catch {
  // Username prefill is optional when browser storage is unavailable.
}
