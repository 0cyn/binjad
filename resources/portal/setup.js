const setupSuffix = "/setup";
const portalPath = location.pathname.endsWith(setupSuffix)
  ? location.pathname.slice(0, -setupSuffix.length)
  : location.pathname.replace(/\/$/, "");
const setupApi = `${portalPath}/api`;
const $ = (selector) => document.querySelector(selector);

let currentStep = 0;
let submitting = false;
const finalStep = 3;

function base64Utf8(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function request(path, options = {}) {
  const response = await fetch(`${setupApi}${path}`, {
    cache: "no-store",
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(options.body ? {"Content-Type": "application/json"} : {}),
    },
  });
  const text = await response.text();
  let value = {};
  try {
    value = text ? JSON.parse(text) : {};
  } catch {
    value = {error: text || String(response.status)};
  }
  if (!response.ok) throw new Error(value.error || String(response.status));
  return value.result;
}

function showError(message = "") {
  const output = $("#onboarding-error");
  output.textContent = message;
  output.classList.toggle("hidden", !message);
}

function updateAccessProfile() {
  const arbitraryPaths = $("#onboarding-arbitrary-paths").checked;
  const projectRegistration = $("#onboarding-project-registration").checked;
  const selected = arbitraryPaths && projectRegistration
    ? "local"
    : !arbitraryPaths && !projectRegistration
      ? "remote"
      : "custom";
  document.querySelectorAll("[data-profile]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.profile === selected));
  });
}

function applyAccessProfile(profile) {
  const local = profile === "local";
  $("#onboarding-arbitrary-paths").checked = local;
  $("#onboarding-project-registration").checked = local;
  updateAccessProfile();
}

function updateReview() {
  $("#onboarding-review-root").textContent = $("#onboarding-project-root").value.trim();
  $("#onboarding-review-url").textContent = $("#onboarding-public-url").value.trim();
}

function showStep(step) {
  currentStep = Math.max(0, Math.min(finalStep, step));
  document.querySelectorAll(".onboarding-step").forEach((element) => {
    element.classList.toggle("hidden", Number(element.dataset.step) !== currentStep);
  });
  document.querySelectorAll("[data-progress]").forEach((element) => {
    const index = Number(element.dataset.progress);
    element.classList.toggle("on", index === currentStep);
    element.classList.toggle("done", index < currentStep);
    if (index === currentStep) element.setAttribute("aria-current", "step");
    else element.removeAttribute("aria-current");
  });
  $("#onboarding-back").classList.toggle("hidden", currentStep === 0);
  $("#onboarding-next").textContent = currentStep === finalStep ? "Create account and token" : "Continue";
  showError();
  if (currentStep === finalStep) updateReview();
  const visibleStep = document.querySelector(`.onboarding-step[data-step="${currentStep}"]`);
  visibleStep.querySelector("input, select, button")?.focus();
}

function validCurrentStep() {
  const step = document.querySelector(`.onboarding-step[data-step="${currentStep}"]`);
  for (const input of step.querySelectorAll("input, select")) {
    if (!input.reportValidity()) return false;
  }
  if (currentStep === 1) {
    try {
      const url = new URL($("#onboarding-public-url").value);
      if (!["http:", "https:"].includes(url.protocol)) throw new Error();
    } catch {
      showError("Public URL must be an absolute HTTP or HTTPS URL.");
      return false;
    }
  }
  if (currentStep === 2) {
    const username = $("#onboarding-username").value;
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(username)) {
      showError("Username can contain ASCII letters, digits, periods, underscores, and hyphens.");
      return false;
    }
    const password = $("#onboarding-password").value;
    const passwordBytes = new TextEncoder().encode(password).length;
    if (passwordBytes < 9 || passwordBytes > 1024) {
      showError("Password must contain 9 through 1,024 UTF-8 bytes.");
      return false;
    }
    if (password !== $("#onboarding-password-confirm").value) {
      showError("The passwords do not match.");
      return false;
    }
  }
  if (currentStep === finalStep) {
    const ttl = Number($("#onboarding-token-ttl").value);
    if (!Number.isSafeInteger(ttl) || ttl < 0) {
      showError("Select a valid token lifetime.");
      return false;
    }
  }
  return true;
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function showStatus(title, message, spinning = true) {
  $("#onboarding-form").classList.add("hidden");
  $(".onboarding-progress").classList.add("hidden");
  $("#onboarding-status-title").textContent = title;
  $("#onboarding-status-message").textContent = message;
  $(".onboarding-spinner").classList.toggle("hidden", !spinning);
  $("#onboarding-status").classList.remove("hidden");
}

function showPortalLink(portalUrl, text = "Open the login page") {
  const link = $("#onboarding-status-link");
  link.href = new URL(portalUrl, location.href).href;
  link.textContent = text;
  link.classList.remove("hidden");
}

function showIssuedToken(token) {
  $("#onboarding-token-secret").textContent = token;
  $("#onboarding-issued-token").classList.remove("hidden");
}

async function waitForRestart(portalUrl, authorization, retryAfterSeconds) {
  const destination = new URL(portalUrl, location.href);
  if (destination.origin !== location.origin) {
    const delay = Math.max(1000, (Number(retryAfterSeconds) + 2) * 1000);
    $("#onboarding-status-message").textContent =
      "The daemon is restarting. Keep this page open so you can copy your token.";
    await wait(delay);
    showStatus("Setup complete", "Copy your token, then open binja'd at its configured public URL.", false);
    showPortalLink(destination.href, "Open configured binja'd");
    return;
  }

  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    await wait(1000);
    try {
      const response = await fetch(`${destination.origin}${destination.pathname.replace(/\/$/, "")}/api/status`, {
        cache: "no-store",
        headers: {Authorization: authorization},
      });
      if (!response.ok) continue;
      const value = await response.json();
      if (value.result?.restart_required !== false) continue;
      showStatus("Setup complete", "Copy your token, then sign in to binja'd.", false);
      showPortalLink(destination.href);
      return;
    } catch {
      // The managed service is still restarting.
    }
  }
  showStatus(
    "Setup is saved",
    "The daemon did not return. Copy your token, check the service, then open the login page.",
    false,
  );
  showPortalLink(destination.href);
}

async function finishOnboarding() {
  if (submitting || !validCurrentStep()) return;
  submitting = true;
  showError();
  const username = $("#onboarding-username").value;
  const password = $("#onboarding-password").value;
  const next = $("#onboarding-next");
  next.disabled = true;
  next.textContent = "Creating…";
  let result;
  try {
    result = await request("/onboarding", {
      method: "POST",
      body: JSON.stringify({
        username,
        password,
        project_root: $("#onboarding-project-root").value.trim(),
        create_project_root: $("#onboarding-create-root").checked,
        public_base_url: $("#onboarding-public-url").value.trim(),
        allow_arbitrary_paths: $("#onboarding-arbitrary-paths").checked,
        allow_project_registration: $("#onboarding-project-registration").checked,
      }),
    });
    try {
      sessionStorage.setItem("binjad-onboarded-username", username);
    } catch {
      // Username prefill is optional when browser storage is unavailable.
    }
  } catch (error) {
    submitting = false;
    next.disabled = false;
    next.textContent = "Create account and token";
    showError(error.message);
    return;
  }

  const authorization = `Basic ${base64Utf8(`${username}:${password}`)}`;
  $("#onboarding-password").value = "";
  $("#onboarding-password-confirm").value = "";
  showStatus("Creating your MCP token", "Keep this page open. Your token will appear once.");

  try {
    const issued = await request("/token", {
      method: "POST",
      body: JSON.stringify({ttl_seconds: Number($("#onboarding-token-ttl").value)}),
      headers: {Authorization: authorization},
    });
    showIssuedToken(issued.token);
  } catch (error) {
    showStatus("Account created", `The first MCP token could not be created: ${error.message}`, false);
    showPortalLink(result.portal_url);
    return;
  }

  if (!result.restart_required) {
    showStatus("Setup complete", "Copy your token, then sign in to binja'd.", false);
    showPortalLink(result.portal_url);
    return;
  }

  showStatus("Restarting binja'd", "Keep this page open while the daemon applies your settings.");
  try {
    const restart = await request("/restart", {
      method: "POST",
      body: "{}",
      headers: {Authorization: authorization},
    });
    await waitForRestart(restart.portal_url, authorization, restart.retry_after_seconds);
  } catch (error) {
    showStatus("Setup is saved", `The daemon could not restart automatically: ${error.message}`, false);
    showPortalLink(result.portal_url);
  }
}

$("#onboarding-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!validCurrentStep()) return;
  if (currentStep < finalStep) showStep(currentStep + 1);
  else finishOnboarding();
});

$("#onboarding-back").addEventListener("click", () => showStep(currentStep - 1));
document.querySelectorAll("[data-profile]").forEach((button) => {
  button.addEventListener("click", () => applyAccessProfile(button.dataset.profile));
});
for (const selector of ["#onboarding-arbitrary-paths", "#onboarding-project-registration"]) {
  $(selector).addEventListener("change", updateAccessProfile);
}
$("#onboarding-copy-token").addEventListener("click", async () => {
  const button = $("#onboarding-copy-token");
  try {
    await navigator.clipboard.writeText($("#onboarding-token-secret").textContent);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Copy unavailable";
  }
});

async function initialize() {
  try {
    const state = await request("/onboarding");
    if (!state.required) {
      location.replace(portalPath);
      return;
    }
    $("#onboarding-project-root").value = state.project_root;
    $("#onboarding-create-root").checked = !state.project_root_exists;
    $("#onboarding-public-url").value = state.public_base_url;
    $("#onboarding-arbitrary-paths").checked = state.allow_arbitrary_paths;
    $("#onboarding-project-registration").checked = state.allow_project_registration;
    updateAccessProfile();
    $("#onboarding").classList.remove("hidden");
    showStep(0);
  } catch (error) {
    $("#onboarding").classList.remove("hidden");
    showStatus("Setup is unavailable", error.message, false);
  }
}

initialize();
