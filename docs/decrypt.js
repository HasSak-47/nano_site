const form = document.querySelector("#unlock-form");
const passwordInput = document.querySelector("#password");
const submitButton = document.querySelector("#submit-button");
const statusElement = document.querySelector("#status");

const payloadUrl = new URL("./site.enc.json", window.location.href);
const SESSION_KEY = "nanosite-session";
const SESSION_DURATION_MS = 30 * 60 * 1000;
const APP_ROOT = "/nano_site";

let logoutTimerId = null;

const ROUTER_HELPER = `
<script>
(() => {
  const APP_ROOT = ${JSON.stringify(APP_ROOT)};
  const stripRoot = (pathname) => {
    if (pathname === APP_ROOT) return "/";
    if (pathname.startsWith(APP_ROOT + "/")) {
      return pathname.slice(APP_ROOT.length) || "/";
    }
    return pathname;
  };

  const prefixRoot = (pathname) => {
    if (!pathname || pathname === "/") return APP_ROOT;
    if (!pathname.startsWith("/")) return pathname;
    if (pathname === APP_ROOT || pathname.startsWith(APP_ROOT + "/")) {
      return pathname;
    }
    return APP_ROOT + pathname;
  };

  window.__NANOSITE_STRIP_ROOT__ = stripRoot;
  window.__NANOSITE_APP_ROOT__ = APP_ROOT;

  const originalPushState = window.history.pushState.bind(window.history);
  window.history.pushState = (state, title, url) => {
    if (typeof url === "string") {
      return originalPushState(state, title, prefixRoot(url));
    }
    return originalPushState(state, title, url);
  };

  const isDocumentRoute = (href) => {
    try {
      const url = new URL(href, window.location.origin);
      const lastSegment = url.pathname.split("/").pop() || "";
      return url.origin === window.location.origin && !lastSegment.includes(".");
    } catch {
      return false;
    }
  };

  document.addEventListener("click", (event) => {
    const link = event.target.closest("a[href]");
    if (!link) return;
    const href = link.getAttribute("href");
    if (!href || href.startsWith("#") || link.target === "_blank") return;
    if (!isDocumentRoute(href)) return;

    event.preventDefault();
    const url = new URL(href, window.location.origin);
    const pathname = prefixRoot(stripRoot(url.pathname));
    window.history.pushState({}, "", pathname + url.search + url.hash);
    window.dispatchEvent(new PopStateEvent("popstate"));
  });
})();
</script>
`;

function setStatus(message, variant = "default") {
  statusElement.textContent = message;
  statusElement.dataset.variant = variant;
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function decodeUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

function isRootPath(pathname = window.location.pathname) {
  return pathname === APP_ROOT || pathname === `${APP_ROOT}/`;
}

function redirectToRoot() {
  window.location.replace(APP_ROOT);
}

function clearSession() {
  window.localStorage.removeItem(SESSION_KEY);
}

function readSession() {
  const raw = window.localStorage.getItem(SESSION_KEY);
  if (!raw) {
    return null;
  }

  try {
    const session = JSON.parse(raw);
    if (!session.password || !session.expiresAt) {
      clearSession();
      return null;
    }
    if (Date.now() >= session.expiresAt) {
      clearSession();
      return null;
    }
    return session;
  } catch {
    clearSession();
    return null;
  }
}

function writeSession(password) {
  const session = {
    password,
    expiresAt: Date.now() + SESSION_DURATION_MS,
  };
  window.localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  return session;
}

function refreshSession(password) {
  return writeSession(password);
}

function scheduleLogout(expiresAt) {
  if (logoutTimerId !== null) {
    window.clearTimeout(logoutTimerId);
  }

  const delay = Math.max(0, expiresAt - Date.now());
  logoutTimerId = window.setTimeout(() => {
    clearSession();
    redirectToRoot();
  }, delay);
}

async function deriveKey(password, salt, iterations) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function decryptFile(key, encryptedFile) {
  const response = await fetch(new URL(encryptedFile.encrypted_path, window.location.href));
  if (!response.ok) {
    throw new Error(`Encrypted file not found: ${encryptedFile.encrypted_path}`);
  }

  const ciphertext = new Uint8Array(await response.arrayBuffer());
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(encryptedFile.iv) },
    key,
    ciphertext,
  );

  return new Uint8Array(decrypted);
}

async function decryptPayload(password) {
  const response = await fetch(payloadUrl);
  if (!response.ok) {
    throw new Error("Encrypted payload not found.");
  }

  const payload = await response.json();
  const key = await deriveKey(
    password,
    base64ToBytes(payload.salt),
    payload.iterations,
  );
  const manifestFiles = payload.files || {};
  const files = {};

  for (const [relativePath, encryptedFile] of Object.entries(manifestFiles)) {
    const bytes = await decryptFile(key, encryptedFile);
    files[relativePath] = {
      mime: encryptedFile.mime || "application/octet-stream",
      bytes,
    };
  }

  return { files };
}

function escapeForRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function createPathAliases(relativePath) {
  const aliases = new Set([`/${relativePath}`, relativePath]);

  if (relativePath.startsWith("public/")) {
    const publiclessPath = relativePath.slice("public/".length);
    aliases.add(`/${publiclessPath}`);
    aliases.add(publiclessPath);
  }

  return aliases;
}

function rewriteTextAsset(source, replacements) {
  let result = source;

  for (const [fromPath, toPath] of replacements.entries()) {
    result = result.replace(new RegExp(escapeForRegExp(fromPath), "g"), toPath);
  }

  return result;
}

function rewriteAppScript(source) {
  return source.replaceAll(
    "window.location.pathname",
    "window.__NANOSITE_STRIP_ROOT__(window.location.pathname)",
  );
}

function isTextLikeMimeType(mimeType) {
  if (mimeType === "image/svg+xml") {
    return false;
  }

  return (
    mimeType.startsWith("text/") ||
    mimeType.includes("javascript") ||
    mimeType.includes("json") ||
    mimeType.includes("xml")
  );
}

function createBlobUrlMap(files) {
  const pathToBlobUrl = new Map();
  const fileAliases = new Map();

  for (const relativePath of Object.keys(files)) {
    fileAliases.set(relativePath, createPathAliases(relativePath));
  }

  for (const [relativePath, file] of Object.entries(files)) {
    const mimeType = file.mime || "application/octet-stream";
    if (isTextLikeMimeType(mimeType)) {
      continue;
    }

    const blob = new Blob([file.bytes], { type: mimeType });
    pathToBlobUrl.set(relativePath, URL.createObjectURL(blob));
  }

  for (const [relativePath, file] of Object.entries(files)) {
    const mimeType = file.mime || "application/octet-stream";
    if (!isTextLikeMimeType(mimeType)) {
      continue;
    }

    const replacements = new Map();
    for (const [candidatePath, aliases] of fileAliases.entries()) {
      if (candidatePath === relativePath) {
        continue;
      }
      const targetUrl = pathToBlobUrl.get(candidatePath);
      if (!targetUrl) {
        continue;
      }
      for (const alias of aliases) {
        replacements.set(alias, targetUrl);
      }
    }

    const blobSource = rewriteTextAsset(
      mimeType.includes("javascript")
        ? rewriteAppScript(decodeUtf8(file.bytes))
        : decodeUtf8(file.bytes),
      replacements,
    );
    const blob = new Blob([blobSource], { type: mimeType });
    pathToBlobUrl.set(relativePath, URL.createObjectURL(blob));
  }

  const urlMap = new Map();
  for (const [relativePath, aliases] of fileAliases.entries()) {
    const blobUrl = pathToBlobUrl.get(relativePath);
    for (const alias of aliases) {
      urlMap.set(alias, blobUrl);
    }
  }

  if (!urlMap.has("/favicon.svg") && urlMap.has("/generic/favicon.svg")) {
    urlMap.set("/favicon.svg", urlMap.get("/generic/favicon.svg"));
  }

  return urlMap;
}

function rewriteHtml(sourceHtml, urlMap) {
  const doc = new DOMParser().parseFromString(sourceHtml, "text/html");

  for (const element of doc.querySelectorAll("[src], [href]")) {
    for (const attribute of ["src", "href"]) {
      const currentValue = element.getAttribute(attribute);
      if (!currentValue || !urlMap.has(currentValue)) {
        continue;
      }
      element.setAttribute(attribute, urlMap.get(currentValue));
    }
  }

  if (doc.body) {
    doc.body.insertAdjacentHTML("beforeend", ROUTER_HELPER);
  }

  return "<!doctype html>\n" + doc.documentElement.outerHTML;
}

function renderUnlockedSite(bundle) {
  const files = bundle.files || {};
  const indexFile = files["index.html"];

  if (!indexFile) {
    throw new Error("Encrypted bundle does not include index.html.");
  }

  const urlMap = createBlobUrlMap(files);
  const html = rewriteHtml(decodeUtf8(indexFile.bytes), urlMap);

  window.__NANOSITE_BLOB_URLS__ = Array.from(urlMap.values());
  document.open();
  document.write(html);
  document.close();
}

async function unlockSite(password) {
  const session = refreshSession(password);
  scheduleLogout(session.expiresAt);
  const bundle = await decryptPayload(password);
  renderUnlockedSite(bundle);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const password = passwordInput.value;
  if (!password) {
    setStatus("Enter a password first.", "error");
    return;
  }

  submitButton.disabled = true;
  setStatus("Decrypting site...");

  try {
    await unlockSite(password);
  } catch (error) {
    console.error(error);
    clearSession();
    setStatus("Wrong password or unreadable payload.", "error");
    submitButton.disabled = false;
  }
});

const session = readSession();
if (session) {
  passwordInput.value = session.password;
  submitButton.disabled = true;
  setStatus("Decrypting site...");
  unlockSite(session.password).catch((error) => {
    console.error(error);
    clearSession();
    submitButton.disabled = false;
    setStatus("Wrong password or unreadable payload.", "error");
    if (!isRootPath()) {
      redirectToRoot();
    }
  });
} else if (!isRootPath()) {
  redirectToRoot();
}
