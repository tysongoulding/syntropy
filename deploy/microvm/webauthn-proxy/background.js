const NATIVE_HOST = "io.syntropy.agent.webauthn_proxy";
const inFlight = new Set();

function log(...args) {
  console.log("[syntropy-webauthn-proxy]", ...args);
}

chrome.webAuthenticationProxy.onRemoteSessionStateChange.addListener(() => {
  void attach();
});

chrome.runtime.onStartup.addListener(() => {
  void attach();
});

chrome.runtime.onInstalled.addListener(() => {
  void attach();
});

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((request) => {
  // Laptop security key is a roaming authenticator, never a platform one
  chrome.webAuthenticationProxy.completeIsUvpaaRequest({
    requestId: request.requestId,
    isUvpaa: false,
  });
});

chrome.webAuthenticationProxy.onCreateRequest.addListener((request) => {
  void handleRequest("create", request);
});

chrome.webAuthenticationProxy.onGetRequest.addListener((request) => {
  void handleRequest("get", request);
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
  if (inFlight.delete(requestId)) {
    log(`request ${requestId} canceled by caller`);
  }
});

async function attach() {
  try {
    const refusal = await chrome.webAuthenticationProxy.attach();
    if (refusal) {
      log("attach refused:", refusal);
      return;
    }
    log("attached - WebAuthn routing to client via Syntropy broker");
  } catch (error) {
    log("attach failed:", error?.message ?? error);
  }
}

async function resolveCaller(options, rpId) {
  const override = options?.extensions?.remoteDesktopClientOverride;
  if (typeof override?.origin === "string" && override.origin !== "") {
    return { origin: override.origin };
  }
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab?.url) {
      const url = new URL(tab.url);
      if (url.hostname === rpId || url.hostname.endsWith(`.${rpId}`)) {
        return { origin: url.origin };
      }
    }
  } catch {}
  return { origin: `https://${rpId}` };
}

async function handleRequest(kind, request) {
  const { requestId, requestDetailsJson } = request;
  inFlight.add(requestId);

  let options;
  try {
    options = JSON.parse(requestDetailsJson);
  } catch (error) {
    fail(kind, requestId, "DataError", `unparseable request options: ${error}`);
    inFlight.delete(requestId);
    return;
  }

  const declaredRpId = kind === "create" ? options?.rp?.id : options?.rpId;
  const rpId = (declaredRpId || "").toLowerCase();
  const caller = await resolveCaller(options, rpId);
  const origin = caller.origin;

  try {
    const result = await chrome.runtime.sendNativeMessage(NATIVE_HOST, {
      kind,
      origin,
      optionsJson: requestDetailsJson,
    });
    if (result?.ok) {
      const details = { requestId, responseJson: result.credentialJson };
      if (kind === "create") {
        await chrome.webAuthenticationProxy.completeCreateRequest(details);
      } else {
        await chrome.webAuthenticationProxy.completeGetRequest(details);
      }
      log(`${kind} request ${requestId} completed`);
    } else {
      fail(kind, requestId, "NotAllowedError", result?.error?.message ?? "Authentication failed");
    }
  } catch (error) {
    fail(kind, requestId, "NotAllowedError", `Bridge error: ${error?.message ?? error}`);
  } finally {
    inFlight.delete(requestId);
  }
}

function fail(kind, requestId, name, message) {
  if (!inFlight.has(requestId)) return;
  const details = { requestId, error: { name, message } };
  const action = kind === "create"
    ? chrome.webAuthenticationProxy.completeCreateRequest(details)
    : chrome.webAuthenticationProxy.completeGetRequest(details);
  action.catch(err => log(`fail rejected: ${err}`));
}

void attach();
