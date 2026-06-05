const SCRIPT_ID = "anti-debugger-inject";

// Anti-bot domains where injection must be skipped to avoid breaking
// challenge scripts. Layer 1 of the two-layer exclusion — Layer 2 is
// the runtime bail-out at the top of inject.js.
const ANTIBOT_EXCLUDE_MATCHES = [
  "*://challenges.cloudflare.com/*",
  "*://js.datadome.co/*",
  "*://tags.datadome.co/*",
  "*://geo.captcha-delivery.com/*",
  "*://client.px-cdn.net/*",
  "*://client.perimeterx.net/*",
  "*://*.kasada.io/*",
  "*://*.incapsula.com/*",
  "*://*.imperva.com/*",
  "*://www.google.com/recaptcha/*",
  "*://js.hcaptcha.com/*",
  "*://*.arkoselabs.com/*",
];

async function updateIndicator(isEnabled) {
  if (isEnabled) {
    chrome.action.setBadgeText({ text: "ON" });
    chrome.action.setBadgeBackgroundColor({ color: "#4D9B52" });
  } else {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#aaaaaa" });
  }
}

async function setInjectionState(isEnabled) {
  try {
    const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID] });
    const isRegistered = scripts.length > 0;

    if (isEnabled && !isRegistered) {
      await chrome.scripting.registerContentScripts([{
        id: SCRIPT_ID,
        js: ["inject.js"],
        matches: ["<all_urls>"],
        excludeMatches: ANTIBOT_EXCLUDE_MATCHES,
        runAt: "document_start",
        world: "MAIN",
      }]);
    } else if (!isEnabled && isRegistered) {
      await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] });
    }
  } catch (error) {
    console.error("Error updating script state:", error);
  }
}

// Inject or undo patches in already-open tabs when toggling.
// When turning OFF: inject a cleanup script that restores originals.
// When turning ON: inject the bypass script into all eligible tabs.
async function toggleExistingTabs(isEnabled) {
  try {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      // Skip non-http tabs (chrome://, about:, etc.)
      if (!tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) continue;
      // Skip tabs on anti-bot domains
      if (isOnExcludedDomain(tab.url)) continue;

      if (!isEnabled) {
        // Inject cleanup: set a flag that inject.js checks on future loads,
        // and attempt to restore key globals. Since we can't fully undo
        // all patches (especially the toString override), we reload the tab
        // to get a clean page. This is the most reliable approach.
        await chrome.tabs.reload(tab.id);
      } else {
        // When turning ON, inject into existing tabs immediately
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ["inject.js"],
            world: "MAIN",
            injectImmediately: true,
          });
        } catch (e) {
          // Some tabs (e.g., chrome://, devtools://) reject injection — skip silently
        }
      }
    }
  } catch (error) {
    console.error("Error toggling existing tabs:", error);
  }
}

// Check if a URL matches an anti-bot excluded domain
function isOnExcludedDomain(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    const excludedPatterns = [
      "challenges.cloudflare.com",
      "js.datadome.co",
      "tags.datadome.co",
      "geo.captcha-delivery.com",
      "client.px-cdn.net",
      "client.perimeterx.net",
      "kasada.io",
      "incapsula.com",
      "imperva.com",
    ];
    for (const pattern of excludedPatterns) {
      if (host === pattern || host.endsWith("." + pattern)) return true;
    }
  } catch (e) { /* invalid URL, skip */ }
  return false;
}

async function syncState() {
  const data = await chrome.storage.local.get(["enabled"]);
  const isEnabled = data.enabled !== false; // enabled by default
  await updateIndicator(isEnabled);
  await setInjectionState(isEnabled);
}

// Debounce toggle clicks to prevent state thrashing
var _toggleTimer = null;
var TOGGLE_DEBOUNCE_MS = 300;

chrome.action.onClicked.addListener(function () {
  if (_toggleTimer) clearTimeout(_toggleTimer);
  _toggleTimer = setTimeout(async function () {
    _toggleTimer = null;
    const data = await chrome.storage.local.get(["enabled"]);
    const isEnabled = data.enabled !== false;
    const newState = !isEnabled;

    await chrome.storage.local.set({ enabled: newState });
    await setInjectionState(newState);
    await updateIndicator(newState);
    await toggleExistingTabs(newState);
  }, TOGGLE_DEBOUNCE_MS);
});

chrome.runtime.onInstalled.addListener(syncState);
chrome.runtime.onStartup.addListener(syncState);
