// background/service_worker.js — PhishGuard main logic
importScripts('../utils/api.js');

const SCAN_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url || !isScannableURL(tab.url)) return;
  const settings = await loadSettings();
  if (settings.whitelist && settings.whitelist.includes(getDomain(tab.url))) return;
  const cached = await getCachedResult(tab.url);
  if (cached) {
    updateBadge(tabId, cached.verdict);
    sendMessageToTab(tabId, cached);
    return;
  }
  const result = await scanURL(tab.url, settings.backend_url);
  await cacheResult(tab.url, result);
  updateBadge(tabId, result.verdict);
  notifyIfDangerous(tab, result.verdict, result.threat_score);
  sendMessageToTab(tabId, result);
});

async function scanURL(url, backendURL) {
  return await self.scanURL(url, backendURL);
}

function updateBadge(tabId, verdict) {
  let text = "~", color = "#666";
  if (verdict === "SAFE") { text = "✓"; color = "#00ff88"; }
  else if (verdict === "SUSPICIOUS") { text = "?"; color = "#ffb800"; }
  else if (verdict === "PHISHING") { text = "!"; color = "#ff3b5c"; }
  else if (verdict === "MALWARE") { text = "☠"; color = "#ff3b5c"; }
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function notifyIfDangerous(tab, verdict, score) {
  if (["PHISHING", "MALWARE"].includes(verdict)) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "⚠️ PhishGuard Alert",
      message: `${verdict} site detected: ${tab.url}`,
      priority: 2
    });
  }
}

function sendMessageToTab(tabId, result) {
  chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", data: result });
}

async function getCachedResult(url) {
  return new Promise(resolve => {
    chrome.storage.local.get([url], data => {
      const entry = data[url];
      if (entry && Date.now() - entry.timestamp < SCAN_CACHE_TTL) resolve(entry.result);
      else resolve(null);
    });
  });
}

async function cacheResult(url, result) {
  chrome.storage.local.set({ [url]: { result, timestamp: Date.now() } });
}

async function loadSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get({
      auto_scan: true,
      show_notifications: true,
      block_malware: true,
      backend_url: "http://localhost:8000",
      whitelist: []
    }, resolve);
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_CURRENT_SCAN") {
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
      const url = tabs[0]?.url;
      const cached = url ? await getCachedResult(url) : null;
      sendResponse(cached);
    });
    return true;
  }
  if (msg.type === "RESCAN_URL") {
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
      const url = tabs[0]?.url;
      const settings = await loadSettings();
      const result = await scanURL(url, settings.backend_url);
      await cacheResult(url, result);
      sendResponse(result);
    });
    return true;
  }
  if (msg.type === "ADD_WHITELIST") {
    chrome.storage.sync.get({ whitelist: [] }, data => {
      const whitelist = data.whitelist;
      if (!whitelist.includes(msg.domain)) whitelist.push(msg.domain);
      chrome.storage.sync.set({ whitelist });
      sendResponse({ success: true });
    });
    return true;
  }
});
