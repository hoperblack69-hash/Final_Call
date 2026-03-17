// utils/api.js — Shared utility functions for PhishGuard

// 1. scanURL(url, backendURL = "http://localhost:8000") → ScanResult
export async function scanURL(url, backendURL = "http://localhost:8000") {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(`${backendURL}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, js_trace: "" }),
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!res.ok) throw new Error("API error");
    return await res.json();
  } catch (e) {
    clearTimeout(timeout);
    return { verdict: "UNKNOWN", error: "Backend offline" };
  }
}

// 2. isScannableURL(url) → boolean
export function isScannableURL(url) {
  return /^https?:\/\//.test(url);
}

// 3. getDomain(url) → string
export function getDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

// 4. truncateURL(url, maxLen = 45) → string
export function truncateURL(url, maxLen = 45) {
  if (url.length <= maxLen) return url;
  return url.slice(0, maxLen - 8) + "..." + url.slice(-5);
}

// 5. getVerdictColor(verdict) → string (hex)
export function getVerdictColor(verdict) {
  switch (verdict) {
    case "SAFE": return "#00ff88";
    case "SUSPICIOUS": return "#ffb800";
    case "PHISHING":
    case "MALWARE": return "#ff3b5c";
    default: return "#666";
  }
}

// 6. timeAgo(timestamp) → string
export function timeAgo(timestamp) {
  const now = Date.now();
  const diff = Math.floor((now - timestamp) / 1000);
  if (diff < 60) return `${diff} seconds ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
  return `${Math.floor(diff / 86400)} days ago`;
}
