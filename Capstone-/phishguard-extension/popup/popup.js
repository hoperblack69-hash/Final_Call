// popup/popup.js — PhishGuard popup logic
import { isScannableURL, truncateURL, getDomain, getVerdictColor } from '../utils/api.js';

let currentURL = "";

document.addEventListener('DOMContentLoaded', initPopup);

document.getElementById('rescan').onclick = handleRescan;
document.getElementById('trust').onclick = handleTrustSite;
document.getElementById('report').onclick = handleFullReport;

defaultState();

function defaultState() {
  document.getElementById('verdict-container').innerHTML = '';
  document.getElementById('threat-bar-inner').style.width = '0';
  document.getElementById('ai-section').innerHTML = '';
  document.getElementById('vt-section').innerHTML = '';
  document.getElementById('gsb-section').innerHTML = '';
  document.getElementById('error').style.display = 'none';
  document.getElementById('unsupported').style.display = 'none';
}

function initPopup() {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs[0];
    currentURL = tab.url || '';
    document.getElementById('url').textContent = truncateURL(currentURL);
    if (!isScannableURL(currentURL)) {
      showUnsupportedPage();
      return;
    }
    showLoadingState();
    chrome.runtime.sendMessage({ type: 'GET_CURRENT_SCAN' }, result => {
      if (result) renderResult(result);
      else handleRescan();
    });
  });
}

function renderResult(result) {
  defaultState();
  if (!result || result.error) {
    showBackendOffline();
    return;
  }
  renderVerdictBadge(result.verdict);
  renderThreatBar(result.threat_score);
  renderAISection(result.ai_result);
  renderVTSection(result.vt_result);
  renderGSBSection(result.gsb_result);
}

function renderVerdictBadge(verdict) {
  const badge = document.createElement('div');
  badge.className = 'verdict-badge';
  if (verdict === 'SAFE') badge.classList.add('safe');
  else if (verdict === 'SUSPICIOUS') badge.classList.add('suspicious');
  else if (['PHISHING', 'MALWARE'].includes(verdict)) badge.classList.add('danger');
  badge.textContent = verdict === 'SAFE' ? '██ SAFE ██' :
    verdict === 'SUSPICIOUS' ? '?? SUSPICIOUS ??' :
    verdict === 'PHISHING' ? '!! PHISHING !!' :
    verdict === 'MALWARE' ? '☠ MALWARE ☠' :
    'UNKNOWN';
  document.getElementById('verdict-container').appendChild(badge);
}

function renderThreatBar(score) {
  const bar = document.getElementById('threat-bar-inner');
  let color = 'var(--safe)';
  if (score > 75) color = 'var(--danger)';
  else if (score > 50) color = 'orange';
  else if (score > 25) color = 'var(--suspicious)';
  bar.style.background = color;
  bar.style.width = score + '%';
}

function renderAISection(ai) {
  document.getElementById('ai-section').innerHTML = `<div class='section-title'>🤖 AI Model</div><div class='section-content'>${ai || 'N/A'}</div>`;
}
function renderVTSection(vt) {
  document.getElementById('vt-section').innerHTML = `<div class='section-title'>🦠 VirusTotal</div><div class='section-content'>${vt || 'N/A'}</div>`;
}
function renderGSBSection(gsb) {
  document.getElementById('gsb-section').innerHTML = `<div class='section-title'>🔍 Google Safe Browsing</div><div class='section-content'>${gsb || 'N/A'}</div>`;
}

function handleRescan() {
  showLoadingState();
  chrome.runtime.sendMessage({ type: 'RESCAN_URL' }, result => {
    renderResult(result);
  });
}

function handleTrustSite() {
  const domain = getDomain(currentURL);
  chrome.runtime.sendMessage({ type: 'ADD_WHITELIST', domain }, () => {
    alert(`✓ ${domain} added to trusted sites`);
  });
}

function handleFullReport() {
  chrome.tabs.create({ url: `http://localhost:5500/frontend/index.html?url=${encodeURIComponent(currentURL)}` });
}

function showLoadingState() {
  defaultState();
  document.getElementById('loading').style.display = '';
}
function showUnsupportedPage() {
  defaultState();
  document.getElementById('unsupported').style.display = '';
  document.getElementById('unsupported').textContent = "PhishGuard doesn't scan browser pages";
}
function showBackendOffline() {
  defaultState();
  document.getElementById('error').style.display = '';
  document.getElementById('error').textContent = '⚠ Backend offline. Start server to scan.';
}
