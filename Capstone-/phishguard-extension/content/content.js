// content/content.js — Injects warning banners and handles scan results

function handleScanResult(result) {
  if (!result || !result.verdict) return;
  if (["PHISHING", "MALWARE"].includes(result.verdict)) {
    injectWarningBanner(result, true);
    blurPageContent();
  } else if (result.verdict === "SUSPICIOUS") {
    injectWarningBanner(result, false);
    removeBlur();
  } else {
    removeWarningBanner();
    removeBlur();
  }
}

function injectWarningBanner(result, aggressive) {
  removeWarningBanner();
  const banner = document.createElement('div');
  banner.id = 'phishguard-banner';
  banner.className = aggressive ? 'danger' : 'suspicious';
  banner.innerHTML = `
    <div class="phg-row">
      <span class="phg-title">🛡️ PhishGuard  ${aggressive ? '⚠️ ' + result.verdict + ' DETECTED' : 'Suspicious Site'} — Threat Score: ${result.threat_score || '?'} / 100</span>
      <span class="phg-actions">
        <button id="phg-back">Go Back to Safety</button>
        <button id="phg-stay">I understand the risks — Stay</button>
      </span>
    </div>
    <div class="phg-row phg-details">
      AI: ${result.ai_result || '?'} | VT: ${result.vt_result || '?'} | GSB: ${result.gsb_result || '?'}
    </div>
  `;
  document.body.prepend(banner);
  document.body.style.paddingTop = '64px';
  document.getElementById('phg-back').onclick = handleGoBack;
  document.getElementById('phg-stay').onclick = () => handleStayOnPage(result);
}

function blurPageContent() {
  document.body.classList.add('phg-blur');
}
function removeBlur() {
  document.body.classList.remove('phg-blur');
}

function removeWarningBanner() {
  const banner = document.getElementById('phishguard-banner');
  if (banner) banner.remove();
  document.body.style.paddingTop = '';
  const strip = document.getElementById('phishguard-strip');
  if (strip) strip.remove();
}

function handleGoBack() {
  if (window.history.length > 1) window.history.back();
  else window.location.href = "chrome://newtab";
}

function handleStayOnPage(result) {
  removeBlur();
  removeWarningBanner();
  // Show persistent warning strip
  const strip = document.createElement('div');
  strip.id = 'phishguard-strip';
  strip.textContent = `🛡️ PhishGuard: ${result.verdict} — Proceed with caution.`;
  document.body.prepend(strip);
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SCAN_RESULT") {
    handleScanResult(message.data);
  }
});
