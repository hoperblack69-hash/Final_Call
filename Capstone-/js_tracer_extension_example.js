// Browser Extension Manifest (manifest.json)
{
  "manifest_version": 3,
  "name": "Phishing Detector JS Tracer",
  "version": "1.0",
  "description": "Collects JavaScript execution traces for phishing analysis",
  "permissions": ["activeTab", "scripting"],
  "action": {
    "default_popup": "popup.html"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["tracer.js"]
  }]
}

// Content Script (tracer.js)
let jsTrace = [];

const originalLog = console.log;
console.log = function(...args) {
  jsTrace.push('LOG: ' + args.join(' '));
  originalLog.apply(console, args);
};

// Hook into function calls
const originalCall = Function.prototype.call;
Function.prototype.call = function(...args) {
  if (this.name && this.name.length > 0) {
    jsTrace.push('CALL: ' + this.name);
  }
  return originalCall.apply(this, args);
};

// Collect on page load
window.addEventListener('load', () => {
  setTimeout(() => {
    // Send trace to extension
    chrome.runtime.sendMessage({
      action: 'jsTrace',
      trace: jsTrace.slice(0, 100).join('\\n') // Limit size
    });
  }, 2000);
});

// Extension Background (background.js)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'jsTrace') {
    // Store or send to phishing detector API
    console.log('JS Trace collected:', request.trace);
  }
});

// Popup (popup.html + popup.js) - to paste into detector
document.getElementById('pasteTrace').addEventListener('click', () => {
  navigator.clipboard.readText().then(text => {
    // Send to phishing detector page
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      chrome.tabs.sendMessage(tabs[0].id, {action: 'insertTrace', trace: text});
    });
  });
});