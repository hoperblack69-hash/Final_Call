// options/options.js — PhishGuard settings logic

document.addEventListener('DOMContentLoaded', loadSettings);
document.getElementById('save-btn').onclick = saveSettings;

function loadSettings() {
  chrome.storage.sync.get({
    auto_scan: true,
    show_notifications: true,
    block_malware: true,
    backend_url: "http://localhost:8000",
    whitelist: []
  }, data => {
    document.getElementById('auto_scan').checked = data.auto_scan;
    document.getElementById('show_notifications').checked = data.show_notifications;
    document.getElementById('block_malware').checked = data.block_malware;
    document.getElementById('backend_url').value = data.backend_url;
    renderWhitelist(data.whitelist);
  });
}

function saveSettings() {
  const auto_scan = document.getElementById('auto_scan').checked;
  const show_notifications = document.getElementById('show_notifications').checked;
  const block_malware = document.getElementById('block_malware').checked;
  const backend_url = document.getElementById('backend_url').value;
  const whitelist = Array.from(document.querySelectorAll('#whitelist-list li')).map(li => li.dataset.domain);
  chrome.storage.sync.set({ auto_scan, show_notifications, block_malware, backend_url, whitelist }, () => {
    showToast();
  });
}

function renderWhitelist(domains) {
  const ul = document.getElementById('whitelist-list');
  ul.innerHTML = '';
  domains.forEach(domain => {
    const li = document.createElement('li');
    li.dataset.domain = domain;
    li.innerHTML = `${domain} <button>Remove</button>`;
    li.querySelector('button').onclick = () => removeFromWhitelist(domain);
    ul.appendChild(li);
  });
}

function removeFromWhitelist(domain) {
  chrome.storage.sync.get({ whitelist: [] }, data => {
    const whitelist = data.whitelist.filter(d => d !== domain);
    chrome.storage.sync.set({ whitelist }, loadSettings);
  });
}

function showToast() {
  const toast = document.getElementById('toast');
  toast.style.display = '';
  setTimeout(() => { toast.style.display = 'none'; }, 1800);
}
