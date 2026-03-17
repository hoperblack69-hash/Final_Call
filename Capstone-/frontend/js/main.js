// Main app logic
document.addEventListener('DOMContentLoaded', initApp);

function initApp() {
    const urlForm = document.getElementById('scanForm');
    const emailForm = document.getElementById('emailForm');
    const clearBtn = document.getElementById('clearHistory');

    document.getElementById('tabUrl').addEventListener('click', () => switchMode('url'));
    document.getElementById('tabEmail').addEventListener('click', () => switchMode('email'));

    urlForm.addEventListener('submit', handleURLScan);
    emailForm.addEventListener('submit', handleEmailScan);
    clearBtn.addEventListener('click', handleClearHistory);

    loadHistory();
}

async function handleURLScan(e) {
    e.preventDefault();

    const url = document.getElementById('url').value;

    if (!validateURL(url)) {
        return;
    }

    showLoadingState('Scanning URL...');

    try {
        const result = await scanUrl(url);
        renderResults(result);
        loadHistory();
    } catch (error) {
        showError('Scan failed: ' + error.message);
    } finally {
        hideLoadingState();
    }
}

async function handleEmailScan(e) {
    e.preventDefault();

    const sender = document.getElementById('sender').value;
    const subject = document.getElementById('subject').value;
    const body = document.getElementById('body').value;

    if (!sender || !subject || !body) {
        showError('Please fill in sender, subject, and body fields.');
        return;
    }

    showLoadingState('Analyzing email...');

    try {
        const result = await scanEmail(sender, subject, body);
        renderEmailResults(result);
        loadHistory();
    } catch (error) {
        showError('Email scan failed: ' + error.message);
    } finally {
        hideLoadingState();
    }
}

function validateURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        showError('Please enter a valid URL');
        return false;
    }
}

function showLoadingState(message = 'SCANNING...') {
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('loadingText').textContent = message;
    document.querySelectorAll('button').forEach(btn => (btn.disabled = true));
}

function hideLoadingState() {
    document.getElementById('loading').classList.add('hidden');
    document.querySelectorAll('button').forEach(btn => (btn.disabled = false));
}

function showError(message) {
    alert(message);
}

async function handleClearHistory() {
    if (confirm('Clear all scan history?')) {
        await clearHistory();
        loadHistory();
    }
}

async function loadHistory() {
    try {
        const history = await getHistory();
        renderScanHistory(history);
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

function renderScanHistory(scans) {
    const container = document.getElementById('historyList');
    container.innerHTML = '';

    scans.slice(-10).reverse().forEach(scan => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.onclick = () => {
            if (scan.scan_type === 'email') {
                renderEmailResults(scan);
            } else {
                renderResults(scan);
            }
        };

        const title = scan.scan_type === 'email' ? scan.sender : scan.url;

        item.innerHTML = `
            <div class="history-url">${title}</div>
            <div class="history-verdict ${scan.verdict.toLowerCase()}">${scan.verdict}</div>
            <div class="history-time">${formatTimestamp(scan.timestamp)}</div>
        `;

        container.appendChild(item);
    });
}

function formatTimestamp(iso) {
    const date = new Date(iso);
    const now = new Date();
    const diff = now - date;
    
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

function switchMode(mode) {
    // Remove active class from all tabs
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    
    // Hide all panels
    document.querySelectorAll('.mode-panel').forEach(panel => panel.classList.add('hidden'));
    
    if (mode === 'url') {
        document.getElementById('tabUrl').classList.add('active');
        document.getElementById('urlPanel').classList.remove('hidden');
    } else if (mode === 'email') {
        document.getElementById('tabEmail').classList.add('active');
        document.getElementById('emailPanel').classList.remove('hidden');
    }
}