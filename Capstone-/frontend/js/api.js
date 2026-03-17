// API functions
async function scanUrl(url) {
    const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
    });

    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || 'Scan failed');
    }

    return response.json();
}

async function scanEmail(sender, subject, body) {
    const response = await fetch('/api/scan/email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ sender, subject, body }),
    });

    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || 'Email scan failed');
    }

    return response.json();
}

async function getHistory() {
    const response = await fetch('/api/history');
    return response.json();
}

async function clearHistory() {
    const response = await fetch('/api/history', {
        method: 'DELETE',
    });
    return response.json();
}