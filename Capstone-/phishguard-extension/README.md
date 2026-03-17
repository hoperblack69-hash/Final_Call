# PhishGuard Chrome Extension

PhishGuard is a real-time browser companion for your Multi-Channel Phishing Detection System.

## Features
- Monitors every tab and scans URLs in real time
- Uses your backend API (http://localhost:8000)
- Shows verdicts in a popup and toolbar badge
- Injects warning banners into dangerous pages
- Blocks navigation to confirmed phishing/malware (with override)
- Customizable settings and trusted sites (whitelist)
- Dark, neon-themed UI

## Installation

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `phishguard-extension/` folder
5. Pin the extension to your toolbar
6. Make sure your backend is running: `uvicorn backend.app:app --reload --port 8000`
7. Visit any website — PhishGuard auto-scans and shows verdicts

## Folder Structure
```
phishguard-extension/
├── manifest.json
├── background/
│   └── service_worker.js
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── content/
│   ├── content.js
│   └── content.css
├── options/
│   ├── options.html
│   ├── options.css
│   └── options.js
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── utils/
    └── api.js
```

## Design
- Colors: #0a0e1a (navy), #00ff88 (neon green), #ff3b5c (red)
- Popup: 380px wide, max 520px tall, no scrollbars
- All transitions: 0.2s ease
- Verdict badge pulses for PHISHING/MALWARE

## Credits
*PhishGuard Chrome Extension — Real-Time Companion for Multi-Channel Phishing Detector*
*Student: Sehajbir | B.Tech CSE | LPU | Capstone Project V3*
