# Optional Configuration Guide
**For Enhanced Features & API Integration**

---

## Overview
This guide explains how to configure optional features in the phishing detection system. These features are NOT required for basic operation, but will enhance detection capabilities.

---

## 1. Configuration File (.env)

### Create the .env File

Create a new file: `Capstone-/.env`

```env
# VirusTotal API (Recommended - scans against 95+ antivirus engines)
VT_API_KEY=your_virustotal_api_key_here

# Google Safe Browsing API (For enterprise protection)
GOOGLE_API_KEY=your_google_safe_browsing_key_here

# CheckPhish API (Additional phishing detection)
CHECKPHISH_API_KEY=your_checkphish_api_key_here

# Server Port (Optional - default is 8080)
PORT=8080
```

### How to Get API Keys

#### VirusTotal
1. Visit: https://www.virustotal.com/gui/home/upload
2. Sign up for a free account
3. Go to: https://www.virustotal.com/gui/settings/api
4. Copy your API key
5. Add to `.env` as `VT_API_KEY=your_key`

**Benefits:**
- Scans against 95+ antivirus engines
- High accuracy threat detection
- Used in the phishing detector

#### Google Safe Browsing
1. Visit: https://developers.google.com/safe-browsing/v4/get-started
2. Create a new project in Google Cloud Console
3. Enable Safe Browsing API
4. Create an API key
5. Add to `.env` as `GOOGLE_API_KEY=your_key`

**Benefits:**
- Enterprise-grade threat detection
- Real-time database of malicious URLs
- Complements VirusTotal scans

#### CheckPhish
1. Visit: https://checkphish.ai/developers
2. Sign up and verify email
3. Generate API key from dashboard
4. Add to `.env` as `CHECKPHISH_API_KEY=your_key`

**Benefits:**
- Specialized phishing detection
- High precision on phishing URLs
- Adds another detection layer

---

## 2. Deploy AI Model (Optional but Recommended)

### Current Status
- System is using **heuristic mode** (rule-based analysis)
- AI model file (`models/multi_channel_phishing.pth`) is missing
- System works fine without it, but AI mode provides better accuracy

### Option A: Train a New Model
```bash
# From project root
python train.py
```

**Requirements:**
- Dataset of URLs labeled as benign/phishing/malware
- GPU recommended (CPU will be slow)
- ~5-30 minutes depending on dataset size

**Output:** Creates `models/multi_channel_phishing.pth`

### Option B: Use Pre-trained Model
If you have a pre-trained model file:
1. Copy `multi_channel_phishing.pth` to `models/` directory
2. Restart the server: `python run_server.py`
3. Check logs for: "Model loaded successfully"

### Verify Model is Loaded
```bash
curl http://localhost:8080/health
# Response should show: "ai_mode": "model" (not "heuristic")
```

---

## 3. Database Setup (Optional - for Persistent History)

### Current Setup
- Uses `scan_history.json` (file-based storage)
- Works fine for small deployments
- No setup needed

### For Production Database
See `backend/services/` for database integration options:
- PostgreSQL
- MongoDB
- MySQL

---

## 4. Frontend Customization

### Change Port or Domain
Edit `backend/app.py`:
```python
# Line ~20
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# To customize, modify the mount point or serve from different location
```

### Environment-Specific Configuration

Create `frontend/config.js`:
```javascript
const CONFIG = {
  API_BASE: process.env.API_BASE || 'http://localhost:8080',
  API_TIMEOUT: 30000,
  MAX_URL_LENGTH: 2048,
};
```

---

## 5. Email Scanning Setup

### Configure Email APIs

Edit `.env` to add email service credentials:
```env
# For email scanning features
SMTP_SERVER=your_smtp_server
SMTP_PORT=587
SMTP_USERNAME=your_email
SMTP_PASSWORD=your_password
```

### Test Email Scanning
```bash
curl -X POST http://localhost:8080/api/email-scan \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "suspicious@example.com",
    "subject": "Urgent action required",
    "body": "Click here to verify your account..."
  }'
```

---

## 6. Browser Extension Configuration

### Setup CheckPhish Extension
Location: `phishguard-extension/`

1. **Install in Chrome:**
   - Open: `chrome://extensions/`
   - Enable "Developer mode" (top right)
   - Click "Load unpacked"
   - Select `phishguard-extension/` folder

2. **Configure API Endpoint:**
   - Open extension options
   - Set backend URL: `http://localhost:8080`
   - Save

3. **Test:**
   - Visit any website
   - Click extension icon
   - Should show scan results

**Files:**
- `manifest.json` - Extension metadata
- `popup/popup.js` - UI logic
- `background/service_worker.js` - Background processing
- `content/content.js` - Page content analysis

---

## 7. Advanced Configuration

### Enable Detailed Logging

Edit `backend/app.py`:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### CORS Configuration

Edit `backend/app.py` line ~12:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://example.com"],  # Restrict domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Rate Limiting

Add to `backend/app.py`:
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/scan")
@limiter.limit("10/minute")  # 10 requests per minute
async def scan_url(request: ScanRequest):
    ...
```

---

## 8. Production Deployment

### Prepare for Production

1. **Set Environment Variables:**
   ```bash
   export PORT=80
   export API_BASE=https://your-domain.com
   ```

2. **Use Production Server:**
   ```bash
   gunicorn backend.app:app --workers 4 --worker-class uvicorn.workers.UvicornWorker
   ```

3. **Enable HTTPS:**
   - Use reverse proxy (Nginx, Apache)
   - Install SSL certificate
   - Redirect HTTP to HTTPS

4. **Database:**
   - Migrate from JSON to PostgreSQL
   - Set up backups

### Docker Deployment (if Dockerfile exists)

```bash
docker build -t phishing-detector .
docker run -p 8080:8080 \
  -e VT_API_KEY=your_key \
  -e GOOGLE_API_KEY=your_key \
  phishing-detector
```

---

## 9. Troubleshooting Configuration

### API Key Issues
```bash
# Test if API key is working
curl -H "X-ApiKey: YOUR_VT_API_KEY" \
  https://www.virustotal.com/api/v3/domains/google.com
```

### Port Already in Use
```bash
# Find process using port 8080
lsof -i :8080

# Kill process (if needed)
kill -9 <PID>

# Or use different port
PORT=8081 python run_server.py
```

### Model Loading Errors
```bash
# Check model file exists
ls models/multi_channel_phishing.pth

# Verify PyTorch can load it
python -c "import torch; torch.load('models/multi_channel_phishing.pth')"
```

### External Service Failures
- Services gracefully fall back if unavailable
- Check internet connection
- Verify API keys are correct
- Check API rate limits

---

## Quick Setup Checklist

- [ ] Created `.env` file in `Capstone-/`
- [ ] Added VT API key (recommended)
- [ ] Added Google API key (optional)
- [ ] Added CheckPhish API key (optional)
- [ ] Verified API keys work with test calls
- [ ] Deployed ML model (if available)
- [ ] Tested scan endpoint works
- [ ] Tested frontend loads
- [ ] Verified external APIs responding

---

## Status Commands

### Check System Status
```bash
curl http://localhost:8080/health
```

**Expected Response:**
```json
{
  "status": "ok",
  "model_loaded": true,
  "ai_mode": "model"  // or "heuristic" if model not loaded
}
```

### Test Full Scan
```bash
python -c "
import httpx
r = httpx.post('http://localhost:8080/api/scan', 
                json={'url': 'https://google.com'})
print(r.json())
"
```

---

## Support Resources

- **Documentation:** See `README.md`, `TROUBLESHOOTING.md`
- **Code Examples:** See `frontend/js/api.js`
- **Test Cases:** See `test_fusion_fix.py`
- **API Specs:** Available at `http://localhost:8080/docs` (FastAPI docs)

---

**Remember:** ✅ The system works without any of these configurations!
These are enhancements for better accuracy and features.

*Last Updated: March 20, 2026*
