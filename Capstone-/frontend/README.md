# Frontend Development Server

This directory contains the static frontend files for the phishing detection application.

## Quick Start

### Option 1: Python Script (Recommended)
```bash
# From frontend directory
python start_frontend.py
```

### Option 2: Batch File (Windows)
```bash
# From frontend directory
start_frontend.bat
```

### Option 3: Manual Python Server
```bash
# From frontend directory
python -m http.server 3000
```

## Features

- **Auto-open browser**: Automatically opens `http://localhost:3000` in your default browser
- **User-friendly messages**: Clear startup messages with server info and tips
- **Custom port**: Specify different port: `python start_frontend.py 8080`
- **No auto-open**: Use `python start_frontend.py 3000 no-open` to disable browser auto-open

## Files Structure

```
frontend/
├── index.html          # Main application page
├── css/
│   └── style.css       # Application styles
├── js/
│   ├── main.js         # Main application logic
│   ├── api.js          # API communication
│   ├── results.js      # Results display
│   └── email_results.js # Email results handling
├── start_frontend.py   # Development server launcher (Python)
└── start_frontend.bat  # Development server launcher (Windows)
```

## Usage Examples

```bash
# Default (port 3000, auto-open browser)
python start_frontend.py

# Custom port
python start_frontend.py 8080

# No auto-open browser
python start_frontend.py 3000 no-open

# Windows batch file
start_frontend.bat 3000
```

## Server Output

When started, you'll see:
```
============================================================
🚀 FRONTEND DEVELOPMENT SERVER STARTED
============================================================
🌐 Server URL: http://localhost:3000
📂 Serving directory: frontend
📝 Files available:
   • index.html (main page)
   • css/style.css (styles)
   • js/ (JavaScript files)
============================================================
💡 Tips:
   • Press Ctrl+C to stop the server
   • Refresh browser to see changes
   • Edit files and save to see live updates
============================================================
🌍 Opening browser automatically...
✅ Browser opened! If not, click the link above.

🔄 Server is running... (Ctrl+C to stop)
```

## Notes

- The frontend communicates with the backend API at `http://localhost:8080`
- Make sure the backend server is running before using the frontend
- For production, the backend serves these static files automatically