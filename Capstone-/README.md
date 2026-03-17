# Multi-Channel Phishing Detection Web Application

This project implements a complete web application for multi-channel URL and web detection. The system fuses AI model predictions with VirusTotal and Google Safe Browsing results to provide comprehensive threat analysis.

## Features

- **AI-Powered Analysis**: Multi-channel neural network (Transformer + CNN + LSTM)
- **VirusTotal Integration**: Real-time malware scanning across 70+ engines
- **Google Safe Browsing**: Advanced threat detection
- **Professional UI**: Dark cybersecurity-themed interface
- **Scan History**: Persistent storage of past analyses
- **REST API**: FastAPI backend for programmatic access

## Project Structure

```
phishing-detection/
├── backend/
│   ├── app.py                    # FastAPI main application
│   ├── routes/
│   │   ├── scan.py               # Scan endpoint
│   │   └── history.py            # History management
│   ├── services/
│   │   ├── model_service.py      # PyTorch model inference
│   │   ├── virustotal_service.py # VT API integration
│   │   └── google_sb_service.py  # GSB API integration
│   ├── utils/
│   │   ├── url_utils.py          # URL processing
│   │   └── fusion.py             # Result fusion logic
│   └── requirements.txt          # Python dependencies
├── frontend/
│   ├── index.html                # Main web interface
│   ├── css/
│   │   └── style.css             # Styling
│   └── js/
│       ├── main.js               # UI logic
│       ├── results.js            # Result rendering
│       └── api.js                # API calls
├── models/
│   ├── models.py                 # Neural network architectures
│   └── multi_channel_phishing.pth # Trained model weights
├── data/
│   └── dataset.py                # Data loading utilities
├── .env                          # API keys
├── scan_history.json             # Scan history (auto-generated)
└── README.md
```

## Setup Instructions

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Set Environment Variables

Create a `.env` file in the root directory:

```
GOOGLE_API_KEY=your_google_api_key
VT_API_KEY=your_virustotal_api_key
```

### 3. Run the Application

Option A (recommended):

```bash
python run_server.py
```

Option B (alternative):

```bash
python -m uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

The application will be available at `http://localhost:8000`

### 4. Access the Web Interface

Open your browser and navigate to `http://localhost:8000/static/index.html`

## API Usage

### Scan URL
```bash
curl -X POST "http://localhost:8000/api/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com", "js_trace": "optional js code"}'
```

### Get Scan History
```bash
curl "http://localhost:8000/api/history"
```

## Architecture

The system uses a three-channel approach:

1. **URL Transformer Channel**: DistilBERT processes URL tokens for semantic analysis
2. **Character CNN Channel**: Convolutional network detects obfuscation patterns
3. **JS Trace LSTM Channel**: Bidirectional LSTM analyzes JavaScript execution traces

Results are fused with external threat intelligence from VirusTotal and Google Safe Browsing using weighted scoring.

## Security Note

This application integrates with external APIs that may have usage limits and require API keys. Ensure you comply with the terms of service for VirusTotal and Google Safe Browsing.
```bash
docker run -it phishing-detector
```

By default, the container will run the `predict.py` script.

## Next Steps
The core foundation is fully functional. Moving forward, consider gathering a massive, multi-modal dataset (e.g., URLs alongside crawled JS traces and image frames) and swapping the pandas DataFrame loader in `dataset.py` with your custom data source!
