from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, Dict, List
import json
import os
from datetime import datetime

from backend.routes.scan import router as scan_router
from backend.routes.email_scan import router as email_router
from backend.routes.history import router as history_router
from backend.services.model_service import load_model

app = FastAPI(title="Phishing Detection API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Include routers
app.include_router(scan_router, prefix="/api")
app.include_router(email_router, prefix="/api")
app.include_router(history_router, prefix="/api")

# Global model
model = None

@app.on_event("startup")
async def startup_event():
    global model
    model_path = "models/multi_channel_phishing.pth"
    model = load_model(model_path)
    if isinstance(model, dict) and model.get("mode") == "heuristic":
        print(f"AI model fallback active: {model.get('reason', 'unknown reason')}")
    else:
        print("Model loaded successfully")

@app.get("/health")
async def health_check():
    ai_mode = model.get("mode", "model") if isinstance(model, dict) else "model"
    return {"status": "ok", "model_loaded": model is not None, "ai_mode": ai_mode}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)