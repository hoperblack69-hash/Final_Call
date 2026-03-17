from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime
import asyncio

from backend.services.model_service import predict
from backend.services.virustotal_service import scan as vt_scan
from backend.services.google_sb_service import check as gsb_check
from backend.services.phishtank_service import check as phishtank_check
from backend.services.urlscan_service import check as urlscan_check
from backend.services.checkphish_service import check as checkphish_check
from backend.utils.fusion import combine
from backend.utils.url_utils import normalize_url
from backend.routes.history import save_scan

router = APIRouter()

class ScanRequest(BaseModel):
    url: str
    js_trace: Optional[str] = ""

class ScanResponse(BaseModel):
    url: str
    verdict: str
    confidence: float
    threat_score: int
    ai_result: Dict
    vt_result: Dict
    gsb_result: Dict
    phishtank_result: Dict
    urlscan_result: Dict
    checkphish_result: Dict
    fusion_explanation: str
    timestamp: str

@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest):
    try:
        # Validate and normalize URL
        normalized_url = normalize_url(request.url)
        
        # Run AI model
        ai_result = predict(normalized_url, request.js_trace or "")
        
        # Run external checks concurrently to reduce overall latency
        external_results = await asyncio.gather(
            vt_scan(normalized_url),
            gsb_check(normalized_url),
            phishtank_check(normalized_url),
            urlscan_check(normalized_url),
            checkphish_check(normalized_url),
            return_exceptions=True,
        )

        vt_result, gsb_result, phishtank_result, urlscan_result, checkphish_result = external_results

        if isinstance(vt_result, Exception):
            vt_result = {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_engines": 0,
                "scan_url": "",
                "threat_names": [],
                "status": "unavailable",
                "error": str(vt_result),
            }
        if isinstance(gsb_result, Exception):
            gsb_result = {
                "is_safe": True,
                "threat_types": [],
                "platform_types": [],
                "status": "unavailable",
                "error": str(gsb_result),
            }
        if isinstance(phishtank_result, Exception):
            phishtank_result = {
                "status": "unavailable",
                "in_database": False,
                "is_phish": False,
                "verified": False,
                "error": str(phishtank_result),
            }
        if isinstance(urlscan_result, Exception):
            urlscan_result = {
                "status": "unavailable",
                "found": False,
                "malicious": False,
                "score": 0,
                "error": str(urlscan_result),
                "report_url": "",
            }
        if isinstance(checkphish_result, Exception):
            checkphish_result = {
                "status": "unavailable",
                "malicious": False,
                "score": 0,
                "error": str(checkphish_result),
            }
        
        # Fuse results
        fused = combine(ai_result, vt_result, gsb_result)
        
        # Create response
        response = ScanResponse(
            url=normalized_url,
            verdict=fused["verdict"],
            confidence=fused["confidence"],
            threat_score=fused["threat_score"],
            ai_result=ai_result,
            vt_result=vt_result,
            gsb_result=gsb_result,
            phishtank_result=phishtank_result,
            urlscan_result=urlscan_result,
            checkphish_result=checkphish_result,
            fusion_explanation=fused["explanation"],
            timestamp=datetime.utcnow().isoformat()
        )
        
        # Save to history
        save_scan({**response.dict(), "scan_type": "url"})
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

