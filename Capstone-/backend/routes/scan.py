from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime
import asyncio
import functools
import time

from backend.services.model_service import predict
from backend.services.virustotal_service import scan as vt_scan
from backend.services.google_sb_service import check as gsb_check
from backend.services.phishtank_service import check as phishtank_check
from backend.services.urlscan_service import check as urlscan_check
from backend.services.checkphish_service import check as checkphish_check
from backend.utils.fusion import combine
from backend.utils.url_utils import normalize_url
from backend.routes.history import save_scan

# LRU Cache for recent scans (max 500 entries, 10-minute expiry)
_scan_cache = {}

def _get_cached_result(url: str) -> Optional[Dict]:
    """Check if URL was scanned recently (within 10 minutes)"""
    if url in _scan_cache:
        cached_time, cached_result = _scan_cache[url]
        if time.time() - cached_time < 600:  # 10 minutes
            return cached_result
        else:
            # Expired, remove from cache
            del _scan_cache[url]
    return None

def _set_cached_result(url: str, result: Dict):
    """Cache scan result with timestamp"""
    # Maintain cache size limit
    if len(_scan_cache) >= 500:
        # Remove oldest entry (simple FIFO)
        oldest_url = min(_scan_cache.keys(), key=lambda k: _scan_cache[k][0])
        del _scan_cache[oldest_url]
    
    _scan_cache[url] = (time.time(), result)

router = APIRouter()

class ScanRequest(BaseModel):
    url: str
    js_trace: Optional[str] = ""
    include_explanation: Optional[bool] = False

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
    explanation: Optional[Dict] = None

@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest):
    try:
        # Validate and normalize URL
        normalized_url = normalize_url(request.url)
        
        # Check cache first
        cached_result = _get_cached_result(normalized_url)
        if cached_result:
            return ScanResponse(**cached_result)
        
        # Global scan timeout: 8 seconds max
        start_time = time.time()
        
        async def _scan_with_timeout():
            # Early exit check: PhishTank lookup (fast, offline)
            phishtank_result = await phishtank_check(normalized_url)
            if phishtank_result.get("is_phish", False):
                # URL is in PhishTank database - return PHISHING immediately
                ai_result = {
                    "prediction": "Phishing",
                    "probabilities": {"Benign": 0.05, "Phishing": 0.90, "Malware": 0.05},
                    "confidence": 0.90,
                    "mode": "phishtank_early_exit",
                }
                
                # Still run APIs concurrently for confidence score, but with timeout
                async def run_api_with_timeout(api_func, timeout=3):
                    try:
                        return await asyncio.wait_for(api_func(normalized_url), timeout=timeout)
                    except asyncio.TimeoutError:
                        return {"status": "timeout", "error": f"API timeout after {timeout}s"}
                    except Exception as e:
                        return {"status": "error", "error": str(e)}
                
                # Run all APIs concurrently with 3-second timeouts
                external_results = await asyncio.gather(
                    run_api_with_timeout(vt_scan),
                    run_api_with_timeout(gsb_check),
                    run_api_with_timeout(urlscan_check),
                    run_api_with_timeout(checkphish_check),
                    return_exceptions=True,
                )
                
                vt_result, gsb_result, urlscan_result, checkphish_result = external_results
                
                # Handle exceptions (same as before)
                if isinstance(vt_result, Exception):
                    vt_result = {
                        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                        "total_engines": 0, "scan_url": "", "threat_names": [], "status": "unavailable",
                        "error": str(vt_result),
                    }
                if isinstance(gsb_result, Exception):
                    gsb_result = {
                        "is_safe": True, "threat_types": [], "platform_types": [], "status": "unavailable",
                        "error": str(gsb_result),
                    }
                if isinstance(urlscan_result, Exception):
                    urlscan_result = {
                        "status": "unavailable", "found": False, "malicious": False, "score": 0,
                        "error": str(urlscan_result), "report_url": "",
                    }
                if isinstance(checkphish_result, Exception):
                    checkphish_result = {
                        "status": "unavailable", "malicious": False, "score": 0, "error": str(checkphish_result),
                    }
                
                fused = combine(ai_result, vt_result, gsb_result)
                response = ScanResponse(
                    url=normalized_url, verdict=fused["verdict"], confidence=fused["confidence"],
                    threat_score=fused["threat_score"], ai_result=ai_result, vt_result=vt_result,
                    gsb_result=gsb_result, phishtank_result=phishtank_result, urlscan_result=urlscan_result,
                    checkphish_result=checkphish_result, fusion_explanation=fused["explanation"],
                    timestamp=datetime.utcnow().isoformat(), explanation=ai_result.get("explanation")
                )
                _set_cached_result(normalized_url, response.dict())
                save_scan({**response.dict(), "scan_type": "url"})
                return response
            
            # Not in PhishTank, run full scan
            # Run AI model (may include whitelist check)
            ai_result = predict(normalized_url, request.js_trace or "", request.include_explanation)
            
            # If whitelisted, return SAFE immediately (AI model already handles this)
            if ai_result.get("is_trusted_domain", False):
                # Create minimal response for whitelisted domains
                fused = combine(ai_result, {"malicious": 0}, {"is_safe": True})
                response = ScanResponse(
                    url=normalized_url, verdict=fused["verdict"], confidence=fused["confidence"],
                    threat_score=fused["threat_score"], ai_result=ai_result,
                    vt_result={"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0},
                    gsb_result={"is_safe": True, "threat_types": [], "platform_types": []},
                    phishtank_result=phishtank_result,
                    urlscan_result={"status": "skipped", "found": False, "malicious": False, "score": 0},
                    checkphish_result={"status": "skipped", "malicious": False, "score": 0},
                    fusion_explanation=fused["explanation"], timestamp=datetime.utcnow().isoformat(),
                    explanation=ai_result.get("explanation")
                )
                _set_cached_result(normalized_url, response.dict())
                save_scan({**response.dict(), "scan_type": "url"})
                return response
            
            # Full scan: Run all external checks concurrently with timeouts
            async def run_api_with_timeout(api_func, timeout=3):
                try:
                    return await asyncio.wait_for(api_func(normalized_url), timeout=timeout)
                except asyncio.TimeoutError:
                    return {"status": "timeout", "error": f"API timeout after {timeout}s"}
                except Exception as e:
                    return {"status": "error", "error": str(e)}
            
            external_results = await asyncio.gather(
                run_api_with_timeout(vt_scan),
                run_api_with_timeout(gsb_check),
                run_api_with_timeout(urlscan_check),
                run_api_with_timeout(checkphish_check),
                return_exceptions=True,
            )
            
            vt_result, gsb_result, urlscan_result, checkphish_result = external_results
            
            # Handle exceptions (same as before)
            if isinstance(vt_result, Exception):
                vt_result = {
                    "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                    "total_engines": 0, "scan_url": "", "threat_names": [], "status": "unavailable",
                    "error": str(vt_result),
                }
            if isinstance(gsb_result, Exception):
                gsb_result = {
                    "is_safe": True, "threat_types": [], "platform_types": [], "status": "unavailable",
                    "error": str(gsb_result),
                }
            if isinstance(urlscan_result, Exception):
                urlscan_result = {
                    "status": "unavailable", "found": False, "malicious": False, "score": 0,
                    "error": str(urlscan_result), "report_url": "",
                }
            if isinstance(checkphish_result, Exception):
                checkphish_result = {
                    "status": "unavailable", "malicious": False, "score": 0, "error": str(checkphish_result),
                }
            
            # Check global timeout
            elapsed = time.time() - start_time
            if elapsed > 8:
                # Timeout exceeded, return partial result
                fused = combine(ai_result, vt_result, gsb_result)
                response = ScanResponse(
                    url=normalized_url, verdict=fused["verdict"], confidence=fused["confidence"],
                    threat_score=fused["threat_score"], ai_result=ai_result, vt_result=vt_result,
                    gsb_result=gsb_result, phishtank_result=phishtank_result, urlscan_result=urlscan_result,
                    checkphish_result=checkphish_result, fusion_explanation=fused["explanation"] + " [PARTIAL - TIMEOUT]",
                    timestamp=datetime.utcnow().isoformat(), explanation=ai_result.get("explanation")
                )
                response_dict = response.dict()
                response_dict["partial_result"] = True
                _set_cached_result(normalized_url, response_dict)
                save_scan({**response_dict, "scan_type": "url"})
                return response
            
            # Fuse results
            fused = combine(ai_result, vt_result, gsb_result)
            
            # Create response
            response = ScanResponse(
                url=normalized_url, verdict=fused["verdict"], confidence=fused["confidence"],
                threat_score=fused["threat_score"], ai_result=ai_result, vt_result=vt_result,
                gsb_result=gsb_result, phishtank_result=phishtank_result, urlscan_result=urlscan_result,
                checkphish_result=checkphish_result, fusion_explanation=fused["explanation"],
                timestamp=datetime.utcnow().isoformat(), explanation=ai_result.get("explanation")
            )
            
            _set_cached_result(normalized_url, response.dict())
            save_scan({**response.dict(), "scan_type": "url"})
            return response
        
        # Run the scan with global 8-second timeout
        try:
            return await asyncio.wait_for(_scan_with_timeout(), timeout=8.0)
        except asyncio.TimeoutError:
            # Global timeout exceeded
            ai_result = predict(normalized_url, request.js_trace or "", False)
            fused = combine(ai_result, {"malicious": 0}, {"is_safe": True})
            response = ScanResponse(
                url=normalized_url, verdict=fused["verdict"], confidence=fused["confidence"],
                threat_score=fused["threat_score"], ai_result=ai_result,
                vt_result={"status": "timeout"}, gsb_result={"status": "timeout"},
                phishtank_result={"status": "timeout"}, urlscan_result={"status": "timeout"},
                checkphish_result={"status": "timeout"},
                fusion_explanation="Global scan timeout - partial results only",
                timestamp=datetime.utcnow().isoformat()
            )
            response_dict = response.dict()
            response_dict["partial_result"] = True
            return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

