import os

import httpx

CHECKPHISH_API_KEY = os.environ.get("CHECKPHISH_API_KEY", "")
API_URL = "https://developers.checkphish.ai/api/neo/scan"


async def check(url: str) -> dict:
    if not CHECKPHISH_API_KEY:
        return {
            "status": "not_configured",
            "malicious": False,
            "score": 0,
            "message": "Set CHECKPHISH_API_KEY to enable this module",
        }

    payload = {
        "urlInfo": {
            "url": url,
        }
    }
    headers = {
        "Authorization": CHECKPHISH_API_KEY,
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.post(API_URL, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        disposition = str(data.get("disposition", "")).lower()
        score = int(data.get("score", 0) or 0)

        return {
            "status": "ok",
            "scan_id": data.get("jobID") or data.get("scan_id"),
            "malicious": disposition in {"phishing", "malicious", "suspicious"} or score >= 70,
            "score": score,
            "disposition": data.get("disposition", "unknown"),
            "confidence": data.get("confidence"),
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "malicious": False,
            "score": 0,
            "error": str(exc),
        }
