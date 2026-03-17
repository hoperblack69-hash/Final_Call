import httpx

API_URL = "https://checkurl.phishtank.com/checkurl/"


async def check(url: str) -> dict:
    payload = {
        "url": url,
        "format": "json",
    }
    headers = {
        "User-Agent": "Capstone-Phishing-Detector/1.0",
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(API_URL, data=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        results = data.get("results", {})
        valid_flag = str(results.get("valid", "no")).lower() == "yes"
        in_database = bool(results.get("in_database", False))
        is_phish = in_database and valid_flag

        return {
            "status": "ok",
            "in_database": in_database,
            "is_phish": is_phish,
            "verified": str(results.get("verified", "no")).lower() == "yes",
            "phish_id": results.get("phish_id"),
            "submitted_at": results.get("submitted_at"),
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "in_database": False,
            "is_phish": False,
            "verified": False,
            "error": str(exc),
        }
