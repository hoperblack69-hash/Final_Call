import os
from urllib.parse import quote

import httpx

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
SEARCH_URL = "https://urlscan.io/api/v1/search/"


async def check(url: str) -> dict:
    query = f'page.url:"{url}"'
    params = {
        "q": query,
        "size": 1,
    }
    headers = {}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(SEARCH_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

        results = data.get("results", [])
        if not results:
            return {
                "status": "ok",
                "found": False,
                "malicious": False,
                "score": 0,
                "report_url": f"https://urlscan.io/search/#{quote(query)}",
            }

        first = results[0]
        verdicts = first.get("verdicts", {}).get("overall", {})
        score = int(verdicts.get("score", 0) or 0)

        return {
            "status": "ok",
            "found": True,
            "malicious": bool(verdicts.get("malicious", False)),
            "score": score,
            "categories": verdicts.get("categories", []),
            "report_url": first.get("result") or f"https://urlscan.io/search/#{quote(query)}",
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "found": False,
            "malicious": False,
            "score": 0,
            "error": str(exc),
            "report_url": f"https://urlscan.io/search/#{quote(query)}",
        }
