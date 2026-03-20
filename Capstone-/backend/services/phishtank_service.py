import csv
from pathlib import Path
from typing import Dict, Any, List

# Project root for offline CSV
ROOT = Path(__file__).resolve().parents[3]  # Go up to project root
OFFLINE_CSV_PATH = ROOT / "data" / "phishtank_offline.csv"

# Cache for loaded phishing URLs
_phishtank_urls: set = set()


def _load_phishtank_urls() -> set:
    """
    Load verified phishing URLs from PhishTank offline CSV.

    CSV Format: phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target
    Filters for: verified == "yes" AND online == "yes"
    """
    global _phishtank_urls

    if _phishtank_urls:  # Already loaded
        return _phishtank_urls

    try:
        if not OFFLINE_CSV_PATH.exists():
            print(f"Warning: PhishTank offline CSV not found at {OFFLINE_CSV_PATH}")
            print("PhishTank service will return no matches. Download CSV from https://phishtank.com/developer_info.php")
            return set()

        urls = set()
        with open(OFFLINE_CSV_PATH, 'r', encoding='utf-8', newline='') as csvfile:
            reader = csv.DictReader(csvfile)

            for row in reader:
                # Filter for verified and online phishing sites
                if (row.get('verified', '').lower() == 'yes' and
                    row.get('online', '').lower() == 'yes'):

                    url = row.get('url', '').strip()
                    if url:
                        urls.add(url)

        _phishtank_urls = urls
        print(f"Loaded {len(urls)} verified phishing URLs from PhishTank offline CSV")
        return urls

    except Exception as exc:
        print(f"Error loading PhishTank CSV: {exc}")
        return set()


async def check(url: str) -> Dict[str, Any]:
    """
    Check URL against PhishTank offline database.

    Uses pre-loaded CSV data with verified phishing URLs.
    No API calls - purely offline operation for academic benchmarking.

    Args:
        url: URL to check against PhishTank database

    Returns:
        Dict with phishing status and metadata
    """
    try:
        phishtank_urls = _load_phishtank_urls()

        # Check if URL is in the verified phishing database
        is_phish = url in phishtank_urls

        return {
            "status": "ok",
            "in_database": is_phish,
            "is_phish": is_phish,
            "verified": is_phish,  # All entries in our filtered list are verified
            "phish_id": None,  # Not available in offline mode
            "submitted_at": None,  # Not available in offline mode
            "mode": "OFFLINE_CSV",
        }

    except Exception as exc:
        return {
            "status": "unavailable",
            "in_database": False,
            "is_phish": False,
            "verified": False,
            "error": f"PhishTank offline check error: {str(exc)}",
            "mode": "OFFLINE_CSV_ERROR",
        }


def get_phishtank_urls() -> set:
    """
    Get list of all verified phishing URLs from PhishTank offline database.

    Returns:
        List of verified phishing URLs for benchmarking/training
    """
    return _load_phishtank_urls()
