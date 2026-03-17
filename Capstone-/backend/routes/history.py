from fastapi import APIRouter
import json
import os

router = APIRouter()

HISTORY_FILE = "scan_history.json"


def _load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        try:
            return json.load(f)
        except Exception:
            return []


def save_scan(scan_result: dict):
    history = _load_history()
    history.append(scan_result)
    # Keep only last 50
    history = history[-50:]
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


@router.get("/history")
async def get_history():
    return _load_history()

@router.delete("/history")
async def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    return {"message": "History cleared"}