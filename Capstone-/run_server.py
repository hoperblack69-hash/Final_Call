"""Run the FastAPI backend with correct module path handling.

Run this script from the project root:
    python run_server.py

This ensures "models" and "backend" packages are importable even when running
from root without modifying PYTHONPATH.
"""

import os
import sys

# Ensure the project root is on sys.path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("backend.app:app", host="0.0.0.0", port=port, reload=True)
