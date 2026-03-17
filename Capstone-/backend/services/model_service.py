import math
import re
import sys
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

# Ensure project root is on sys.path so that `models` and `backend` packages are importable
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TORCH_IMPORT_ERROR: Optional[Exception] = None

try:
    import numpy as np
    import torch
    from transformers import AutoTokenizer

    from models.models import MultiChannelFusionNetwork
except Exception as exc:
    np = None
    torch = None
    AutoTokenizer = None
    MultiChannelFusionNetwork = None
    TORCH_IMPORT_ERROR = exc

_model = None
_tokenizer = None


def _fallback_result(reason: str) -> Dict[str, str]:
    return {"mode": "heuristic", "reason": reason}


def _is_ipv4_host(hostname: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname or ""))


def _heuristic_predict(url: str, js_trace: str = "") -> Dict:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    lowered_url = url.lower()
    lowered_js = (js_trace or "").lower()

    score = 0.05
    suspicious_terms = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "wallet",
        "bank",
        "signin",
        "confirm",
    ]
    risky_js_terms = ["eval(", "document.cookie", "fromcharcode", "atob(", "fetch(", "xmlhttprequest"]

    if parsed.scheme != "https":
        score += 0.1
    if _is_ipv4_host(hostname):
        score += 0.25
    if "@" in url:
        score += 0.25
    if "xn--" in hostname:
        score += 0.15
    if len(url) > 90:
        score += 0.1
    if hostname.count(".") >= 3:
        score += 0.1
    if any(term in lowered_url for term in suspicious_terms):
        score += 0.25
    if any(term in path for term in suspicious_terms):
        score += 0.1
    if any(term in lowered_js for term in risky_js_terms):
        score += 0.25

    score = max(0.0, min(0.98, score))

    if score >= 0.75:
        prediction = "Malware"
        probabilities = {
            "Benign": max(0.01, 1 - score - 0.15),
            "Phishing": max(0.05, 0.2),
            "Malware": score,
        }
    elif score >= 0.4:
        prediction = "Phishing"
        phishing_prob = min(0.95, max(0.45, score))
        benign_prob = max(0.02, 1 - phishing_prob - 0.08)
        probabilities = {
            "Benign": benign_prob,
            "Phishing": phishing_prob,
            "Malware": max(0.03, 1 - benign_prob - phishing_prob),
        }
    else:
        benign_prob = min(0.96, max(0.55, 1 - score))
        probabilities = {
            "Benign": benign_prob,
            "Phishing": max(0.03, score * 0.75),
            "Malware": max(0.01, score * 0.25),
        }
        prediction = "Benign"

    total = sum(probabilities.values())
    normalized = {label: value / total for label, value in probabilities.items()}

    return {
        "prediction": prediction,
        "probabilities": normalized,
        "confidence": float(normalized[prediction]),
        "mode": "heuristic",
    }


def load_model(model_path: str = None):
    global _model, _tokenizer
    if _model is not None:
        return _model

    if model_path is None:
        resolved_model_path = ROOT / "models" / "multi_channel_phishing.pth"
    else:
        resolved_model_path = Path(model_path)
        if not resolved_model_path.is_absolute():
            resolved_model_path = ROOT / resolved_model_path

    if TORCH_IMPORT_ERROR is not None:
        _model = _fallback_result(f"PyTorch stack unavailable: {TORCH_IMPORT_ERROR}")
        return _model

    if not resolved_model_path.exists():
        _model = _fallback_result(f"Model weights not found at {resolved_model_path}")
        return _model

    _model = MultiChannelFusionNetwork(num_classes=3)
    state_dict = torch.load(resolved_model_path, map_location=torch.device("cpu"))
    _model.load_state_dict(state_dict, strict=False)
    _model.eval()
    _tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    return _model


def tokenize_url(url: str):
    global _tokenizer
    if _tokenizer is None:
        _tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    return _tokenizer(
        url,
        padding="max_length",
        truncation=True,
        max_length=200,
        return_tensors="pt",
    )


def encode_chars(text: str, max_len: int):
    encoded = np.zeros(max_len, dtype=np.int64)
    for i, char in enumerate(text[:max_len]):
        val = ord(char)
        encoded[i] = val if val < 128 else 0
    return torch.tensor(encoded, dtype=torch.long).unsqueeze(0)


def predict(url: str, js_trace: str = ""):
    model = load_model("models/multi_channel_phishing.pth")
    if isinstance(model, dict) and model.get("mode") == "heuristic":
        return _heuristic_predict(url, js_trace)

    with torch.no_grad():
        encoded_url_llm = tokenize_url(url)
        encoded_url_char = encode_chars(url, 200)
        encoded_js = encode_chars(js_trace or "", 500)

        outputs = model(
            encoded_url_llm["input_ids"],
            encoded_url_llm["attention_mask"],
            encoded_url_char,
            encoded_js,
        )
        probs = torch.nn.functional.softmax(outputs, dim=1).squeeze(0).cpu().numpy()

    classes = {0: "Benign", 1: "Phishing", 2: "Malware"}
    pred_idx = int(np.argmax(probs))
    prediction = classes[pred_idx]

    return {
        "prediction": prediction,
        "probabilities": {classes[i]: float(probs[i]) for i in range(3)},
        "confidence": float(probs[pred_idx]),
        "mode": "model",
    }