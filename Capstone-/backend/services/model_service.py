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
SHAP_IMPORT_ERROR: Optional[Exception] = None

try:
    import numpy as np
    import torch
    from transformers import AutoTokenizer
    from models.models import MultiChannelFusionNetwork
    TORCH_AVAILABLE = True
except ImportError as exc:
    # Extract which package failed from the error message
    error_msg = str(exc)
    failed_package = "unknown"
    if "torch" in error_msg.lower():
        failed_package = "torch"
    elif "transformers" in error_msg.lower():
        failed_package = "transformers"
    elif "models" in error_msg.lower():
        failed_package = "models"
    elif "numpy" in error_msg.lower():
        failed_package = "numpy"
    
    print(f"CRITICAL: {failed_package} import failed - {exc}")
    print("Server will run in heuristic-only mode")
    np = None
    torch = None
    AutoTokenizer = None
    MultiChannelFusionNetwork = None
    TORCH_AVAILABLE = False
    TORCH_IMPORT_ERROR = exc

# Separate SHAP import with its own error handling
try:
    import shap
    _shap_available = True
except ImportError as exc:
    shap = None
    _shap_available = False
    SHAP_IMPORT_ERROR = exc

_model = None
_tokenizer = None
_shap_explainer = None

# TRUSTED DOMAIN WHITELIST - Prevents false positives on legitimate sites
TRUSTED_DOMAINS = {
    # Tech Giants
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "wikipedia.org", "reddit.com", "linkedin.com",
    "netflix.com", "spotify.com", "whatsapp.com", "telegram.org",
    "stackoverflow.com", "medium.com", "notion.so", "figma.com",
    # Indian Educational Institutions
    "lpu.in", "edu", "ac.in", "gov",
    # Add domain extensions that should be checked as subdomains
}

def _extract_root_domain(url: str) -> str:
    """Extract root domain from URL for whitelist comparison"""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return ""
        
        parts = hostname.split(".")
        
        # Handle special cases
        if hostname.endswith(".ac.in"):
            return ".".join(parts[-3:])  # e.g., iit.ac.in
        if hostname.endswith(".edu"):
            return ".".join(parts[-2:])  # e.g., mit.edu
        if hostname.endswith(".gov"):
            return ".".join(parts[-2:])  # e.g., whitehouse.gov
        if hostname.endswith(".org"):
            return ".".join(parts[-2:])  # e.g., wikipedia.org
        if hostname.endswith(".co.uk"):
            return ".".join(parts[-3:])  # e.g., bbc.co.uk
        
        # Default: return last 2 parts
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""

def _is_domain_trusted(url: str) -> bool:
    """Check if domain is in trusted whitelist"""
    domain = _extract_root_domain(url)
    if not domain:
        return False
    
    # Direct match check
    if domain in TRUSTED_DOMAINS:
        return True
    
    # Check for special suffixes
    if domain.endswith(".edu") or domain.endswith(".gov") or domain.endswith(".ac.in"):
        return True
    
    # Check parent domain for known trusted TLDs
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    
    return False


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

    if not TORCH_AVAILABLE:
        _model = _fallback_result("PyTorch/ML dependencies not available - running in heuristic mode only")
        return _model

    if not resolved_model_path.exists():
        _model = _fallback_result(f"Model weights not found at {resolved_model_path}")
        return _model

    _model = MultiChannelFusionNetwork(num_classes=3)
    state_dict = torch.load(resolved_model_path, map_location=torch.device("cpu"), weights_only=True)
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


def encode_chars(text: str, max_len: int) -> torch.Tensor:
    """Convert text to character-level encoding for CNN/LSTM channels"""
    if not text:
        # Return zeros tensor if empty
        return torch.zeros(1, max_len, dtype=torch.long)
    
    # Convert characters to ASCII codes, clamp to 0-127
    chars = [min(ord(c), 127) for c in text[:max_len]]
    # Pad with zeros
    chars.extend([0] * (max_len - len(chars)))
    return torch.tensor(chars, dtype=torch.long).unsqueeze(0)  # Add batch dimension


def _create_fusion_explainer(model):
    """Create SHAP explainer for channel contributions"""
    if not _shap_available or shap is None:
        return None
    
    def channel_predictor(channel_features):
        """
        Predictor function for SHAP that takes channel features 
        [llm_256, cnn_256, lstm_256] and returns classifier outputs
        """
        with torch.no_grad():
            # channel_features shape: (batch, 3, 256) where 3 = channels
            llm_feat = channel_features[:, 0, :]  # (batch, 256)
            cnn_feat = channel_features[:, 1, :]  # (batch, 256) 
            lstm_feat = channel_features[:, 2, :]  # (batch, 256)
            
            # Concatenate for fusion
            concatenated = torch.cat((llm_feat, cnn_feat, lstm_feat), dim=1)
            
            # Pass through fusion and classifier
            fused = model.fusion(concatenated)
            outputs = model.classifier(fused)
            
            return outputs.cpu().numpy()
    
    # Create background dataset (random channel features)
    background = np.random.randn(50, 3, 256).astype(np.float32)
    
    try:
        explainer = shap.KernelExplainer(channel_predictor, background)
        return explainer
    except Exception as e:
        print(f"Warning: Could not create SHAP explainer: {e}")
        return None


def get_shap_explanation(url: str, js_trace: str = "", top_k: int = 5) -> Dict[str, float]:
    """
    Get SHAP explanation for channel contributions to the final prediction.
    
    Returns the contribution of each channel (LLM, CNN, LSTM) to the prediction.
    """
    global _shap_explainer, _model
    
    if not _shap_available:
        return {
            "LLM_Channel": 0.0,
            "CNN_Channel": 0.0, 
            "LSTM_Channel": 0.0,
            "note": "SHAP not installed - install with 'pip install shap' for explanations"
        }
    
    if _model is None:
        return {"error": "Model not loaded"}
    
    if _shap_explainer is None:
        _shap_explainer = _create_fusion_explainer(_model)
    
    if _shap_explainer is None:
        return {"error": "Could not create SHAP explainer"}
    
    if _shap_explainer is None:
        _shap_explainer = _create_fusion_explainer(_model)
    
    if _shap_explainer is None:
        return {"error": "Could not create SHAP explainer"}
    
    try:
        # Get channel features for this input
        with torch.no_grad():
            encoded_url_llm = tokenize_url(url)
            encoded_url_char = encode_chars(url, 200)
            encoded_js = encode_chars(js_trace or "", 500)
            
            # Get individual channel outputs
            llm_feat, _ = _model.llm_channel(encoded_url_llm["input_ids"], encoded_url_llm["attention_mask"])
            cnn_feat = _model.cnn_channel(encoded_url_char)
            js_feat = _model.js_channel(encoded_js)
            
            # Stack channel features: (1, 3, 256)
            channel_features = torch.stack([llm_feat, cnn_feat, js_feat], dim=1).cpu().numpy()
            
            # Get SHAP explanation
            shap_values = _shap_explainer.shap_values(channel_features, nsamples=50)
            
            # Get the predicted class
            outputs, _ = _model(
                encoded_url_llm["input_ids"],
                encoded_url_llm["attention_mask"], 
                encoded_url_char,
                encoded_js
            )
            pred_class = int(torch.argmax(outputs, dim=1).item())
            
            # Get SHAP values for the predicted class
            if isinstance(shap_values, list):
                class_shap_values = shap_values[pred_class][0]  # [0] for batch dimension
            else:
                class_shap_values = shap_values[0]
            
            # Channel names
            channel_names = ["LLM_Channel", "CNN_Channel", "LSTM_Channel"]
            
            # Return channel contributions
            explanation = {}
            for i, channel in enumerate(channel_names):
                # Sum the SHAP values for all features in this channel
                channel_shap = float(np.sum(class_shap_values[i]))
                explanation[channel] = channel_shap
            
            # Sort by absolute contribution and return top-k
            sorted_channels = sorted(explanation.items(), key=lambda x: abs(x[1]), reverse=True)
            return dict(sorted_channels[:top_k])
            
    except Exception as e:
        return {"error": f"SHAP explanation failed: {str(e)}"}


def predict(url: str, js_trace: str = "", include_explanation: bool = False):
    # CRITICAL: Check whitelist FIRST to prevent false positives on trusted domains
    if _is_domain_trusted(url):
        result = {
            "prediction": "Benign",
            "probabilities": {"Benign": 0.99, "Phishing": 0.005, "Malware": 0.005},
            "confidence": 0.99,
            "mode": "whitelist",
            "whitelist_match": True,
            "is_trusted_domain": True,
        }
        if include_explanation:
            result["explanation"] = {"whitelist_match": "Domain is on verified trusted list"}
        return result
    
    model = load_model("models/multi_channel_phishing.pth")
    if isinstance(model, dict) and model.get("mode") == "heuristic":
        result = _heuristic_predict(url, js_trace)
        if include_explanation:
            result["explanation"] = {"heuristic": "Rule-based detection used due to model unavailability"}
        return result

    with torch.no_grad():
        encoded_url_llm = tokenize_url(url)
        encoded_url_char = encode_chars(url, 200)
        encoded_js = encode_chars(js_trace or "", 500)

        outputs, attentions = model(
            encoded_url_llm["input_ids"],
            encoded_url_llm["attention_mask"],
            encoded_url_char,
            encoded_js,
        )
        probs = torch.nn.functional.softmax(outputs, dim=1).squeeze(0).cpu().numpy()

    classes = {0: "Benign", 1: "Phishing", 2: "Malware"}
    pred_idx = int(np.argmax(probs))
    prediction = classes[pred_idx]

    # Convert attentions to serializable format
    attention_weights = [att.squeeze(0).cpu().numpy().tolist() for att in attentions] if attentions else []

    result = {
        "prediction": prediction,
        "probabilities": {classes[i]: float(probs[i]) for i in range(3)},
        "confidence": float(probs[pred_idx]),
        "mode": "model",
        "is_trusted_domain": False,
        "attention_weights": attention_weights,
    }
    
    # Add SHAP explanation if requested
    if include_explanation:
        explanation = get_shap_explanation(url, js_trace)
        result["explanation"] = explanation
    
    return result