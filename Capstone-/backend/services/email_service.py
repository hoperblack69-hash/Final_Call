import re
from typing import List, Dict, Tuple

from backend.utils.email_utils import (  # noqa: F401
    extract_urls,
    is_lookalike_domain,
    levenshtein_distance,
)

KNOWN_BRANDS = [
    "amazon", "paypal", "google", "microsoft", "apple",
    "facebook", "netflix", "instagram", "twitter", "ebay",
    "bank", "chase", "wellsfargo", "citibank", "hsbc"
]

FREE_PROVIDERS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"]

CREDENTIAL_PHRASES = [
    "enter your password", "confirm your details", "verify your account",
    "click the link below", "update payment", "confirm identity"
]

URGENCY_KEYWORDS = ["urgent", "immediate", "act now", "expires", "24 hours", "suspended"]
FEAR_KEYWORDS = ["account locked", "unauthorized", "suspicious activity", "verify now"]
REWARD_KEYWORDS = ["you won", "free", "prize", "gift card", "lucky winner", "claim now"]
THREAT_KEYWORDS = ["legal action", "police", "lawsuit", "penalty", "fine"]


def analyze_sender(sender: str) -> Dict:
    sender = sender.strip()
    local_part = ""
    domain = ""

    if "@" in sender:
        local_part, domain = sender.split("@", 1)
    else:
        domain = sender

    is_lookalike, brand, dist = is_lookalike_domain(domain, KNOWN_BRANDS)
    spoofed_brand = brand if is_lookalike else ""

    is_free_provider = domain.lower() in FREE_PROVIDERS
    free_spoof = False
    if is_free_provider and any(b in local_part.lower() for b in KNOWN_BRANDS):
        free_spoof = True

    risk_score = 20
    reason_parts = []

    if is_lookalike:
        risk_score += 50
        reason_parts.append(f"Domain '{domain}' is a lookalike of '{brand}.com'")

    if free_spoof:
        risk_score += 25
        reason_parts.append("Using a free email provider while posing as a brand")

    if not reason_parts:
        reason_parts.append("No obvious spoofing indicators detected")

    risk_score = min(100, risk_score)

    return {
        "email": sender,
        "domain": domain,
        "is_spoofed": is_lookalike or free_spoof,
        "spoofed_brand": spoofed_brand,
        "risk_score": risk_score,
        "reason": "; ".join(reason_parts)
    }


def analyze_subject(subject: str) -> Dict:
    subject_lower = subject.lower()
    triggered = []
    category = "NONE"

    for kw in URGENCY_KEYWORDS:
        if kw in subject_lower:
            triggered.append(kw)
            category = "URGENCY"
    for kw in FEAR_KEYWORDS:
        if kw in subject_lower:
            triggered.append(kw)
            if category == "NONE":
                category = "FEAR"
    for kw in REWARD_KEYWORDS:
        if kw in subject_lower:
            triggered.append(kw)
            if category == "NONE":
                category = "REWARD"
    for kw in THREAT_KEYWORDS:
        if kw in subject_lower:
            triggered.append(kw)
            if category == "NONE":
                category = "THREAT"

    risk_score = 10 + len(triggered) * 15
    risk_score = min(100, risk_score)

    reason = (
        "Subject uses high-pressure language" if triggered else "No urgency or threat language detected"
    )

    return {
        "subject": subject,
        "risk_score": risk_score,
        "triggered_keywords": triggered,
        "category": category,
        "reason": reason
    }


def analyze_body(body: str) -> Dict:
    text = body.lower() if body else ""

    credential_phrases = [p for p in CREDENTIAL_PHRASES if p in text]

    suspicious_patterns = []
    # Detect mismatched href and display text
    link_pattern = re.compile(r'<a[^>]+href=["\'](.*?)["\'][^>]*>(.*?)<\/a>', re.IGNORECASE)
    for match in link_pattern.findall(body):
        href, display = match
        if href and display and href.strip() not in display:
            suspicious_patterns.append("mismatched href links")
            break

    # Hidden text patterns
    hidden_pattern = re.compile(r'style=["\'][^"\']*(display\s*:\s*none|font-size\s*:\s*0)[^"\']*["\']', re.IGNORECASE)
    if hidden_pattern.search(body):
        suspicious_patterns.append("hidden text")

    # Too many exclamation marks
    if text.count("!") > 3:
        suspicious_patterns.append("excessive exclamation marks")

    # Fake urgency timers
    manipulation = []
    if re.search(r"within\s*\d+\s*hours", text) or re.search(r"\d+\s*hours?\s*left", text):
        manipulation.append("fake urgency timer")

    # All-caps words
    caps = re.findall(r"\b[A-Z]{4,}\b", body)
    if caps:
        manipulation.append("all-caps words")

    risk_score = 15
    risk_score += len(credential_phrases) * 15
    risk_score += len(suspicious_patterns) * 10
    risk_score += len(manipulation) * 10
    risk_score = min(100, risk_score)

    reason = "Body contains suspicious patterns" if (credential_phrases or suspicious_patterns or manipulation) else "No major suspicious patterns detected"

    return {
        "risk_score": risk_score,
        "credential_phrases": credential_phrases,
        "suspicious_patterns": suspicious_patterns,
        "manipulation_tactics": manipulation,
        "reason": reason
    }


def compute_email_threat_score(
    sender_analysis: Dict,
    subject_analysis: Dict,
    body_analysis: Dict,
    url_results: List[Dict]
) -> Dict:
    sender_score = sender_analysis.get("risk_score", 0)
    subject_score = subject_analysis.get("risk_score", 0)
    body_score = body_analysis.get("risk_score", 0)

    url_score = 0
    if url_results:
        # Use worst score among URLs (highest threat)
        url_score = max((r.get("threat_score", 0) for r in url_results), default=0)

    overall = (
        sender_score * 0.25
        + subject_score * 0.20
        + body_score * 0.25
        + url_score * 0.30
    )
    overall_score = int(min(100, max(0, overall)))

    if overall_score <= 25:
        verdict = "SAFE"
    elif overall_score <= 50:
        verdict = "SUSPICIOUS"
    elif overall_score <= 75:
        verdict = "PHISHING"
    else:
        verdict = "MALWARE"

    explanation = (
        f"Sender risk: {sender_score}, Subject risk: {subject_score}, "
        f"Body risk: {body_score}, Worst URL risk: {url_score}."
    )

    return {
        "overall_score": overall_score,
        "verdict": verdict,
        "explanation": explanation,
    }
