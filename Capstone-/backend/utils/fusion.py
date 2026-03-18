def combine(ai_result, vt_result, gsb_result):
    """
    NEW CLASSIFICATION LOGIC - Based on percentage distributions and signal counts
    Prevents false positives on legitimate sites
    """
    
    # Extract probabilities from AI model
    probs = ai_result.get("probabilities", {})
    benign_pct = float(probs.get("Benign", 0)) * 100
    phishing_pct = float(probs.get("Phishing", 0)) * 100
    malware_pct = float(probs.get("Malware", 0)) * 100
    
    # Extract detection signals
    malicious_count = vt_result.get("malicious", 0)
    total_engines = vt_result.get("total_engines", 1)  # Avoid division by zero
    gsb_is_safe = gsb_result.get("is_safe", True)
    
    # Whitelist check from model
    is_trusted = ai_result.get("is_trusted_domain", False)
    
    # PRIORITY 1: Whitelist takes precedence
    if is_trusted:
        return {
            "verdict": "SAFE",
            "threat_score": 5,
            "confidence": 0.99,
            "explanation": "Domain is on verified trusted list. No threat detected.",
            "badge": "✅ Verified Trusted Domain",
            "classification_rule": "Whitelist Match"
        }
    
    # PRIORITY 2: Benign >= 90% AND malicious <= 3
    if benign_pct >= 90 and malicious_count <= 3:
        threat_score = int(benign_pct / 10)  # 5-10 range
        return {
            "verdict": "SAFE",
            "threat_score": threat_score,
            "confidence": min(benign_pct / 100, 0.99),
            "explanation": f"ML model confidence very high ({benign_pct:.1f}% benign). Detection signals: {malicious_count}/{total_engines}.",
            "badge": "✅ Safe",
            "classification_rule": "High Benign Confidence"
        }
    
    # PRIORITY 3: Benign >= 75% AND malicious <= 10
    if benign_pct >= 75 and malicious_count <= 10:
        threat_score = int(10 + (100 - benign_pct) / 3)  # 10-25 range
        return {
            "verdict": "LOW RISK",
            "threat_score": threat_score,
            "confidence": benign_pct / 100,
            "explanation": f"ML model indicates mostly benign ({benign_pct:.1f}%). Minor detection signals: {malicious_count}/{total_engines}.",
            "badge": "🟢 Low Risk",
            "classification_rule": "Moderate Benign, Low Signals"
        }
    
    # PRIORITY 4: Benign >= 50% AND malicious <= 25
    if benign_pct >= 50 and malicious_count <= 25:
        threat_score = int(25 + (phishing_pct / 2))  # 25-40 range
        return {
            "verdict": "SUSPICIOUS",
            "threat_score": threat_score,
            "confidence": max(phishing_pct / 100, 0.5),
            "explanation": f"Mixed signals detected. ML: {benign_pct:.1f}% benign, {phishing_pct:.1f}% phishing. External detections: {malicious_count}/{total_engines}.",
            "badge": "⚠️ Suspicious",
            "classification_rule": "Mixed Signals"
        }
    
    # PRIORITY 5: Benign < 50% OR malicious > 25
    if benign_pct < 50 or malicious_count > 25:
        threat_score = int(40 + min((phishing_pct + malware_pct) / 4, 20))  # 40-60 range
        return {
            "verdict": "PHISHING",
            "threat_score": threat_score,
            "confidence": max((phishing_pct + malware_pct) / 100, 0.6),
            "explanation": f"Significant threat indicators detected. ML: {phishing_pct:.1f}% phishing, {malware_pct:.1f}% malware. Detection engines: {malicious_count}/{total_engines} flagged.",
            "badge": "🚨 Phishing Alert",
            "classification_rule": "High Malicious Signals"
        }
    
    # PRIORITY 6: Malicious > 50 OR explicit malware detection
    if malicious_count > 50 or malware_pct > 50:
        threat_score = int(85 + min(malware_pct / 10, 15))  # 85-100 range
        return {
            "verdict": "MALWARE",
            "threat_score": threat_score,
            "confidence": min((malware_pct + malicious_count) / 100, 1.0),
            "explanation": f"CRITICAL: Malware/high-risk payload detected. {malicious_count}/{total_engines} detection engines flagged as malicious. {malware_pct:.1f}% malware probability.",
            "badge": "☠️ Malware Detected",
            "classification_rule": "Critical Threat"
        }
    
    # Fallback (should not reach here)
    default_threat = int((phishing_pct + malware_pct) / 2)
    return {
        "verdict": "SUSPICIOUS",
        "threat_score": max(default_threat, 20),
        "confidence": 0.5,
        "explanation": f"Evaluation complete. Benign: {benign_pct:.1f}%, Phishing: {phishing_pct:.1f}%, Malware: {malware_pct:.1f}%.",
        "badge": "⚠️ Review Required",
        "classification_rule": "Default Classification"
    }

def generate_explanation(ai_result, vt_result, gsb_result, verdict):
    malicious = vt_result.get("malicious", 0)
    total = vt_result.get("total_engines", 0)
    confidence = ai_result.get("confidence", 0.0)
    prediction = ai_result.get("prediction", "Unknown")

    safety_line = (
        "Supplementary web safety validation did not identify direct threat matches"
        if gsb_result.get("is_safe", True)
        else "Supplementary web safety validation identified threat indicators"
    )

    return (
        f"Classifier output indicates {prediction} with {confidence:.2%} confidence. "
        f"Independent detection checks reported {malicious}/{total} malicious findings. "
        f"{safety_line}. Overall verdict: {verdict}."
    )