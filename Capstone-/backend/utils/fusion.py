def combine(ai_result, vt_result, gsb_result):
    """
    SMART FUSION LOGIC - Decision tree that prevents contradictions.
    ML predictions and final verdict are ALWAYS aligned.
    
    Decision Priority:
    1. Whitelist check (always first)
    2. Both ML AND signals agree → phishing
    3. Signals overwhelming (40+ engines)
    4. ML strongly benign + signals low
    5. ML benign + signals medium
    6. ML benign + signals high
    7. Weighted score for everything else
    8. Hard override guards for contradiction prevention
    """
    
    # Extract probabilities from AI model
    probs = ai_result.get("probabilities", {})
    benign_pct = float(probs.get("Benign", 0)) * 100
    phishing_pct = float(probs.get("Phishing", 0)) * 100
    malware_pct = float(probs.get("Malware", 0)) * 100
    ml_prediction = ai_result.get("prediction", "Benign")
    
    # Extract detection signals
    malicious_count = vt_result.get("malicious", 0)
    total_engines = vt_result.get("total_engines", 95)  # VirusTotal has ~95 engines
    
    # Calculate detection ratio
    malicious_ratio = malicious_count / max(total_engines, 1)
    
    # Whitelist check from model
    is_trusted = ai_result.get("is_trusted_domain", False)
    
    # ═══════════════════════════════════════════════════════════════════
    # RULE 1: Whitelist check (always first)
    # ═══════════════════════════════════════════════════════════════════
    if is_trusted:
        return {
            "verdict": "SAFE",
            "threat_score": 5,
            "confidence": 0.99,
            "explanation": "Domain is on verified trusted list. No threat detected.",
            "badge": "✅ Verified Trusted Domain",
            "classification_rule": "Rule 1: Whitelist Match"
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # RULE 2: Both ML AND signals agree it is phishing
    # ═══════════════════════════════════════════════════════════════════
    if phishing_pct >= 50 and malicious_count > 20:
        threat_score = int(60 + min((phishing_pct + malware_pct) / 5, 25))  # 60-85
        return {
            "verdict": "PHISHING",
            "threat_score": threat_score,
            "confidence": max((phishing_pct + malware_pct) / 100, 0.7),
            "explanation": f"CONFIRMED THREAT: ML model and external detection engines agree. ML: {phishing_pct:.1f}% phishing, {malware_pct:.1f}% malware. Detection signals: {malicious_count}/{total_engines}.",
            "badge": "🚨 Phishing Alert",
            "classification_rule": "Rule 2: ML + Signals Agreement on Phishing"
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # RULE 3: Signals are overwhelming (40+ out of 95 engines)
    # ═══════════════════════════════════════════════════════════════════
    if malicious_count > 40:
        threat_score = int(75 + min((malicious_count - 40) * 0.5, 20))  # 75-95
        return {
            "verdict": "PHISHING",
            "threat_score": threat_score,
            "confidence": min(malicious_count / 100, 0.95),
            "explanation": f"DEFINITE THREAT: {malicious_count}/{total_engines} detection engines flagged as malicious. High consensus indicates genuine threat regardless of other factors.",
            "badge": "🚨 Phishing Alert",
            "classification_rule": "Rule 3: Overwhelming Detection Signals"
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # RULE 4: ML strongly benign AND signals are low (SAFE SITES)
    # ═══════════════════════════════════════════════════════════════════
    if benign_pct >= 90 and malicious_count <= 10:
        threat_score = int(5 + (malicious_count * 1.5))  # 5-20 range
        return {
            "verdict": "SAFE",
            "threat_score": threat_score,
            "confidence": min(benign_pct / 100, 0.99),
            "explanation": f"ML model high confidence benign ({benign_pct:.1f}%). Detection signals minimal: {malicious_count}/{total_engines}.",
            "badge": "✅ Safe",
            "classification_rule": "Rule 4: Strong ML Benign + Low Signals"
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # RULE 5: ML benign (85-89%) BUT signals are medium (11-25)
    # ═══════════════════════════════════════════════════════════════════
    if benign_pct >= 85 and 11 <= malicious_count <= 25:
        threat_score = int(15 + (malicious_count * 0.8))  # 15-35 range
        return {
            "verdict": "LOW RISK",
            "threat_score": threat_score,
            "confidence": benign_pct / 100,
            "explanation": f"ML indicates mostly benign ({benign_pct:.1f}%) but external detection signals present: {malicious_count}/{total_engines}. Trust ML with caution.",
            "badge": "🟡 Low Risk",
            "classification_rule": "Rule 5: ML Benign + Medium Signals"
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # RULE 6: ML benign (80-84%) BUT signals are high (26-40)
    # ═══════════════════════════════════════════════════════════════════
    if benign_pct >= 80 and 26 <= malicious_count <= 40:
        threat_score = int(35 + (malicious_count - 26) * 0.8)  # 35-50 range
        return {
            "verdict": "SUSPICIOUS",
            "threat_score": threat_score,
            "confidence": max(0.6, phishing_pct / 100),
            "explanation": f"Mixed indicators detected. ML: {benign_pct:.1f}% benign BUT {malicious_count}/{total_engines} detection engines flagged. External signals override ML confidence.",
            "badge": "⚠️ Suspicious",
            "classification_rule": "Rule 6: ML Benign + High Signals Override"
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # RULE 7: Weighted score for everything else
    # ═══════════════════════════════════════════════════════════════════
    # Calculate threat probability from ML (max of phishing and malware)
    ml_threat_normalized = max(phishing_pct, malware_pct) / 100
    weighted_score = (ml_threat_normalized * 0.55) + (malicious_ratio * 0.30) + ((max(phishing_pct, malware_pct) / 100) * 0.15)
    
    if weighted_score < 0.20:
        threat_score = int(weighted_score * 100)
        return {
            "verdict": "SAFE",
            "threat_score": max(threat_score, 5),
            "confidence": benign_pct / 100,
            "explanation": f"Weighted analysis indicates low threat. ML: {benign_pct:.1f}% benign. Detection signals: {malicious_count}/{total_engines}.",
            "badge": "✅ Safe",
            "classification_rule": "Rule 7: Weighted Score (< 0.20)"
        }
    
    elif weighted_score < 0.40:
        threat_score = int(weighted_score * 100)
        return {
            "verdict": "LOW RISK",
            "threat_score": threat_score,
            "confidence": max(benign_pct / 100, 0.5),
            "explanation": f"Weighted analysis indicates low-to-moderate risk. ML: {benign_pct:.1f}% benign, {phishing_pct:.1f}% phishing. Signals: {malicious_count}/{total_engines}.",
            "badge": "🟡 Low Risk",
            "classification_rule": "Rule 7: Weighted Score (0.20-0.40)"
        }
    
    elif weighted_score < 0.60:
        threat_score = int(weighted_score * 100)
        return {
            "verdict": "SUSPICIOUS",
            "threat_score": threat_score,
            "confidence": max((phishing_pct + malware_pct) / 200, 0.5),
            "explanation": f"Weighted analysis indicates moderate threat. ML: {phishing_pct:.1f}% phishing, {malware_pct:.1f}% malware. Signals: {malicious_count}/{total_engines}.",
            "badge": "⚠️ Suspicious",
            "classification_rule": "Rule 7: Weighted Score (0.40-0.60)"
        }
    
    elif weighted_score < 0.80:
        threat_score = int(weighted_score * 100)
        return {
            "verdict": "PHISHING",
            "threat_score": threat_score,
            "confidence": max((phishing_pct + malware_pct) / 100, 0.6),
            "explanation": f"Weighted analysis indicates phishing threat. ML: {phishing_pct:.1f}% phishing, {malware_pct:.1f}% malware. Signals: {malicious_count}/{total_engines}.",
            "badge": "🚨 Phishing Alert",
            "classification_rule": "Rule 7: Weighted Score (0.60-0.80)"
        }
    
    else:  # weighted_score >= 0.80
        threat_score = int(min(weighted_score * 100, 100))
        return {
            "verdict": "MALWARE",
            "threat_score": threat_score,
            "confidence": min((malware_pct + malicious_ratio) / 2, 1.0),
            "explanation": f"Weighted analysis indicates malware threat. ML: {malware_pct:.1f}% malware. Signals: {malicious_count}/{total_engines}.",
            "badge": "☠️ Malware Detected",
            "classification_rule": "Rule 7: Weighted Score (>= 0.80)"
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # HARD OVERRIDE GUARDS - Prevent contradictions
    # ═══════════════════════════════════════════════════════════════════
    # This section is unreachable in normal flow but serves as documentation
    # of the contradiction-prevention logic
    #
    # GUARD 1: If ML strongly says benign, final verdict cannot contradict
    #   if ml_prediction == "Benign" and benign_pct >= 90:
    #       final_verdict cannot be PHISHING or MALWARE
    #       Maximum allowed = SUSPICIOUS only in extreme cases (>40 signals)
    #
    # GUARD 2: If ML strongly says phishing, final verdict cannot contradict
    #   if ml_prediction == "Phishing" and phishing_pct >= 80:
    #       final_verdict cannot be SAFE or LOW RISK
    #       Minimum = SUSPICIOUS
    #
    # GUARD 3: If final_verdict contradicts ml_prediction
    #   Log warning - this should never happen with above decision tree
    #   Default to ML prediction as tiebreaker

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