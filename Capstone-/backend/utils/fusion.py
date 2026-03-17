def combine(ai_result, vt_result, gsb_result):
    # AI score: confidence * 100, weighted 40%
    ai_score = ai_result["confidence"] * 100
    ai_weight = 0.4
    
    # VT score: (malicious / total) * 100, weighted 40%
    vt_score = (vt_result["malicious"] / vt_result["total_engines"]) * 100 if vt_result["total_engines"] > 0 else 0
    vt_weight = 0.4
    
    # GSB score: 0 if safe, 100 if unsafe, weighted 20%
    gsb_score = 0 if gsb_result["is_safe"] else 100
    gsb_weight = 0.2
    
    # Weighted average
    threat_score = (ai_score * ai_weight + vt_score * vt_weight + gsb_score * gsb_weight)
    threat_score = min(100, max(0, threat_score))
    
    # Map to verdict
    if threat_score <= 25:
        verdict = "SAFE"
    elif threat_score <= 50:
        verdict = "SUSPICIOUS"
    elif threat_score <= 75:
        verdict = "PHISHING"
    else:
        verdict = "MALWARE"
    
    confidence = max(ai_result["confidence"], vt_score / 100, 1 - gsb_score / 100)
    
    explanation = generate_explanation(ai_result, vt_result, gsb_result, verdict)
    
    return {
        "verdict": verdict,
        "threat_score": int(threat_score),
        "confidence": confidence,
        "explanation": explanation
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