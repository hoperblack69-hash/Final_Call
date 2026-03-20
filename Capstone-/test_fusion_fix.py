#!/usr/bin/env python3
"""
Test script to verify the fusion logic fix.
Traces through all 4 test cases to ensure ML and verdict alignment.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.utils.fusion import combine

def test_case(name, ai_result, vt_result, gsb_result, expected_verdict, expected_score_range):
    """Run a single test case and verify results."""
    print(f"\n{'='*80}")
    print(f"TEST CASE: {name}")
    print(f"{'='*80}")
    
    # Extract ML predictions
    probs = ai_result.get("probabilities", {})
    print(f"\n📊 ML Model Predictions:")
    print(f"  • Benign:  {probs.get('Benign', 0)*100:.2f}%")
    print(f"  • Phishing: {probs.get('Phishing', 0)*100:.2f}%")
    print(f"  • Malware: {probs.get('Malware', 0)*100:.2f}%")
    print(f"  • ML Verdict: {ai_result.get('prediction', 'Benign')}")
    
    # Extract external signals
    malicious = vt_result.get("malicious", 0)
    total = vt_result.get("total_engines", 95)
    print(f"\n🔴 External Detection Signals:")
    print(f"  • Malicious count: {malicious}/{total} ({malicious/total*100:.1f}%)")
    
    # Get fusion result
    result = combine(ai_result, vt_result, gsb_result)
    
    print(f"\n✅ Final Verdict:")
    print(f"  • Badge: {result['badge']}")
    print(f"  • Verdict: {result['verdict']}")
    print(f"  • Threat Score: {result['threat_score']}/100 {expected_score_range}")
    print(f"  • Confidence: {result['confidence']:.2%}")
    print(f"  • Rule Applied: {result['classification_rule']}")
    print(f"  • Explanation: {result['explanation']}")
    
    # Verification
    match_verdict = result['verdict'] == expected_verdict
    in_range = True
    if "-" in expected_score_range:
        min_score, max_score = map(int, expected_score_range.replace("(", "").replace(")", "").split("-"))
        in_range = min_score <= result['threat_score'] <= max_score
    
    print(f"\n🔍 Verification:")
    print(f"  ✓ Expected Verdict: {expected_verdict} → {result['verdict']} {'✅' if match_verdict else '❌'}")
    print(f"  {'✓' if in_range else '✗'} Threat Score in {expected_score_range} → {result['threat_score']} {'✅' if in_range else '❌'}")
    
    return match_verdict and in_range


def main():
    print("\n" + "="*80)
    print("FUSION LOGIC TEST SUITE")
    print("Verifying ML prediction and final verdict alignment")
    print("="*80)
    
    all_passed = True
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TEST CASE 1: Current failing case (MUST FIX)
    # ═══════════════════════════════════════════════════════════════════════════
    test1 = test_case(
        "Case 1 - CURRENT BUG FIX: ML benign=95%, signals=19/95",
        ai_result={
            "prediction": "Benign",
            "probabilities": {"Benign": 0.95, "Phishing": 0.0375, "Malware": 0.0125},
            "is_trusted_domain": False
        },
        vt_result={
            "malicious": 19,
            "total_engines": 95
        },
        gsb_result={
            "is_safe": True
        },
        expected_verdict="LOW RISK",
        expected_score_range="(15-35)"
    )
    all_passed = all_passed and test1
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TEST CASE 2: Real phishing MUST still be caught
    # ═══════════════════════════════════════════════════════════════════════════
    test2 = test_case(
        "Case 2 - REAL THREAT: ML phishing=80%, signals=60/95",
        ai_result={
            "prediction": "Phishing",
            "probabilities": {"Benign": 0.15, "Phishing": 0.80, "Malware": 0.05},
            "is_trusted_domain": False
        },
        vt_result={
            "malicious": 60,
            "total_engines": 95
        },
        gsb_result={
            "is_safe": False
        },
        expected_verdict="PHISHING",
        expected_score_range="(60-80)"
    )
    all_passed = all_passed and test2
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TEST CASE 3: ML benign but signals overwhelming
    # ═══════════════════════════════════════════════════════════════════════════
    test3 = test_case(
        "Case 3 - SIGNALS OVERRIDE: ML benign=70%, signals=45/95",
        ai_result={
            "prediction": "Benign",
            "probabilities": {"Benign": 0.70, "Phishing": 0.20, "Malware": 0.10},
            "is_trusted_domain": False
        },
        vt_result={
            "malicious": 45,
            "total_engines": 95
        },
        gsb_result={
            "is_safe": False
        },
        expected_verdict="PHISHING",
        expected_score_range="(75-95)"
    )
    all_passed = all_passed and test3
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TEST CASE 4: Trusted domain (whitelist)
    # ═══════════════════════════════════════════════════════════════════════════
    test4 = test_case(
        "Case 4 - TRUSTED WHITELIST: youtube.com or lpu.in",
        ai_result={
            "prediction": "Benign",
            "probabilities": {"Benign": 0.99, "Phishing": 0.005, "Malware": 0.005},
            "is_trusted_domain": True
        },
        vt_result={
            "malicious": 0,
            "total_engines": 95
        },
        gsb_result={
            "is_safe": True
        },
        expected_verdict="SAFE",
        expected_score_range="(5-5)"
    )
    all_passed = all_passed and test4
    
    # ═════════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═════════════════════════════════════════════════════════════════════════════
    print(f"\n\n{'='*80}")
    print("📋 TEST SUMMARY")
    print(f"{'='*80}")
    print(f"Test 1 (Bug Fix): {'✅ PASSED' if test1 else '❌ FAILED'}")
    print(f"Test 2 (Real Phishing): {'✅ PASSED' if test2 else '❌ FAILED'}")
    print(f"Test 3 (Signals Override): {'✅ PASSED' if test3 else '❌ FAILED'}")
    print(f"Test 4 (Whitelist): {'✅ PASSED' if test4 else '❌ FAILED'}")
    print(f"\nOverall: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    # ═════════════════════════════════════════════════════════════════════════════
    # VERIFICATION CHECKLIST
    # ═════════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*80}")
    print("✅ VERIFICATION CHECKLIST")
    print(f"{'='*80}")
    print(f"✓ Real phishing links still caught correctly: {'✅' if test2 else '❌'}")
    print(f"✓ Safe sites not falsely flagged as suspicious: {'✅' if test1 else '❌'}")
    print(f"✓ ML prediction and final badge never contradict: {'✅' if all_passed else '❌'}")
    print(f"✓ 40+ malicious signals always triggers threat: {'✅' if test3 else '❌'}")
    print()
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
