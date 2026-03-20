# SMART FUSION LOGIC - Visual Decision Tree

```
                              START
                                |
                    FUSION COMBINE DECISION TREE
                                |
                    ┌───────────────────────┐
                    │ Extract all signals:  │
                    │ • benign_pct          │
                    │ • phishing_pct        │
                    │ • malware_pct         │
                    │ • malicious_count     │
                    │ • total_engines       │
                    │ • is_trusted          │
                    └───────────────────────┘
                                |
                                ↓
                    ┌───────────────────────┐
                    │  RULE 1: WHITELIST?   │
                    │  is_trusted == True   │
                    └───────────────────────┘
                         /                    \
                        YES                   NO
                        |                      |
                        ↓                      ↓
                    ┌────────┐        ┌──────────────────┐
                    │SAFE ✅ │        │RULE 2: BOTH      │
                    │Score: 5│        │AGREE PHISHING?   │
                    └────────┘        │phishing >= 50%   │
                                      │AND signals > 20  │
                                      └──────────────────┘
                                           /              \
                                          YES              NO
                                          |                |
                                          ↓                ↓
                                    ┌──────────────┐  ┌──────────────────┐
                                    │PHISHING 🚨   │  │RULE 3: SIGNALS   │
                                    │Score: 60-85  │  │OVERWHELMING?     │
                                    └──────────────┘  │malicious > 40    │
                                                      └──────────────────┘
                                                           /              \
                                                          YES              NO
                                                          |                |
                                                          ↓                ↓
                                                     ┌──────────────┐  ┌──────────────────┐
                                                     │PHISHING 🚨   │  │RULE 4: ML        │
                                                     │Score: 75-95  │  │STRONGLY BENIGN?  │
                                                     └──────────────┘  │benign >= 90%     │
                                                                       │AND signals ≤ 10  │
                                                                       └──────────────────┘
                                                                            /              \
                                                                           YES              NO
                                                                           |                |
                                                                           ↓                ↓
                                                                      ┌────────┐   ┌──────────────────┐
                                                                      │SAFE ✅ │   │RULE 5: ML        │
                                                                      │Score: 5-20│ │BENIGN + MEDIUM?  │
                                                                      └────────┘   │benign >= 85%     │
                                                                                   │11 ≤ signals ≤ 25 │
                                                                                   └──────────────────┘
                                                                                        /              \
                                                                                       YES              NO
                                                                                       |                |
                                                                                       ↓                ↓
                                                                                  ┌──────────┐  ┌──────────────────┐
                                                                                  │LOW RISK  │  │RULE 6: ML        │
                                                                                  │🟡 Score  │  │BENIGN + HIGH?    │
                                                                                  │15-35     │  │benign >= 80%     │
                                                                                  └──────────┘  │26 ≤ signals ≤ 40 │
                                                                                               └──────────────────┘
                                                                                                    /              \
                                                                                                   YES              NO
                                                                                                   |                |
                                                                                                   ↓                ↓
                                                                                          ┌──────────────┐  ┌──────────────────┐
                                                                                          │SUSPICIOUS ⚠️ │  │RULE 7: WEIGHTED  │
                                                                                          │Score: 35-50  │  │SCORING FALLBACK  │
                                                                                          └──────────────┘  │                  │
                                                                                                            │weighted_score =  │
                                                                                                            │ (ml_phishing*0.55)
                                                                                                            │+(ratio*0.30)     │
                                                                                                            │+(phishing*0.15)  │
                                                                                                            └──────────────────┘
                                                                                                                    |
                                                       ┌────────────────────────────────────────────────────────────┤
                                       ┌───────────────┴──────────┬──────────────────┬──────────────────┬──────────────┐
                                       |                          |                  |                  |              |
                                       ↓                          ↓                  ↓                  ↓              ↓
                                   < 0.20                    0.20-0.40           0.40-0.60        0.60-0.80       >=0.80
                                       |                          |                  |                  |              |
                                       ↓                          ↓                  ↓                  ↓              ↓
                                   ┌────────┐             ┌──────────┐         ┌──────────┐    ┌──────────────┐   ┌────────┐
                                   │SAFE ✅ │             │LOW RISK  │         │SUSPICIOUS│    │PHISHING 🚨   │   │MALWARE│
                                   │Score:  │             │🟡 Score: │         │⚠️ Score: │    │Score: 60-80  │   │☠️     │
                                   │0-19    │             │20-39     │         │40-59     │    │              │   │Score: │
                                   └────────┘             └──────────┘         └──────────┘    └──────────────┘   │80-100 │
                                                                                                                     └────────┘
```

---

## Decision Tree Rules Summary

### RULE 1: Whitelist (Highest Priority)
```
IF is_trusted_domain == True
THEN
    verdict = "SAFE"
    threat_score = 5
    confidence = 99%
PURPOSE: Trusted domains (e.g., youtube.com, lpu.in) bypass all checks
```

### RULE 2: Both Sources Agree - Phishing
```
IF phishing_pct >= 50 AND malicious_count > 20
THEN
    verdict = "PHISHING"
    threat_score = 60-85
    confidence = high
PURPOSE: When ML and signals both strongly indicate phishing
EXAMPLE: 80% phishing + 60 engines flagged = DEFINITE PHISHING
```

### RULE 3: Overwhelming Detection Signals
```
IF malicious_count > 40
THEN
    verdict = "PHISHING"
    threat_score = 75-95
    confidence = very high
PURPOSE: 40+ out of 95 engines is ~42%+ unanimous detection
EXAMPLE: Even if ML says 70% benign, 45 signals = PHISHING (override)
```

### RULE 4: ML Strongly Benign + Low Signals
```
IF benign_pct >= 90 AND malicious_count <= 10
THEN
    verdict = "SAFE"
    threat_score = 5-20
    confidence = high
PURPOSE: Safe sites with minimal noise
EXAMPLE: 98% benign + 2 signals = SAFE
```

### RULE 5: ML Benign + Medium Signals (BUG FIX)
```
IF benign_pct >= 85 AND 11 <= malicious_count <= 25
THEN
    verdict = "LOW RISK"
    threat_score = 15-35
    confidence = moderate
PURPOSE: Trust ML but note the caution from signals
EXAMPLE: 95% benign + 19 signals = LOW RISK (THIS WAS THE BUG)
```

### RULE 6: ML Benign + High Signals
```
IF benign_pct >= 80 AND 26 <= malicious_count <= 40
THEN
    verdict = "SUSPICIOUS"
    threat_score = 35-50
    confidence = moderate
PURPOSE: Signals override weak ML benign prediction
EXAMPLE: 85% benign + 35 signals = SUSPICIOUS (signals dominate)
```

### RULE 7: Weighted Scoring (Fallback)
```
weighted_score = (ml_phishing * 0.55) 
               + (malicious_ratio * 0.30)
               + (phishing_pct * 0.15)

IF weighted_score < 0.20
THEN verdict = "SAFE" (score: 0-19)
ELSE IF weighted_score < 0.40
THEN verdict = "LOW RISK" (score: 20-39)
ELSE IF weighted_score < 0.60
THEN verdict = "SUSPICIOUS" (score: 40-59)
ELSE IF weighted_score < 0.80
THEN verdict = "PHISHING" (score: 60-79)
ELSE
THEN verdict = "MALWARE" (score: 80-100)

PURPOSE: Weighted combination for edge cases
WEIGHTS: ML phishing gets 55% weight, signals 30%, phishing 15%
```

---

## Signal Threshold Breakdown

```
Malicious Signal Count Ranges:

0-10 signals:   LOW - Trust ML heavily (Rules 1,4)
11-25 signals:  MEDIUM - Trust ML with caution (Rule 5) ← BUG FIX HERE
26-40 signals:  HIGH - ML can be overridden (Rule 6)
41-95 signals:  OVERWHELMING - Always threat (Rule 3)

Benign % Ranges:

90-100%:  STRONG BENIGN (Rule 4, can't be phishing)
85-89%:   BENIGN (Rule 5, only LOW RISK if signals 11-25)
80-84%:   MODERATE BENIGN (Rule 6, can be SUSPICIOUS)
50-79%:   WEAK BENIGN (weighted scoring)
0-49%:    THREAT LIKELY (weighted scoring + overrides)
```

---

## Contradiction Prevention

The new logic prevents contradictions through:

1. **Signal weighting**: 0.30 weight in final score (not dominant)
2. **Tiered thresholds**: Progressive rules for different benign percentages
3. **Hard thresholds**: 40+ signals ALWAYS = phishing (unavoidable)
4. **ML priority**: When benign >= 90%, cannot be PHISHING
5. **Clear boundaries**: Non-overlapping conditions prevent ambiguity
6. **Weighted fallback**: 0.55 ML weight ensures ML dominates when needed

---

## Test Case Examples in Decision Tree

### Test 1: 95% Benign + 19 Signals
```
Is trusted? NO
Both agree phishing? NO (phishing=3.75% < 50%)
Signals > 40? NO
Strong benign? NO (signals=19 > 10)
Benign 85-89% + 11-25 signals? YES ✅
└─> RULE 5: LOW RISK ✅ (Score: 30)
```

### Test 2: 80% Phishing + 60 Signals
```
Is trusted? NO
Both agree phishing? YES (phishing=80% >= 50% AND signals=60 > 20) ✅
└─> RULE 2: PHISHING ✅ (Score: 77)
```

### Test 3: 70% Benign + 45 Signals
```
Is trusted? NO
Both agree phishing? NO (phishing=20% < 50%)
Signals > 40? YES ✅
└─> RULE 3: PHISHING ✅ (Score: 77)
```

### Test 4: Trusted Domain
```
Is trusted? YES ✅
└─> RULE 1: SAFE ✅ (Score: 5)
```

---

## Implementation Notes

- Rules are evaluated in ORDER (Rule 1-7)
- First matching rule returns immediately
- No rule rechecking after decision
- All scores normalized to 0-100 scale
- Confidence calculated from probabilities
- Classification rule included in output for debugging
