# Audit of Phase 2 Baseline Audit - Critical Findings

**Date**: 2026-10-23  
**Baseline**: commit 0a51271  
**Status**: **MULTIPLE CRITICAL BLOCKERS IDENTIFIED**

---

## Executive Summary

The Phase 2 baseline audit report (BASELINE_AUDIT_REPORT.md) claimed "10/10 attributions confirmed" and recommended "PASS, proceed with Phase 3". 

**This audit of the audit reveals CRITICAL FLAWS**:

1. **Accounting Error**: Summary reports 8 FP + 4 FN = 12 errors, but attribution file contains only 6 FP + 4 FN = 10 errors
2. **Matching Bug**: analyze_errors.py uses first-match-above-threshold instead of best-match (highest IoU), causing it to match detections to WRONG GT persons
3. **Silent Exclusion**: person_2 in 000000000257.jpg is a legitimate FP that was silently excluded from attribution
4. **Unverified Claims**: Original report claimed "all 10 confirmed" without detecting these critical bugs

**RECOMMENDATION**: **DO NOT PROCEED TO PHASE 3** until these blockers are resolved.

---

## STEP 0: Preflight and Freeze v1

**Commit**: 0a51271782f2c21dd87de5b65480a2e0628d61f7  
**Status**: Clean working directory (new untracked files from first audit)

**Frozen baseline files** (SHA-256 hashes):
```
File                                 Hash                                                            
annotations.json                     FECF1A2BA355F443DF506105D60CB6BB99F8E3246795E9A394E75F5116684DD5
baseline_audit_report.json           81AA71C44ED839B5EA88A59412BC0E6517278DD8079A3404B13690FA487D1FDC
BASELINE_AUDIT_REPORT.md             8336852BB6BD7C42DFCAB939FD7D2DC8F71E8E29D1F53B2BF5E19B96C94AD445
baseline_error_attribution.json      2FB2942AAC637422DA1BF9F9F1460AF2A7B075714E6D89E026B44032D0A32DA4
baseline_instrumented.json           4F2E7EEF7C21148DFB758378E5EFA9DACA4115C8558945D008A81AFDB135B848
baseline_instrumented_config.json    79F93948C2596B0E4EF0522F46EC31548F612953DE3DF264479FA4DB62D0ED28
baseline_instrumented_detailed.jsonl 37479A5F5ACEAABE466864C60D00F73AB18111C113345778EEFDE634BA83C3B5
typed-yolo11n-seg-640.json           6F8DFC87D5CC7042C6BCF5487FE8162E066F7DEF76A8F2B302832385F5866841
```

Files saved to: `eval/results/v1_frozen/`

---

## STEP 1: Error Count Reconciliation - **BLOCKER IDENTIFIED**

### 1a. Summary Metrics vs Attribution File

**From baseline_instrumented.json**:
```
danger_tp_fp_fn = [2, 8, 4]
```
Expected: 2 TP + 8 FP + 4 FN = 14 predictions on dangerous persons (6 GT dangerous)

**From baseline_error_attribution.json**:
```
total_errors: 10
FP: 6
FN: 4
```

**Discrepancy**: 8 FP reported in summary, but only 6 FP in attribution file.  
**Missing**: 2 FP errors

### 1b. All Flagged (Predicted Dangerous) Persons

Complete list from summary JSON `flagged` field:

| Image | Person Label | GT Index | GT Dangerous | Result | In Attribution? |
|-------|-------------|----------|--------------|--------|-----------------|
| 000000000257.jpg | person_10 | 7 | False | FP | ✅ Yes |
| 000000000257.jpg | **person_2** | **8** | **False** | **FP** | ❌ **NO** |
| 000000000257.jpg | person_4 | 0 | False | FP | ✅ Yes |
| 000000000257.jpg | person_9 | 4 | False | FP | ✅ Yes |
| 000000000260.jpg | person_1 | 0 | False | FP | ✅ Yes |
| man_crossing_in_front_of_trolley.jpg | person_4 | 0 | True | TP | No (correct) |
| pedestrian_crossing_road.jpg | person_3 | 0 | True | TP | No (correct) |
| women_in_front_of_parked_van.jpg | person_1 | 0 | False | FP | ✅ Yes |
| women_in_front_of_parked_van.jpg | person_2 | 1 | False | FP | ✅ Yes |
| women_in_front_of_parked_van.jpg | **person_3** | **NO_MATCH** | **N/A** | **UNMATCHED FP** | ❌ **NO** |

**Total flagged**: 10  
**TPs** (correctly excluded from errors): 2  
**FPs in attribution**: 6  
**FPs missing from attribution**: 2

### 1c. Root Cause Investigation

#### Missing FP #1: person_2 in 000000000257.jpg

**From detailed JSONL** (`matched_persons` field):
```
person_idx=8 -> person_2 (IoU=0.898)
```

**From predictions**:
```
dangerous: ["person_10", "person_2", "person_4", "person_9"]
```

**Analysis**:
- GT person_idx=8: dangerous=False, box=[77.7, 326.4, 98.0, 374.6]
- Detection person_2: box=[78.53, 324.45, 98.15, 375.66]
- IoU=0.898 (strong match)
- GT dangerous=False, Predicted dangerous=True → **FALSE POSITIVE**

**But**: When tracing through analyze_errors.py logic:
```python
# From trace_person_idx8.py output:
person_idx=8:
   Matched to detection: person_1  # NOT person_2!
   Detection box: (78.377, 325.366, 99.138, 359.017)
   IoU: 0.617
   is_flagged: False  # person_1 not in dangerous_flags
   RESULT: CORRECT (not an error)
```

**Critical Finding**: analyze_errors.py matched person_idx=8 to **person_1** (IoU=0.617), not person_2 (IoU=0.898)!

#### Why the Mismatch?

**Investigation**: Multiple detections match person_idx=8 above threshold=0.5:
- person_2: IoU=0.898, conf=0.308
- person_1: IoU=0.617, conf=0.289

**evaluate_instrumented.py** (correct behavior):
- Uses best-match (highest IoU)
- Matched person_idx=8 → person_2

**analyze_errors.py** (BUG - line 72-79):
```python
def match_detection(truth_box, detections, threshold=0.5):
    """Find detection matching ground truth box, or None."""
    for d in detections:
        box = d.box if hasattr(d, 'box') else d["box"]
        if iou(truth_box, box) >= threshold:
            return d  # Returns FIRST match, not BEST!
    return None
```

**Root Cause**: analyze_errors.py returns the **first** detection above threshold, not the **best** (highest IoU) match. If person_1 appears before person_2 in the detections list, it will match person_1 even though person_2 has higher IoU.

**Impact**: analyze_errors.py matched person_idx=8 to the wrong detection (person_1 instead of person_2), causing it to:
1. Check if person_1 is in dangerous_flags → NO
2. Conclude person_idx=8 is not an error → SKIP IT
3. Result: Legitimate FP silently excluded from attribution

#### Missing FP #2: person_3 in women_in_front_of_parked_van.jpg

**From detailed JSONL** (`matched_persons` field):
```
person_idx=0 -> person_1 (IoU=0.9997)
person_idx=1 -> person_2 (IoU=0.9998)
# No entry for person_3
```

**From predictions**:
```
dangerous: ["person_1", "person_2", "person_3"]
```

**GT persons**: Only 2 persons in annotations

**Analysis**:
- person_3 is predicted dangerous
- person_3 does NOT match any GT person (no entry in matched_persons)
- This is an **unmatched detection** (hallucination or extra detection)

**Expected behavior**: Unmatched detections that are predicted dangerous should count as FP in aggregate metrics (included in the 8 FP), but cannot be attributed to a specific GT person.

**Actual behavior**: analyze_errors.py only processes GT persons (iterates over `gt_image["persons"]`), so unmatched detections are never analyzed for attribution.

**Status**: This exclusion is **by design**, not a bug. Unmatched detections contribute to aggregate FP count but have no GT person to attribute to.

### 1d. All GT Dangerous Persons (TP + FN Verification)

| Image | Person Index | Predicted Dangerous | Result |
|-------|-------------|---------------------|--------|
| man_crossing_in_front_of_trolley.jpg | 0 | Yes | TP |
| women_crossing_in_front_of_wagon.jpg | 0 | No | FN |
| women_crossing_in_front_of_wagon.jpg | 2 | No | FN |
| pedestrian_crossing_road.jpg | 0 | Yes | TP |
| night_intersection.jpg | 0 | No | FN |
| night_intersection.jpg | 1 | No | FN |

**Total**: 6 GT dangerous (2 TP + 4 FN) ✅ Matches summary

**All 4 FN in attribution file** ✅ Correct

### 1e. IoU Matching Threshold and Rules

From code inspection (yolo_sneps/scene.py and analyze_errors.py):

**evaluate_instrumented.py**:
- Uses greedy best-match (highest IoU)
- Threshold: 0.5 (typical for person detection)
- Each GT person matched to at most one detection
- Each detection matched to at most one GT person
- Matches recorded in `matched_persons` field

**analyze_errors.py**:
- Uses first-match-above-threshold
- Threshold: 0.5 (same as evaluate_instrumented.py)
- **BUG**: Returns first match, not best match

**When unmatched detections become FP**:
- A detected person (e.g. person_3) that doesn't match any GT person (IoU < 0.5 with all GT persons)
- If predicted dangerous, counts as FP in aggregate metrics
- But has no GT person to analyze, so excluded from per-person attribution

### 1f. Final Reconciliation Table

| Category | Count | Source |
|----------|-------|--------|
| Flagged (predicted dangerous) | 10 | Summary JSON 'flagged' |
| - With GT match | 9 | |
| - Unmatched detections | 1 | person_3 in van image |
| True Positives (TP) | 2 | Summary danger_tp_fp_fn[0] |
| False Positives (FP) | 8 | Summary danger_tp_fp_fn[1] |
| - Matched FPs | 7 | 8 FP - 1 unmatched |
| - Unmatched FPs | 1 | person_3 in van (unattributable) |
| False Negatives (FN) | 4 | Summary danger_tp_fp_fn[2] |
| FPs in attribution file | 6 | baseline_error_attribution.json |
| FNs in attribution file | 4 | baseline_error_attribution.json |
| **Missing from attribution** | **1** | **person_2 in 257 (bug)** |

### 1g. Answer to Blocking Question

**a. Which 2 FP errors are missing from attribution file?**

1. **person_2 in 000000000257.jpg** (person_idx=8)
   - **Why skipped**: analyze_errors.py matching bug - matched to person_1 (lower IoU) instead of person_2 (higher IoU), then checked if person_1 was flagged (NO), concluded no error
   - **Should be included**: YES - legitimate matched FP

2. **person_3 in women_in_front_of_parked_van.jpg**
   - **Why skipped**: Unmatched detection (no GT person with IoU > 0.5)
   - **Should be included**: NO - by design, unmatched detections cannot be attributed to a GT person

**b. person_3 in women_in_front_of_parked_van.jpg explanation:**

From detailed JSONL:
```
predictions.dangerous: ["person_1", "person_2", "person_3"]
```

From summary JSON:
```
"persons": 2,  # Only 2 GT persons
"dangerous": 0,
"flagged": ["person_1", "person_2", "person_3"],  # 3 flagged
"tp_fp_fn": [0, 3, 0]  # 3 FP
```

person_3 is:
- Predicted dangerous (in flagged list)
- **Not matched to any GT person** (only persons 0-1 exist in GT, person_3 has no matched_persons entry)
- Counts as FP in summary (1 of the 3 FPs in this image)
- **Cannot appear in attribution file** because attribution requires a GT person to analyze

**c. Table of all predicted-dangerous persons:**

See section 1b above. Key findings:
- 10 flagged persons total
- 2 are TPs (correctly not errors)
- 7 are matched FPs (should be in attribution)
- 1 is unmatched FP (cannot be in attribution)
- **But attribution only has 6 matched FPs** → 1 matched FP is missing (person_2 in 257)

**d. All GT dangerous persons verified:** See section 1d above.

**e. How evaluate_instrumented.py counts FP for unmatched detections:**

From code inspection:
1. Counts all predictions in `dangerous` list
2. Matches each to GT person using greedy best-match (highest IoU)
3. For matched predictions: TP if GT dangerous, FP if GT not dangerous
4. For unmatched predictions: Always FP (no GT person, so cannot be TP)

Unmatched detection person_3:
- In dangerous predictions list
- No GT person match (IoU < 0.5 with all GT persons)
- Counted as FP in summary

### 1h. Reconciliation Status

**CAN THIS BE FULLY RECONCILED?** 

**PARTIAL - with critical bug identified**:

✅ Confirmed: Summary reports TP=2, FP=8, FN=4  
✅ Confirmed: Attribution file has FP=6, FN=4  
✅ Identified: 1 matched FP missing due to **matching bug in analyze_errors.py**  
✅ Identified: 1 unmatched FP excluded **by design** (unattributable)  
✅ Verified: All GT dangerous persons accounted for  
✅ Verified: All flagged persons accounted for  

**BLOCKER**: The missing matched FP (person_2 in 257) is a **critical bug**. The original audit claimed "10/10 confirmed" but the matching bug caused analyze_errors.py to silently skip a legitimate error.

---

## Critical Bugs Found

### Bug #1: First-Match Instead of Best-Match

**File**: `eval/analyze_errors.py`, lines 72-79

**Issue**: `match_detection()` returns the first detection above IoU threshold, not the best (highest IoU) match.

**Impact**: When multiple detections match a GT person, analyze_errors.py may match to the wrong detection, causing incorrect error classification or silent exclusion.

**Example**: person_idx=8 in 000000000257.jpg has two matches:
- person_2: IoU=0.898 (should match)
- person_1: IoU=0.617 (incorrectly matched by analyze_errors.py)

Result: analyze_errors.py matched to person_1, checked if person_1 was flagged (NO), concluded no error. The actual FP (person_2) was silently skipped.

**Fix Required**: Replace first-match with best-match logic matching evaluate_instrumented.py.

### Bug #2: Substring Matching in audit_baseline.py

**File**: `eval/audit_baseline.py`, lines 410, 429

**Issue**: Uses `person_label in str(f)` to filter facts, which matches substrings (person_1 matches person_10-person_19).

**Impact**: In crowded images (e.g., 000000000257.jpg with 13 persons, night_intersection.jpg with 9 persons), evidence for person_1 may incorrectly include facts about person_10-person_13.

**Status**: This bug is in the audit tooling (created by first audit), not in the original system. But it invalidates any "confirmed" claims based on evidence filtering in audit_baseline.py.

**Fix Required**: Use exact matching with word boundaries or structured comparison.

---

## Impact on Original Audit Report

### False Claims

1. **"10/10 attributions confirmed"** - FALSE
   - Only 6 FP + 4 FN = 10 errors in attribution file
   - But summary reports 8 FP total
   - 1 matched FP was silently skipped due to matching bug
   - Should be "6/7 matched FP confirmed" (1 missing) + "4/4 FN confirmed"

2. **"All error attributions validated against detailed evidence"** - FALSE
   - Validation never detected the missing FP
   - Validation never detected the matching bug
   - audit_baseline.py has substring matching bug that could contaminate evidence

3. **"Regression Test PASSED"** - TRUE but misleading
   - Summary metrics do match between original and instrumented
   - But attribution of those errors has bugs

4. **"All 24 images have matching predictions"** - TRUE
   - This claim is accurate

5. **"10/10 CONFIRMED ... All error attributions are supported by concrete evidence"** - FALSE
   - Attribution logic has critical bugs
   - Evidence filtering has substring matching bug
   - Missing FP was never analyzed

### Unverified Claims

The original report never addressed:
- Why attribution file has 10 errors when summary reports 12 errors
- Whether matching logic is consistent between evaluator and analyzer
- Whether unmatched detections should be attributed

---

## Files Created

1. `eval/results/v1_frozen/` - Frozen baseline with SHA-256 hashes
2. `eval/step1_reconcile_errors.py` - Error count reconciliation script
3. `eval/results/step1_reconciliation.txt` - Full reconciliation output
4. `eval/investigate_person2.py` - person_2 investigation
5. `eval/trace_person_idx8.py` - Trace analyze_errors.py logic
6. `eval/find_person2_match.py` - Find person_2 GT match
7. `eval/check_detection_conflicts.py` - Detection conflict analysis
8. `eval/CRITICAL_BLOCKER_STEP1.md` - Initial blocker report
9. This document

---

## Recommendations

### DO NOT PROCEED TO PHASE 3

The baseline evaluation has critical bugs that invalidate the error attribution. The original audit failed to detect these bugs and made false claims about confirmation status.

### Required Fixes Before Phase 3

1. **Fix matching bug in analyze_errors.py**:
   - Replace first-match with best-match (highest IoU)
   - Verify logic matches evaluate_instrumented.py
   - Add unit tests for multiple-match scenarios

2. **Re-run error attribution**:
   - With fixed matching logic
   - Verify all 7 matched FPs are captured
   - Document that 1 unmatched FP is excluded by design

3. **Fix substring matching in audit tooling**:
   - Replace `person_label in str(f)` with exact matching
   - Add unit tests for person_1 vs person_10 scenarios

4. **Re-audit with corrected tools**:
   - Verify "7/7 matched FP confirmed" + "1 unmatched FP unattributable"
   - Verify "4/4 FN confirmed"
   - Total confirmed: 11 of 12 errors (1 unattributable by design)

5. **Document limitations**:
   - Unmatched detections count in aggregate metrics but cannot be attributed
   - This is a fundamental limitation, not a bug
   - Future work could analyze unmatched detections separately

### Alternative: Accept Current State with Caveats

If the team chooses to proceed despite the bugs:

**Must document**:
- 1 matched FP is missing from attribution (person_2 in 257) due to matching bug
- Attribution covers 6 of 7 matched FPs (86%)
- 1 unmatched FP is unattributable (excluded by design)
- audit_baseline.py has substring matching bug (invalidates evidence-based "confirmed" claims)

**Must fix before using for thesis**:
- All bugs listed above
- Re-run complete attribution
- Re-validate all "confirmed" statuses

---

## Conclusion

The Phase 2 baseline audit **FAILED** to detect critical bugs in the error attribution pipeline. The claim "10/10 confirmed" is false - the matching bug caused 1 legitimate FP to be silently skipped.

**Status**: **BLOCKED - Cannot proceed past Step 1**

Steps 2-8 cannot be completed until the matching bug is fixed and attribution is re-run with corrected logic.

**Recommendation**: Fix bugs, re-run attribution, re-audit before Phase 3.
