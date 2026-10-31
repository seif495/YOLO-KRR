# CRITICAL BLOCKER IDENTIFIED IN STEP 1

**Date**: 2026-10-23  
**Task**: Audit of Phase 2 Baseline Audit  
**Status**: **BLOCKED - Cannot proceed past Step 1**

---

## Executive Summary

The Phase 2 baseline audit claimed "10/10 attributions confirmed" and "PASS, proceed with Phase 3". However, **Step 1 reconciliation reveals a critical accounting error**:

- **Summary metrics report**: 8 FP + 4 FN = 12 errors
- **Attribution file contains**: 6 FP + 4 FN = 10 errors  
- **Missing**: 2 FP errors + 2 TP cases (not errors but absent from analysis)

The missing items are NOT "unmatched detections" as initially hypothesized. They include:
1. **person_2 in 000000000257.jpg** - matched to GT person index 8, GT dangerous=False → **legitimate FP**
2. **person_3 in women_in_front_of_parked_van.jpg** - unmatched detection → counts as FP in summary
3. **person_4 in man_crossing_in_front_of_trolley.jpg** - GT dangerous=True, predicted dangerous → **TP (not an error, but excluded from error attribution as designed)**
4. **person_3 in pedestrian_crossing_road.jpg** - GT dangerous=True, predicted dangerous → **TP (not an error, but excluded)**

**The 2 TPs are correctly excluded from error attribution** (analyze_errors.py only reports errors, not correct predictions).

**BUT**: person_2 in 000000000257.jpg is a **legitimate FP that was silently dropped** from the attribution file.

---

## Detailed Findings

### Reconciliation Table (from step1_reconcile_errors.py output)

```
Category                       Count      Source
--------------------------------------------------------------------------------
Flagged (predicted dangerous)  10         Summary JSON 'flagged'
  - With GT match              9         
  - Unmatched detections       1         
True Positives (TP)            2          Summary danger_tp_fp_fn[0]
False Positives (FP)           8          Summary danger_tp_fp_fn[1]
False Negatives (FN)           4          Summary danger_tp_fp_fn[2]
FPs in attribution file        6          baseline_error_attribution.json
FNs in attribution file        4          baseline_error_attribution.json
Missing from attribution       4          Flagged - In attribution
```

### All Flagged Persons Cross-Reference

| Image | Person Label | GT Index | GT Dangerous | Result | In Attribution? |
|-------|-------------|----------|--------------|--------|-----------------|
| 000000000257.jpg | person_10 | 7 | False | FP | ✓ Yes |
| 000000000257.jpg | person_2 | 8 | False | FP | ❌ **NO** |
| 000000000257.jpg | person_4 | 0 | False | FP | ✓ Yes |
| 000000000257.jpg | person_9 | 4 | False | FP | ✓ Yes |
| 000000000260.jpg | person_1 | 0 | False | FP | ✓ Yes |
| man_crossing_in_front_of_trolley.jpg | person_4 | 0 | True | TP | No (correct - not an error) |
| pedestrian_crossing_road.jpg | person_3 | 0 | True | TP | No (correct - not an error) |
| women_in_front_of_parked_van.jpg | person_1 | 0 | False | FP | ✓ Yes |
| women_in_front_of_parked_van.jpg | person_2 | 1 | False | FP | ✓ Yes |
| women_in_front_of_parked_van.jpg | person_3 | NO_MATCH | N/A | UNMATCHED FP | ❌ **NO** (expected - no GT person) |

### All GT Dangerous Persons (TP + FN verification)

| Image | Person Index | Predicted Dangerous | Result |
|-------|-------------|---------------------|--------|
| man_crossing_in_front_of_trolley.jpg | 0 | Yes | TP |
| women_crossing_in_front_of_wagon.jpg | 0 | No | FN |
| women_crossing_in_front_of_wagon.jpg | 2 | No | FN |
| pedestrian_crossing_road.jpg | 0 | Yes | TP |
| night_intersection.jpg | 0 | No | FN |
| night_intersection.jpg | 1 | No | FN |

Total: 6 GT dangerous (2 TP + 4 FN) ✓ Matches summary

---

## Root Cause Analysis

### Why is person_2 in 000000000257.jpg missing?

**Investigation needed**: This person is:
- Matched to GT person index 8
- GT dangerous = False
- Predicted dangerous (in flagged list)
- Legitimate false positive
- Has GT pairs defined
- **Should appear in attribution file but doesn't**

**Hypothesis**: Either:
1. A bug in analyze_errors.py that skipped this person
2. The person label in detailed JSONL doesn't match summary JSON flagged list
3. The matching logic failed to find this person

### Why is person_3 in women_in_front_of_parked_van.jpg missing?

**Expected**: This is an unmatched detection (no GT person with IoU > threshold). analyze_errors.py only processes matched GT persons, so this is correctly excluded from per-person attribution. However, it's still counted as an FP in the summary because the system predicted it dangerous.

**This is a limitation of the error attribution design**: Unmatched detections (hallucinations) are counted in aggregate metrics but cannot be attributed to a specific GT person.

---

## Questions for Step 2 (cannot proceed until Step 1 resolved)

The original plan was to investigate whether the system "needs GT pairs to evaluate danger". However, **we cannot proceed to Step 2 until the accounting error in Step 1 is resolved**.

Step 2 questions depend on having a complete and accurate error list. With person_2 in 000000000257.jpg missing from attribution, we don't have a complete picture.

---

## Impact on Original Audit Report

The original BASELINE_AUDIT_REPORT.md claimed:

> "✅ **10/10 CONFIRMED** ... All error attributions validated against detailed evidence."

This claim is **FALSE** because:
1. The report validated 10 errors, but the summary says there are 12 errors (8 FP + 4 FN)
2. One of the missing errors (person_2 in 257) is a matched FP that should have been analyzed
3. The report never identified or explained this discrepancy

The report's conclusion:

> "**Ready for Phase 3**: Annotation expansion with quality controls in place."

This conclusion is **PREMATURE** because the error count reconciliation was never performed, and a legitimate FP was silently excluded from analysis.

---

## Blocker Statement

**BLOCKED**: Cannot proceed with Steps 2-8 until Step 1 is fully resolved.

**Required for unblocking**:
1. Identify why person_2 in 000000000257.jpg was excluded from attribution
2. Re-run error attribution with fix
3. Verify that all 8 FPs (or 7 matched FPs + 1 unmatched) are accounted for
4. Document whether unmatched detections should be attributed or excluded by design

**Alternative path**: If the audit team determines that:
- The 2 TPs should not be in attribution (correct by design)
- The 1 unmatched detection should not be in attribution (acceptable limitation)
- BUT the 1 missing matched FP (person_2 in 257) is a bug

Then the blocker can be resolved by fixing that bug and re-running attribution, resulting in 7 FP + 4 FN = 11 errors attributed (with 1 unmatched FP documented as unattributable).

---

## Files Created

1. `eval/step1_reconcile_errors.py` - Analysis script
2. `eval/results/step1_reconciliation.txt` - Full output
3. `eval/results/v1_frozen/` - Frozen baseline files with hashes
4. This document

---

## Recommendation

**DO NOT PROCEED TO PHASE 3** until:
1. Step 1 accounting error is fully resolved
2. analyze_errors.py is debugged and fixed
3. Complete error attribution is re-generated
4. A revised audit report documents the actual error counts

The current baseline audit cannot be trusted because it missed a fundamental accounting error and claimed "10/10 confirmed" when the summary itself reports 12 errors.
