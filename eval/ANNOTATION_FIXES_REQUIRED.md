# Annotation Fixes Required

**Date**: 2026-10-23  
**Source**: Baseline Audit Report  
**Priority**: HIGH (blocking Phase 3)  
**Estimated Time**: 15-30 minutes

---

## Summary

4 missing person-hazard pairs identified across 2 images. All involve dangerous persons that have no hazard associations, making it impossible for the system to evaluate their danger level.

**DO NOT apply these fixes automatically.** Each fix requires visual inspection to verify:
1. The hazard identification is correct
2. The depth order (`nearer` field) is accurately determined
3. No other persons should be marked dangerous in the scene

---

## Image 1: `women_crossing_in_front_of_wagon.jpg`

### Current Annotation

```json
{
  "source": "examples",
  "file": "women_crossing_in_front_of_wagon.jpg",
  "persons": [
    {"box": [428.1, 519.3, 584.6, 851.7], "dangerous": true},   // person 0 ← NO PAIRS
    {"box": [1068.1, 462.1, 1104.4, 545.2], "dangerous": false},  // person 1
    {"box": [281.0, 505.1, 398.8, 831.5], "dangerous": true},    // person 2 ← NO PAIRS
    {"box": [1137.8, 479.5, 1163.8, 545.8], "dangerous": false},  // person 3
    {"box": [1120.3, 476.4, 1142.5, 540.8], "dangerous": false},  // person 4
    {"box": [1138.6, 481.7, 1169.0, 554.2], "dangerous": false}   // person 5
  ],
  "hazards": [
    {"class": "horse", "box": [616.5, 453.5, 876.2, 804.7]},  // hazard 0
    {"class": "car", "box": [926.1, 494.9, 1085.8, 566.4]}    // hazard 1
  ],
  "pairs": [
    {"person": 1, "hazard": 1, "nearer": "unclear"}  // Only 1 pair (wrong person!)
  ]
}
```

### Visual Context

Scene: Two women crossing a street in front of a horse-drawn wagon. The wagon is moving (or about to move). The women are in the roadway directly in the wagon's path.

- **Person 0** (box: [428.1, 519.3, 584.6, 851.7]): Woman on right side, crossing in front of wagon
- **Person 2** (box: [281.0, 505.1, 398.8, 831.5]): Woman on left side, crossing in front of wagon
- **Hazard 0** (horse, box: [616.5, 453.5, 876.2, 804.7]): Horse pulling the wagon

### Required Fixes

**Add 2 pairs:**

```json
{
  "person": 0,
  "hazard": 0,
  "nearer": "person"
}
```
**Rationale**: Person 0 is crossing in front of the horse-drawn wagon. Visually, the woman appears to be in front of (nearer to camera than) the horse.

```json
{
  "person": 2,
  "hazard": 0,
  "nearer": "person"
}
```
**Rationale**: Person 2 is also crossing in front of the wagon. Both women are in the roadway in front of the moving hazard.

### Verification Steps

1. Open `examples/women_crossing_in_front_of_wagon.jpg` in image viewer
2. Verify persons 0 and 2 are the two women crossing
3. Verify hazard 0 (horse) is the primary threat
4. Confirm depth order: Are the women in front of the horse? (YES)
5. If depth order is ambiguous, use `"nearer": "unclear"` instead

### Alternative Consideration

**Question**: Should these persons also have pairs with hazard 1 (car)?
- **Visual inspection needed**: Is the car moving? Is it in their path?
- **Current assessment**: No evidence the car is a threat (appears parked in background)
- **Recommendation**: Add only horse pairs for now, can expand if visual review shows car involvement

---

## Image 2: `night_intersection.jpg`

### Current Annotation

```json
{
  "source": "examples",
  "file": "night_intersection.jpg",
  "persons": [
    {"box": [1091.1, 553.5, 1158.3, 734.2], "dangerous": true},  // person 0 ← NO PAIRS
    {"box": [1005.5, 537.7, 1061.6, 663.1], "dangerous": true},  // person 1 ← NO PAIRS
    {"box": [1227.7, 544.5, 1276.8, 680.1], "dangerous": false}, // person 2
    {"box": [757.2, 551.2, 841.0, 720.1], "dangerous": false},   // person 3
    {"box": [896.9, 548.4, 938.6, 655.8], "dangerous": false},   // person 4
    {"box": [675.6, 543.9, 701.2, 611.7], "dangerous": false},   // person 5
    {"box": [693.0, 545.8, 753.5, 639.3], "dangerous": false},   // person 6
    {"box": [844.8, 539.5, 874.9, 608.6], "dangerous": false},   // person 7
    {"box": [1262.3, 543.8, 1279.5, 684.2], "dangerous": false}  // person 8
  ],
  "hazards": [
    {"class": "car", "box": [0.2, 566.4, 543.0, 813.2]},      // hazard 0
    {"class": "motorcycle", "box": [670.4, 606.5, 915.4, 749.6]}, // hazard 1
    {"class": "car", "box": [321.6, 555.1, 529.2, 643.5]}     // hazard 2
  ],
  "pairs": [
    {"person": 3, "hazard": 1, "nearer": "unclear"},
    {"person": 4, "hazard": 1, "nearer": "hazard"},
    {"person": 5, "hazard": 1, "nearer": "hazard"},
    {"person": 6, "hazard": 1, "nearer": "unclear"},
    {"person": 7, "hazard": 1, "nearer": "hazard"}
    // All pairs for persons 3-7 with motorcycle, but NONE for persons 0-1 (dangerous!)
  ]
}
```

### Visual Context

Scene: Night intersection with 9 pedestrians. Persons 0 and 1 appear to be crossing or in the roadway, making them vulnerable to oncoming traffic.

- **Person 0** (box: [1091.1, 553.5, 1158.3, 734.2]): Pedestrian on right side of image
- **Person 1** (box: [1005.5, 537.7, 1061.6, 663.1]): Pedestrian near person 0
- **Hazard 0** (car, box: [0.2, 566.4, 543.0, 813.2]): Large car on left side
- **Hazard 2** (car, box: [321.6, 555.1, 529.2, 643.5]): Smaller car in center

### Required Fixes

**⚠️  VISUAL INSPECTION REQUIRED** - The correct hazard and depth order are unclear without viewing the image.

**Option A**: Persons 0-1 are crossing in front of hazard 0 (large car on left)
```json
{"person": 0, "hazard": 0, "nearer": "person"},
{"person": 1, "hazard": 0, "nearer": "person"}
```

**Option B**: Persons 0-1 are crossing in front of hazard 2 (center car)
```json
{"person": 0, "hazard": 2, "nearer": "person"},
{"person": 1, "hazard": 2, "nearer": "person"}
```

**Option C**: Depth order is ambiguous
```json
{"person": 0, "hazard": 0, "nearer": "unclear"},
{"person": 1, "hazard": 0, "nearer": "unclear"}
```

**Option D**: Multiple hazards involved (persons crossing between cars)
```json
{"person": 0, "hazard": 0, "nearer": "person"},
{"person": 0, "hazard": 2, "nearer": "unclear"},
{"person": 1, "hazard": 0, "nearer": "person"},
{"person": 1, "hazard": 2, "nearer": "unclear"}
```

### Verification Steps

1. Open `examples/night_intersection.jpg` in image viewer
2. Locate persons 0 and 1 using bounding box coordinates
3. Identify which hazard(s) they are near or crossing in front of
4. Determine depth order (are persons in front of hazard, behind, or unclear?)
5. Choose appropriate option (A, B, C, or D) based on visual evidence
6. Add corresponding pair(s) to annotation

### Critical Questions for Visual Review

1. **Why are persons 0 and 1 marked dangerous?**
   - Are they crossing the street?
   - Are they in a vehicle's path?
   - Is there approaching traffic?

2. **Which hazard poses the threat?**
   - Hazard 0 (large car on left)?
   - Hazard 2 (center car)?
   - Both?
   - Or was the dangerous marking incorrect?

3. **What is the depth order?**
   - Are the persons clearly in front of the hazard(s)?
   - Are they behind or beside the hazard(s)?
   - Is the depth order ambiguous in this night scene?

**If the dangerous marking appears incorrect upon visual review**, consider:
- Changing `"dangerous": true` to `"dangerous": false` for persons 0 and/or 1
- Documenting the rationale for the change

---

## Validation After Fixes

After applying fixes to `eval/annotations.json`, run these checks:

### 1. Schema Validation
```powershell
cd C:\Users\DELL\PycharmProjects\YOLO-KRR
.\.venv\Scripts\python.exe eval/audit_baseline.py
```

**Expected Output**:
```
--- Dangerous Persons Without Pairs ---
✅ All dangerous persons have at least one hazard pair
```

### 2. Re-run Error Attribution
```powershell
cd C:\Users\DELL\PycharmProjects\YOLO-KRR
.\.venv\Scripts\python.exe eval/analyze_errors.py `
    eval/results/baseline_instrumented_detailed.jsonl `
    --annotations eval/annotations.json `
    --output eval/results/baseline_error_attribution_fixed.json
```

**Expected Changes**:
- FN "unknown" count should drop (from 4 to 0 or lower)
- New FN categories may appear:
  - `2a_depth_order` (if system got depth order wrong)
  - `3a_missing_facts` (if system didn't generate required spatial facts)
  - `4a_wrong_inference` (if system generated facts but didn't infer danger)

### 3. Compare Attribution Changes
```powershell
cd C:\Users\DELL\PycharmProjects\YOLO-KRR
.\.venv\Scripts\python.exe -c "
import json

original = json.load(open('eval/results/baseline_error_attribution.json'))
fixed = json.load(open('eval/results/baseline_error_attribution_fixed.json'))

print('Original FN unknown:', len([e for e in original['errors'] if e['type'] == 'FN' and e['category'] == 'unknown']))
print('Fixed FN unknown:', len([e for e in fixed['errors'] if e['type'] == 'FN' and e['category'] == 'unknown']))
print()
print('Fixed error categories:')
for cat, count in fixed['summary']['by_category'].items():
    print(f'  {cat}: {count}')
"
```

---

## Post-Fix Documentation

After applying and validating fixes, document:

1. **Which option was chosen** for `night_intersection.jpg` (A, B, C, or D)
2. **Rationale** based on visual inspection
3. **New error categories** that emerged after fixes
4. **Lessons learned** for Phase 3 annotation protocol

Update `BASELINE_AUDIT_REPORT.md` with:
- Fixes applied (with date and annotator)
- Re-audit results showing 0 annotation issues
- Updated error attribution summary

---

## Annotation Protocol Improvements

Based on these findings, update `ANNOTATION_GUIDELINES.md` with:

### Mandatory Checklist

For every image annotation:
- [ ] All persons identified and labeled
- [ ] All hazards identified and labeled
- [ ] All **dangerous persons** have ≥1 hazard pair
- [ ] All pairs have `nearer` field (`"person"`, `"hazard"`, or `"unclear"`)
- [ ] Depth order matches visual inspection
- [ ] If dangerous person has NO pairs → either add pairs OR change `dangerous: false`

### Common Errors to Avoid

1. ❌ Marking person dangerous without defining hazard pairs
2. ❌ Defining pairs for non-dangerous persons but forgetting dangerous ones
3. ❌ Using wrong person index in pair (e.g., person 1 instead of person 0)
4. ❌ Guessing depth order without visual verification

### Quality Gates

Before accepting annotation:
1. **Automated check**: Run validation script
2. **Peer review**: Second annotator verifies dangerous-person pairs
3. **Spot check**: Sample random annotations for depth order accuracy

---

## Files to Modify

1. **Primary**: `eval/annotations.json`
   - Add 2 pairs to `women_crossing_in_front_of_wagon.jpg`
   - Add 2+ pairs to `night_intersection.jpg` (after visual verification)

2. **Optional**: Re-generate instrumented evaluation (if you want updated detailed records)
   - Re-run `eval/evaluate_instrumented.py` with fixed annotations
   - This will update `matched_persons` and `pair_evaluations` fields

3. **Documentation**: Update `BASELINE_AUDIT_REPORT.md`
   - Add "Fixes Applied" section with date and changes
   - Update recommendation from "Fix issues" to "Issues fixed, proceeding to Phase 3"

---

## Estimated Impact

**Before Fixes**:
- Dangerous persons without pairs: 4 (100%)
- FN errors attributed to "unknown": 4 (100%)

**After Fixes** (expected):
- Dangerous persons without pairs: 0 (0%)
- FN errors attributed to "unknown": 0-1 (0-25%)
- FN errors with specific categories: 3-4 (75-100%)

**Benefit**: Enables meaningful error analysis for false negatives, revealing whether the errors are due to:
- Perception failures (person not detected)
- Geometric reasoning failures (depth order wrong)
- Knowledge representation failures (facts not generated)
- Reasoning failures (rule didn't fire)

Currently, all 4 FN errors are "unknown" because the system was never asked to evaluate them.

---

## Contact for Questions

If unsure about:
- Which hazard to associate with dangerous persons
- Whether depth order is truly ambiguous
- Whether a person should actually be marked dangerous

**Options**:
1. Use `"nearer": "unclear"` as a conservative choice
2. Add multiple pairs (person with multiple hazards) if scenario is complex
3. Document the ambiguity in a comment and proceed
4. Escalate to primary annotator or domain expert

**Remember**: It's better to mark depth order as "unclear" than to guess incorrectly. The system can handle ambiguity; it cannot handle missing data.
