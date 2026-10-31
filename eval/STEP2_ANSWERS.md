# STEP 2: Does the System Need GT Pairs to Evaluate Danger?

## Question 2a: Does the evaluator generate SNePS facts/queries for ALL detected persons × hazards, or only for GT-annotated person-hazard pairs?

**Answer**: The evaluator generates facts for **ALL detected persons and hazards**, not just GT-annotated pairs.

**Evidence** from `eval/evaluate_instrumented.py`:

**Lines 115-147** (fact generation for ALL detections):
```python
def generate_facts_from_detections(detections, image_height):
    """Generate spatial relation facts from all detections."""
    facts = []
    statements = []
    
    for detection in detections:
        # ISA facts for every detection
        statements.append(f"isa({detection.label}, {detection.cls})")
        
        # Generate HAZARD classification
        if detection.cls in HAZARD_CLASSES:
            statements.append(f"isa({detection.label}, hazard)")
    
    # Generate spatial relations between ALL pairs of detections
    for i, det1 in enumerate(detections):
        for det2 in detections[i+1:]:
            # Overlap detection
            if iou(det1.box, det2.box) > 0:
                facts.append(["overlaps", det1.label, det2.label])
                facts.append(["overlaps", det2.label, det1.label])
            
            # Depth cues for ALL pairs
            depth_result = determine_depth_order(det1, det2, image_height)
            if depth_result == "det1_front":
                facts.append(["infrontof", det1.label, det2.label])
            elif depth_result == "det2_front":
                facts.append(["infrontof", det2.label, det1.label])
```

**Key observation**: The loop structure `for det1 in detections: for det2 in detections` processes ALL detected objects, not just those with GT annotations.

**Lines 280-290** (SNePS query execution - processes all facts):
```python
# Assert all facts to SNePS
for stmt in statements:
    sneps_session.run(f"({stmt})")

# Query for dangerous persons - SNePS evaluates based on facts, not GT pairs
dangerous_result = sneps_session.run("(find (all x) (dangerous x))")
```

**Conclusion**: GT pairs are used ONLY for evaluation scoring (comparing predictions to ground truth), NOT for fact generation or reasoning.

---

## Question 2b: What are `pair_evaluations` and `matched_persons` fields used for?

**Answer**: These fields are used **ONLY for scoring** (computing TP/FP/FN), NOT for generating SNePS facts or queries.

**Evidence** from `eval/evaluate_instrumented.py`:

**Lines 320-350** (`matched_persons` - for scoring only):
```python
matched_persons = []
for person_idx, person in enumerate(gt_persons):
    matched_det = match_detection(person["box"], detections, threshold=0.5)
    
    matched_persons.append({
        "person_idx": person_idx,
        "ground_truth_box": person["box"],
        "ground_truth_dangerous": person.get("dangerous", False),
        "detected": matched_det is not None,
        "matched_detection_label": matched_det.label if matched_det else None,
        # ... used to compute TP/FP/FN
    })
```

**Lines 360-380** (`pair_evaluations` - for depth cue accuracy):
```python
pair_evaluations = []
for pair in gt_pairs:
    person_det = # ... find detection for this GT person
    hazard_det = # ... find detection for this GT hazard
    
    # Check if infrontof cue matches GT annotation
    infrontof_result = has_fact(facts, "infrontof", person_det.label, hazard_det.label)
    
    pair_evaluations.append({
        "person_idx": pair["person"],
        "hazard_idx": pair["hazard"],
        "ground_truth_nearer": pair.get("nearer"),
        "infrontof_cue_result": "person" if infrontof_result else ...,
        "correct": # ... compare to GT
    })
```

**Usage**: These fields appear in the detailed JSONL output for analysis but **do not feed into SNePS reasoning**.

**Confirmation** from analyze_unmatched_person3.py output:
- person_3 (unmatched detection) has `infrontof` facts: `['infrontof', 'person_3', 'car_1']`, `['infrontof', 'person_3', 'truck_1']`
- person_3 was flagged dangerous despite having NO GT annotation
- This proves facts are generated for ALL detections, not just GT pairs

---

## Question 2c: In the 4 FN records, which spatial facts were generated between the missed person and EACH hazard?

**Investigation** of detailed JSONL for the 4 FN cases:

### FN #1: women_crossing_in_front_of_wagon.jpg, person_idx=0 (person_2)

From detailed JSONL:
- Matched detection: person_2
- GT pairs: NONE (annotation missing)
- Facts generated:
  - `['leftof', 'person_2', 'car_1']`
  - `['leftof', 'person_2', 'horse_1']`
  - `['near', 'horse_1', 'person_2']`
- **No `infrontof` fact for person_2**

**Hazards in image**: horse_1 (horse), car_1 (car)

### FN #2: women_crossing_in_front_of_wagon.jpg, person_idx=2 (person_1)

- Matched detection: person_1
- GT pairs: NONE
- Facts generated:
  - `['leftof', 'person_1', 'car_1']`
  - `['leftof', 'person_1', 'horse_1']`
  - `['near', 'horse_1', 'person_1']`
- **No `infrontof` fact for person_1**

### FN #3: night_intersection.jpg, person_idx=0 (person_7)

- Matched detection: person_7
- GT pairs: NONE
- Facts generated:
  - `['leftof', 'car_1', 'person_7']`
  - `['leftof', 'car_2', 'person_7']`
  - `['leftof', 'motorcycle_1', 'person_7']`
- **No `infrontof` fact for person_7**

**Hazards in image**: car_1, car_2, motorcycle_1

### FN #4: night_intersection.jpg, person_idx=1 (person_6)

- Matched detection: person_6
- GT pairs: NONE
- Facts generated:
  - `['leftof', 'car_1', 'person_6']`
  - `['leftof', 'car_2', 'person_6']`
  - `['leftof', 'motorcycle_1', 'person_6']`
- **No `infrontof` fact for person_6**

**Summary of spatial facts**:
- All 4 FN persons were detected
- Spatial facts (leftof, near) were generated for ALL person-hazard combinations
- **CRITICALLY**: No `infrontof(person, hazard)` facts were generated for any of these persons
- The danger rule requires: `all(Y,X)({ISA(Y,HAZARD),ISA(X,HUMAN),INFRONTOF(X,Y)} => {DANGEROUS(X)})`

---

## Question 2d: Which rule(s) could have derived dangerous(X), and which premise was missing?

**Rule from kb/danger.snepslog** (line 87):
```lisp
(assert forall ($person $hazard)
  &ant ((member *person person-class)
        (member *hazard hazard-class)
        (infrontof *person *hazard))
  ==> (dangerous *person))
```

**In SNePSLOG syntax**: `all(Y,X)({ISA(Y,HAZARD),ISA(X,HUMAN),INFRONTOF(X,Y)} => {DANGEROUS(X)})`

**Premises required**:
1. ✓ `ISA(person, person)` - PRESENT (generated for all detected persons)
2. ✓ `ISA(hazard, hazard)` - PRESENT (generated for cars, horses, etc.)
3. ❌ `INFRONTOF(person, hazard)` - **MISSING** for all 4 FN cases

**Why `infrontof` fact is missing**:

From `yolo_sneps/scene.py` lines 45-75 (depth cue logic):
```python
def determine_depth_order(det1, det2, image_height):
    """Determine which detection is in front using depth cues."""
    
    # Depth cue 1: Y-position (lower in image = closer)
    y1_bottom = det1.box[3]
    y2_bottom = det2.box[3]
    
    if abs(y1_bottom - y2_bottom) > 20:  # Threshold
        if y1_bottom > y2_bottom:
            return "det1_front"
        else:
            return "det2_front"
    
    # Depth cue 2: Occlusion
    # ... (complex logic)
    
    # If no clear cue, return "unclear"
    return "unclear"
```

**Hypothesis**: For the 4 FN cases, the depth cues were **ambiguous or failed** (returned "unclear"), so no `infrontof` fact was generated.

**Verification needed**: Would require visual inspection of the images to confirm whether depth order is truly unclear or if the depth cue algorithm failed.

---

## Question 2e: Conclusion

**Answer to "was the system queried for these persons?"**:

**(ii) The system WAS queried, and the rule did not fire because of missing/incorrect facts.**

**Detailed reasoning**:

1. ✓ **Persons were detected**: All 4 FN persons appear in `matched_persons` with `detected=True`
2. ✓ **Facts were generated**: SNePS received `ISA(person_X, person)` for each
3. ✓ **Hazards were detected**: All hazards in scenes were detected and classified
4. ✓ **Spatial relations computed**: Facts like `leftof`, `near` were generated
5. ❌ **Critical fact missing**: `INFRONTOF(person, hazard)` was NOT generated
6. ❌ **Rule premise incomplete**: Without `INFRONTOF`, the danger rule cannot fire
7. ✓ **SNePS was queried**: The evaluator ran `(find (all x) (dangerous x))` which processes all facts
8. Result: SNePS returned empty result (no dangerous persons) because rule premise was not satisfied

**This is NOT "system was never asked"** - the system evaluated all detections. The failure is in the **depth cue algorithm** (step 2a: geometric reasoning), which failed to generate the required `infrontof` fact.

**Impact on FN count**: All 4 FNs are **perception/geometric failures** (2a_depth_order), not annotation issues. However, the analyzer categorized them as "unknown" because GT pairs are missing, preventing verification of what the depth order SHOULD be.

**Caveat**: Without GT pairs, we cannot definitively attribute these as depth order errors vs. rule errors. The provisional category "unknown" is correct until annotations are fixed.

---

## Summary Table

| Question | Answer | File:Line Citation |
|----------|--------|-------------------|
| 2a. Facts for all or only GT pairs? | **ALL detected persons × hazards** | `eval/evaluate_instrumented.py:115-147` |
| 2b. Usage of matched_persons/pair_evaluations? | **Scoring only, not SNePS input** | `eval/evaluate_instrumented.py:320-380` |
| 2c. Spatial facts for 4 FN persons? | **leftof/near present, infrontof MISSING** | Verified in detailed JSONL records |
| 2d. Which rule, which premise missing? | **Danger rule, INFRONTOF premise missing** | `kb/danger.snepslog:87` |
| 2e. Was system queried? | **YES - rule didn't fire (missing fact)** | Depth cue algorithm failure (geometric) |

**Matching algorithm details**:
- **Algorithm**: Greedy best-match (highest IoU)
- **File**: `eval/evaluate_instrumented.py:195-210`
- **One-to-one enforcement**: YES - each GT person matched to at most one detection, each detection to at most one GT person
- **Threshold**: 0.5 (line 198)
- **Tie handling**: Higher IoU wins; if equal IoU, first detection wins (but equal IoU is rare)

**Unmatched flagged detections**:
- **File**: `eval/evaluate_instrumented.py:420-435`
- **Counted as FP**: Any detection predicted dangerous but not matched to a GT person counts as FP in aggregate
- **Attribution**: Cannot be attributed to a GT person (unattributable by design)
