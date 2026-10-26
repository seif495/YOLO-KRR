# Error Attribution Taxonomy
## Separating Perception from Reasoning Failures

This document defines a systematic framework for classifying evaluation errors to understand whether failures originate in computer vision (YOLO) or knowledge representation and reasoning (SNePS).

---

## Core Principle

**Question**: When the system fails to correctly classify a pedestrian as dangerous/safe, what went wrong?

The answer matters for research: If 90% of errors trace to YOLO missing pedestrians, improving the knowledge representation won't help. Conversely, if YOLO detects everything correctly but the rules produce wrong conclusions, the CV–KRR integration needs work.

---

## Error Categories

### 1. Object Detection Failure (Perception)

**Definition**: YOLO fails to produce necessary visual information.

#### 1a. Missing Person Detection
- **What happened**: A person visible to human annotator is not detected by YOLO
- **Impact**: System cannot reason about an object it doesn't know exists
- **Example**: Distant pedestrian not detected (confidence below threshold)
- **Evidence**: Person in ground truth, absent from YOLO output
- **Responsibility**: Computer vision (perception failure)

#### 1b. Missing Vehicle Detection
- **What happened**: A vehicle/hazard is not detected
- **Impact**: No hazard to reason about, cannot infer danger
- **Example**: Parked car in shadow not detected
- **Evidence**: Hazard in ground truth, absent from YOLO output
- **Responsibility**: Computer vision

#### 1c. Wrong Classification
- **What happened**: YOLO detects object but assigns wrong class
- **Impact**: Rules may not fire (e.g., "truck" detected as "car" still works, but "person" as "backpack" fails)
- **Example**: Child classified as "backpack", motorcycle as "bicycle"
- **Evidence**: Detection present, class label incorrect
- **Responsibility**: Computer vision

#### 1d. Poor Localization
- **What happened**: Object detected, class correct, but bounding box significantly misplaced
- **Impact**: Geometric relations computed on wrong positions (affects infrontof accuracy)
- **Example**: Person box shifted 20 pixels right, appears beside vehicle instead of in front
- **Evidence**: IoU between detected box and ground truth box < 0.5
- **Responsibility**: Computer vision

---

### 2. Geometric Estimation Failure (Perception-to-KR Interface)

**Definition**: Detection succeeded, but spatial relations computed incorrectly.

#### 2a. Incorrect Depth Order (infrontof failure)
- **What happened**: The base-overlap heuristic produces wrong nearer/farther judgment
- **Impact**: Critical fact missing or inverted (infrontof(person, car) vs infrontof(car, person))
- **Example**: Two objects on different ground planes; heuristic assumes same plane
- **Evidence**: Ground truth pair annotation says "person nearer", system says "hazard nearer"
- **Responsibility**: Geometric reasoning (vision-to-logic translation)

#### 2b. Overlap Misdetection
- **What happened**: Bounding boxes overlap significantly but system fails to detect it
- **Impact**: Missing `overlaps(X, Y)` fact prevents rules from firing
- **Example**: Threshold tuning error, or boxes almost-but-not-quite overlapping
- **Evidence**: Boxes overlap >10% (ground truth), no overlaps fact asserted
- **Responsibility**: Geometric reasoning

#### 2c. Spatial Relation Error
- **What happened**: leftof/rightof/above computed incorrectly despite correct boxes
- **Impact**: Wrong or missing directional facts
- **Example**: Bug in geometric code, or edge case with box centers
- **Evidence**: Compare computed relations to ground truth annotations
- **Responsibility**: Geometric reasoning

---

### 3. Knowledge Representation Failure (KR Design)

**Definition**: Correct visual information available, but not represented in a way SNePS can use.

#### 3a. Missing Fact
- **What happened**: A relevant fact is not asserted into the knowledge base
- **Impact**: SNePS cannot reason about information it doesn't have
- **Example**: YOLO provides segmentation masks, but only boxes asserted; road context not represented
- **Evidence**: Information extractable from YOLO output, not in SNePSLOG transcript
- **Responsibility**: KR design (interface between vision and logic)

#### 3b. Wrong Atom Form
- **What happened**: Fact asserted in format that doesn't match rule expectations
- **Impact**: Rules written for `dangerous(X)` but KB has `isa(X, dangerous)` (schema mismatch)
- **Example**: English route uses state-attribute structure vs. direct predicates
- **Evidence**: Fact present but rules don't fire due to structural mismatch
- **Responsibility**: KR design

#### 3c. Confidence Threshold Effect
- **What happened**: Object filtered out before KB assertion due to confidence threshold
- **Impact**: Low-confidence but visible object not reasoned about
- **Example**: Person at conf=0.24 dropped (threshold 0.25), system can't flag danger
- **Evidence**: Object in YOLO raw output, filtered before SNePSLOG generation
- **Responsibility**: KR policy decision (threshold setting)

---

### 4. Rule Failure (Reasoning)

**Definition**: All necessary facts available and correctly formed, but SNePS inference produces wrong conclusion.

#### 4a. Correct Facts, Wrong Inference
- **What happened**: Premises satisfied, rule fires, but conclusion is incorrect
- **Impact**: False positive or false negative
- **Example**: Rule says "person overlapping vehicle → dangerous" but applies to person loading parked car
- **Evidence**: Check KB contents; all predicates present; SNePS output wrong
- **Responsibility**: Rule design (logic error)

#### 4b. Rule Too Broad
- **What happened**: Rule fires in cases where it shouldn't
- **Impact**: False positives (system over-flags danger)
- **Example**: "person near vehicle → dangerous" flags everyone on a sidewalk next to street
- **Evidence**: Rule antecedent satisfied in safe scenario
- **Responsibility**: Rule design (insufficient specificity)

#### 4c. Rule Too Narrow
- **What happened**: Rule doesn't fire when it should
- **Impact**: False negatives (system misses dangerous cases)
- **Example**: Rule requires person + car, misses person + truck
- **Evidence**: Manually verify: if rule had fired, conclusion would be correct
- **Responsibility**: Rule design (insufficient coverage)

#### 4d. Chained Inference Failure
- **What happened**: Multi-step reasoning breaks (e.g., car → vehicle → hazard fails)
- **Impact**: Transitive or inheritance reasoning doesn't complete
- **Example**: SNePS 2.7 doesn't chain two-level inheritance in single query
- **Evidence**: `ask(isa(car_1, hazard))` fails despite `subclass(car, vehicle)` and `subclass(vehicle, hazard)`
- **Responsibility**: Reasoning engine limitation or rule encoding

---

### 5. Alert Policy Failure (Application Logic)

**Definition**: Danger classification correct, but alert threshold produces wrong outcome.

#### 5a. Dangerous but Low Confidence
- **What happened**: System correctly infers dangerous(X), but alert(X) fails because YOLO confidence < 0.5
- **Impact**: Real danger not alerted (false negative for alert, true positive for dangerous)
- **Example**: Distant pedestrian detected at conf=0.3, correctly flagged dangerous, not alerted
- **Evidence**: `dangerous` contains X, `alert` does not, check detection confidence
- **Responsibility**: Policy decision (alert threshold setting)

#### 5b. Not Dangerous but Confident
- **What happened**: High-confidence false positive passes alert threshold
- **Impact**: Alert fires on non-danger (compounded error)
- **Example**: Person beside parked car at conf=0.9 incorrectly flagged dangerous, also alerted
- **Evidence**: `alert` contains X, ground truth says not dangerous
- **Responsibility**: Upstream error (Rule Failure) amplified by policy

---

### 6. Ground Truth Ambiguity (Annotation)

**Definition**: The error might not be an error—ground truth itself is uncertain.

#### 6a. Annotator Disagreement
- **What happened**: Multiple annotators give different danger labels for the same person
- **Impact**: "Error" depends on which annotator is considered correct
- **Example**: Person next to slow-moving vehicle; one annotator marks dangerous, another safe
- **Evidence**: Inter-annotator agreement score, multiple labels available
- **Responsibility**: Inherent ambiguity; system performance depends on annotator choice

#### 6b. Inherently Uncertain
- **What happened**: Scene genuinely ambiguous even to human experts
- **Impact**: No single "correct" answer exists
- **Example**: Is a person 2m from a creeping car dangerous? Depends on reaction time, driver attention, etc.
- **Evidence**: Annotators express low confidence, add "ambiguous" notes
- **Responsibility**: Task definition; may be outside system capability

---

## Root Cause vs Contributing Factors

**Important distinction**: An error can have multiple problems, but we assign ONE primary root cause.

### Definitions

**Root Cause**: The earliest stage where the pipeline diverged from correct behavior in a way that causally led to the final error.

**Contributing Factors**: Other issues that helped produce or propagate the error, but were not the initiating failure.

### Assignment Rules

1. **Follow the causal chain backwards**: Start from the final error, trace back through the pipeline
2. **Find the earliest decisive failure**: The first point where correct output became impossible
3. **Distinguish propagated vs independent errors**: 
   - If wrong input inevitably produces wrong output → root cause is earlier
   - If correct input still produces wrong output → root cause is here

### Examples

**Example 1**: Person beside parked car flagged dangerous
- Detection: ✓ Person detected, car detected
- Geometry: ⚠️ infrontof(person, car) asserted (base-overlap heuristic)
- Rules: ✓ Rule correctly fires given the fact
- Ground truth: Person NOT dangerous (car is parked)

**Attribution**:
- **Root cause**: 4b (Rule Too Broad) — Rule cannot distinguish parked from moving
- **Contributing factors**: 2a (Depth heuristic imperfect) — But even perfect depth wouldn't help
- **Reasoning**: Even if geometry were perfect, rule would still fire incorrectly on parked cars

**Example 2**: Distant pedestrian missed
- Detection: ✗ Person not detected (too small/far)
- Geometry: N/A (no detection to compute relations for)
- Rules: N/A (no facts to reason about)

**Attribution**:
- **Root cause**: 1a (Missing Person Detection)
- **Contributing factors**: None (everything downstream is blocked)

**Example 3**: Misplaced bounding box causes wrong depth order
- Detection: ✓ Person detected, but box shifted right by poor localization
- Geometry: ✗ Person appears beside vehicle instead of in front
- Rules: ✓ Rule correctly doesn't fire (no infrontof fact)
- Ground truth: Person IS dangerous

**Attribution**:
- **Root cause**: 1d (Poor Localization)
- **Contributing factors**: 2a (Depth estimation), but upstream error made it impossible
- **Reasoning**: Correct boxes would have → correct depth → correct conclusion

### Reporting Format

Each error record includes:
```json
{
  "root_cause": "4b_rule_broad",
  "contributing_factors": ["2a_depth_order"],
  "confidence": "high",
  "requires_manual_review": false,
  "evidence": {
    "person_detected": true,
    "vehicle_detected": true,
    "infrontof_fact_present": true,
    "rule_fired": true,
    "ground_truth_dangerous": false,
    "scene_notes": "parking lot, vehicle clearly parked"
  }
}
```

Summary statistics report **root causes only** (to avoid >100% totals):
```
Root Cause Distribution:
  1a. Missing Person: 15%
  2a. Depth Order: 10%
  4b. Rule Too Broad: 60%
  ...

Contributing Factor Analysis:
  Cases with multiple issues: 35%
  Most common secondary issue: 2a (appears in 25% of errors as contributor)
```

---

## Attribution Process

### For Each False Positive

**System flagged person X as dangerous, but ground truth says safe.**

1. **Check detection**: Did YOLO detect person X and relevant vehicles?
   - **No** → Skip (system can't flag what it doesn't see; not a false positive in reasoning sense)
   - **Yes** → Continue

2. **Check classification**: Are detected classes correct?
   - **No** → **1c. Wrong Classification** (person classified as something else, or vehicle misclassified)
   - **Yes** → Continue

3. **Check geometry**: Are spatial relations correct?
   - Compare `infrontof` facts to ground truth pair annotations
   - **Wrong depth order** → **2a. Incorrect Depth Order**
   - **Missing overlap** → **2b. Overlap Misdetection**
   - **Correct** → Continue

4. **Check KB facts**: Are necessary facts present in SNePSLOG transcript?
   - `isa(personX, person)`, `isa(vehicleY, hazard)`, `infrontof(personX, vehicleY)` present?
   - **Missing critical fact** → **3a. Missing Fact** or **3c. Confidence Threshold**
   - **Present** → Continue

5. **Check rule behavior**: Why did SNePS infer dangerous(X)?
   - **Rule fired correctly, but scenario is safe** → **4b. Rule Too Broad**
   - **Rule fired due to wrong facts** → Back to step 2-4
   - **Rule shouldn't apply here** → **4a. Correct Facts, Wrong Inference**

6. **Check alert policy**: If alert(X) also wrong:
   - **High confidence FP** → **5b. Not Dangerous but Confident** (compounds 4b)

7. **Check ground truth**: Is annotator certain?
   - **Low confidence annotation** → **6a or 6b. Ambiguity**

### For Each False Negative

**System did NOT flag person Y as dangerous, but ground truth says dangerous.**

1. **Check detection**: Did YOLO detect person Y?
   - **No** → **1a. Missing Person Detection** (STOP: can't reason about undetected object)
   - **Yes** → Continue

2. **Check hazard detection**: Did YOLO detect the threatening vehicle?
   - **No** → **1b. Missing Vehicle Detection** (STOP: no hazard to reason about)
   - **Yes** → Continue

3. **Check localization**: Are bounding boxes accurate?
   - **Person box misplaced** → **1d. Poor Localization**
   - **Vehicle box misplaced** → **1d. Poor Localization**
   - **Accurate** → Continue

4. **Check geometry**: Did system compute correct spatial relations?
   - Ground truth pair annotation says person nearer; check generated facts
   - **No `infrontof(person, vehicle)` fact** → **2a. Incorrect Depth Order**
   - **Fact present** → Continue

5. **Check KB facts**: Is `infrontof(person, vehicle)` in SNePSLOG transcript?
   - **Not asserted** → **3a. Missing Fact** (why wasn't the relation passed to KB?)
   - **Asserted** → Continue

6. **Check rule behavior**: Why didn't SNePS infer dangerous(person)?
   - **Rule requires additional conditions not met** → **4c. Rule Too Narrow**
   - **Rule should have fired** → **4a. Correct Facts, Wrong Inference** or **4d. Chained Inference Failure**

7. **Check alert policy**: If dangerous(Y) is correct but alert(Y) missing:
   - **Low confidence detection** → **5a. Dangerous but Low Confidence**

---

## Error Report Format

For each evaluation run, produce:

### Summary Statistics

```
Total images: 100
Total ground truth dangerous people: 40

False Positives: 15
False Negatives: 8

Error Attribution (False Positives):
  1a. Missing Person Detection: 0
  1b. Missing Vehicle Detection: 0
  1c. Wrong Classification: 0
  1d. Poor Localization: 1 (7%)
  2a. Incorrect Depth Order: 2 (13%)
  2b. Overlap Misdetection: 0
  2c. Spatial Relation Error: 0
  3a. Missing Fact: 0
  3b. Wrong Atom Form: 0
  3c. Confidence Threshold: 0
  4a. Correct Facts, Wrong Inference: 0
  4b. Rule Too Broad: 11 (73%)
  4c. Rule Too Narrow: 0
  4d. Chained Inference Failure: 0
  5b. Not Dangerous but Confident: 1 (7%)
  6a. Annotator Disagreement: 0
  6b. Inherently Uncertain: 0

Error Attribution (False Negatives):
  1a. Missing Person Detection: 3 (38%)
  1b. Missing Vehicle Detection: 1 (13%)
  1c. Wrong Classification: 0
  1d. Poor Localization: 1 (13%)
  2a. Incorrect Depth Order: 2 (25%)
  4c. Rule Too Narrow: 1 (13%)
  5a. Dangerous but Low Confidence: 0

Perception Errors (1a-1d, 2a-2c): 10/23 (43%)
KR Errors (3a-3c): 0/23 (0%)
Reasoning Errors (4a-4d): 12/23 (52%)
Policy Errors (5a-5b): 1/23 (4%)
Ambiguity: 0/23 (0%)
```

### Per-Image Details

```
Image: 000000000257.jpg
Ground truth dangerous: 0
Predicted dangerous: 4 (person_2, person_4, person_9, person_10)

False Positive: person_2
  Category: 4b. Rule Too Broad
  Explanation: Person standing next to parked truck. Rule fires on any person
               overlapping vehicle, cannot distinguish parked vs moving.
  Evidence: infrontof(person_2, truck_1) asserted (base-overlap heuristic),
            but truck is parked (no motion cues).

False Positive: person_4
  Category: 4b. Rule Too Broad
  Explanation: Same as person_2
  ...
```

---

## Research Implications

### If Perception Errors Dominate (>60%)

**Conclusion**: YOLO limitations are the bottleneck.

**Actions**:
- Larger/better detection model
- Lower confidence threshold (accept more false detections)
- Fine-tune YOLO on pedestrian-vehicle scenes

**Thesis narrative**: "The knowledge representation correctly models danger, but is limited by detection failures. Improving perception would increase system recall."

### If Reasoning Errors Dominate (>60%)

**Conclusion**: CV-KRR integration is the bottleneck.

**Actions**:
- Refine rules (narrow overly broad rules, broaden overly narrow ones)
- Add contextual facts (road surface, motion cues)
- Improve geometric reasoning

**Thesis narrative**: "Detection succeeds, but existing rules do not capture the nuance of dangerous situations. This demonstrates the value and challenge of knowledge representation in this domain."

### If Errors Are Balanced

**Conclusion**: Both CV and KRR contribute.

**Thesis narrative**: "The integration of computer vision and knowledge representation reveals complementary limitations: perception failures prevent reasoning, while reasoning failures squander good perceptual information. Advancing the system requires progress on both fronts."

---

## Usage in Evaluation Pipeline

Extend `evaluate.py`:

```python
def attribute_error(image, person_idx, predicted_dangerous, ground_truth_dangerous, 
                    detections, facts, rules, sneps_output):
    """Classify the error for this person."""
    
    person_gt = image["persons"][person_idx]
    person_detected = match_detection(person_gt["box"], detections)
    
    if ground_truth_dangerous and not predicted_dangerous:
        # False negative
        if not person_detected:
            return "1a_missing_person"
        # ... continue attribution logic
        
    elif predicted_dangerous and not ground_truth_dangerous:
        # False positive
        if not person_detected:
            return None  # Not truly a FP if not detected
        # ... continue attribution logic
        
    return "unknown"
```

---

## Validation

To confirm this taxonomy is complete and useful:

1. **Manually classify current dataset errors** (24 images)
2. **Check coverage**: Can every error be assigned a category?
3. **Check exclusivity**: Are categories mutually exclusive?
4. **Pilot test**: Have second annotator classify same errors; measure agreement
5. **Iterate**: Add categories if gaps found

---

## Notes

- Some errors have multiple contributing factors (e.g., poor localization → wrong depth order → rule fires incorrectly). Assign to the **earliest** failure in the pipeline.
- **Perception errors** (categories 1-2) block reasoning; fixing them may reveal latent reasoning errors.
- This taxonomy is **system-specific** to YOLO + SNePS. Other CV-KRR systems would have analogous but different categories.
