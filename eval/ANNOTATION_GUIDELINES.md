# Annotation Guidelines
## Ground Truth Definitions for Pedestrian Danger Assessment

**Version**: 1.0  
**Date**: 2026-10-23  
**Purpose**: Ensure consistent, defensible annotations across all datasets

---

## Core Principle

**Labels must reflect what is observable in the static image, not inferred context beyond the frame.**

We cannot see:
- Whether a vehicle is moving or parked
- Driver attention or reaction time
- What happened 1 second before or after the photo
- Pedestrian intent or trajectory

We can only see:
- Spatial relationships (overlap, proximity, relative position)
- Scene context clues (road markings, lighting, vehicle orientation)
- Visibility and occlusion

---

## Label Definitions

### 1. `dangerous` (boolean)

**Definition**: A pedestrian whose spatial position in this frame suggests immediate collision risk with a detected vehicle, based on observable geometric evidence alone.

**Annotate as TRUE when**:
- Pedestrian and vehicle bounding boxes overlap significantly (IoU > 0.1)
- Pedestrian appears spatially in front of vehicle (lower base in image)
- Vehicle is on a roadway (not sidewalk/parking lot) when determinable
- No clear protective barrier visible between them

**Annotate as FALSE when**:
- Pedestrian on sidewalk/pathway clearly separated from road
- Pedestrian behind vehicle (higher base in image)
- Pedestrian beside vehicle with no overlap
- Clear barrier (fence, wall, curb with significant height difference) present

**Annotate as NULL (ambiguous) when**:
- Cannot determine spatial relationship from image alone
- Vehicle location ambiguous (parking lot vs active lane unclear)
- Significant distance but unclear if safe (perspective/scale issues)
- You cannot confidently choose TRUE or FALSE

**Examples**:
- ✅ TRUE: Person crossing street mid-frame, overlapping car coming toward camera
- ❌ FALSE: Person on sidewalk, car 10m away in adjacent lane
- ⚠️ NULL: Person standing 2m from van in parking lot (moving? parked? unclear)

**NOT considered**:
- Whether vehicle is actually moving (unknowable from static image)
- Whether driver would stop (unknowable)
- Pedestrian reaction time (unknowable)
- Contextual danger not visible in frame

### 2. `hidden` (boolean)

**Definition**: A pedestrian partially or fully occluded by a vehicle from the camera's perspective.

**Annotate as TRUE when**:
- Pedestrian bounding box overlaps with vehicle box
- Pedestrian base is higher in the image than vehicle base (behind vehicle)
- At least 20% of the pedestrian box overlaps the vehicle

**Annotate as FALSE when**:
- No overlap between pedestrian and any vehicle
- Pedestrian fully visible with no occlusion

**Annotate as NULL when**:
- Minimal overlap (~10-20%) and unclear if truly occluded

**Examples**:
- ✅ TRUE: Person walking behind bus, lower half visible, upper occluded
- ❌ FALSE: Person fully visible standing beside car
- ⚠️ NULL: Person's shoulder barely touches vehicle edge

**Note**: A person can be both `dangerous: true` and `hidden: true` if overlapping one vehicle from behind while also in front of another vehicle.

### 3. `alert` (NOT annotated directly)

**Definition**: This is a **system output**, not a ground truth label.

`alert(X)` means: `dangerous(X) AND confidence(X) ≥ 0.5`

Do NOT annotate `alert` in ground truth. The system computes it from:
- Your `dangerous` annotation
- YOLO's detection confidence

**Evaluation**: Compare system's alert flags to your dangerous labels, accounting for confidence threshold.

---

## Annotation Process

### Step 1: Person Detection Ground Truth

For each visible person in the image:

1. Draw bounding box (tight fit around person)
2. Record box coordinates: `[x1, y1, x2, y2]`
3. Assign unique person index (0-based, left-to-right order)

### Step 2: Hazard Detection Ground Truth

For each vehicle that could pose danger:

1. Draw bounding box
2. Record class: `car`, `bus`, `truck`, `train`, `motorcycle`, `bicycle`, `horse`, etc.
3. Record box coordinates
4. Note `motion_state` (if determinable):
   - `"moving"`: Clearly in motion (motion blur, tire spray, position in active lane)
   - `"stopped"`: Brake lights visible, queue at red light
   - `"parked"`: Parking lot, curb with no driver visible, parking lines
   - `"unclear"`: Cannot determine from frame (DEFAULT)

### Step 3: Danger Classification

For each person:

1. Identify all vehicles within proximity (boxes within ~50 pixels or overlapping)
2. For each person-vehicle pair:
   - Determine spatial relationship: person nearer, vehicle nearer, or unclear
   - Record in `pairs` array: `{"person": idx, "hazard": idx, "nearer": "person|hazard|unclear"}`
3. Apply dangerous definition above
4. Set `dangerous: true|false|null`
5. Record `confidence_gt`: 
   - `"high"`: Confident in your judgment
   - `"medium"`: Reasonable judgment but some uncertainty
   - `"low"`: Genuinely ambiguous, forced to choose
6. Add `notes` if needed: "parking lot scene, unclear if vehicle moving"

### Step 4: Hidden Classification

For each person:

1. Check overlap with any vehicle
2. Check relative base position (person higher = behind)
3. Set `hidden: true|false|null`

### Step 5: Metadata

Record:
- `category`: Scenario type (clear_danger, beside_parked, hidden, crossing, small_distant, crowded, ambiguous, safe)
- `lighting`: day, night, dawn_dusk
- `weather`: clear, rain, fog, snow (if determinable)
- `annotator`: Your ID
- `date`: YYYY-MM-DD
- `time_seconds`: How long annotation took
- `ambiguous`: true if `confidence_gt == "low"` for any person

---

## Decision Tree for `dangerous` Label

```
START: Person P and Vehicle V detected

Q1: Do their bounding boxes overlap (IoU > 0.1)?
  NO  → dangerous: FALSE (not spatially close)
  YES → Continue to Q2

Q2: Is P's base lower in image than V's base?
  NO  → dangerous: FALSE (P is behind V, should be hidden instead)
  YES → Continue to Q3

Q3: Is V clearly on a sidewalk/parking lot/safe area?
  YES → dangerous: FALSE (not in traffic area)
  NO  → Continue to Q4

Q4: Is there a clear protective barrier between P and V?
  YES → dangerous: FALSE (separated by barrier)
  NO  → Continue to Q5

Q5: Can you confidently determine their spatial relationship?
  NO  → dangerous: NULL (ambiguous)
  YES → dangerous: TRUE (person in front of vehicle, no barriers)
```

---

## Inter-Annotator Agreement

**All ambiguous cases (confidence_gt == "low") MUST be reviewed by two annotators.**

Process:
1. Annotator A labels entire dataset
2. Identify all `confidence_gt: "low"` cases
3. Annotator B independently labels those cases
4. Compute Cohen's kappa on ambiguous subset
5. Discuss disagreements, establish consensus label
6. Record final label + "consensus" in notes

**Target**: κ ≥ 0.7 on ambiguous cases

If κ < 0.7:
- Guidelines too vague, need refinement
- Task may be inherently ambiguous for some cases
- Consider excluding truly undecidable cases from evaluation

---

## Data Splitting Rules

### Three Datasets

| Dataset | Size | Purpose | Usage |
|---|---|---|---|
| **Baseline** | 24 images | Historical reference | Regression checks, compare to original results |
| **Development** | 100 images | Rule tuning | Iterative improvements, threshold selection |
| **Test** | 30-50 images | Final evaluation | Use ONCE, after all decisions frozen |

### Partition Rules

1. **Images from same source stay together**
   - Same video → same partition
   - Near-duplicate scenes → same partition
   - Same location/time → same partition

2. **Stratify by scenario**
   - Each partition should have examples from each category
   - Don't put all "clear danger" in dev and all "ambiguous" in test

3. **Hold-out test is sacred**
   - Never use test images to debug rules
   - Never adjust thresholds based on test performance
   - Never re-label test images after seeing system output
   - Treat test results as final until you change the system, then re-evaluate

4. **Baseline is frozen**
   - Original 24 images never change
   - Always report results on baseline for comparison
   - Serves as regression check

### Recommended Distribution

| Category | Baseline | Dev | Test | Total |
|---|---|---|---|---|
| Clear danger | 4 | 16 | 5 | 25 |
| Beside parked | 3 | 12 | 5 | 20 |
| Hidden | 2 | 8 | 3 | 13 |
| Crossing | 2 | 13 | 5 | 20 |
| Small/distant | 1 | 9 | 3 | 13 |
| Crowded | 5 | 5 | 3 | 13 |
| Ambiguous | 3 | 7 | 3 | 13 |
| Safe street | 4 | 6 | 3 | 13 |
| **TOTAL** | **24** | **~100** | **~30** | **~154** |

---

## Quality Control

### Before Starting Annotation

- [ ] Read these guidelines completely
- [ ] Practice on 5 example images
- [ ] Compare your practice annotations with reference answers
- [ ] Resolve any confusion before annotating real dataset

### During Annotation

- [ ] Take breaks every 20 images
- [ ] Re-read guidelines if uncertain
- [ ] Record all ambiguous cases in notes
- [ ] Flag any guideline gaps encountered

### After Annotation

- [ ] Sample 20% for quality review
- [ ] Check for systematic biases (e.g., always marking parking lot as safe)
- [ ] Verify all required fields present
- [ ] Compute summary statistics (% dangerous, % hidden, % ambiguous)

### Expected Distributions

| Metric | Expected Range | Flag if Outside |
|---|---|---|
| % dangerous | 20-40% | <10% or >50% |
| % hidden | 10-20% | <5% or >30% |
| % ambiguous (NULL) | 5-15% | >25% |
| Annotation time | 2-5 min/image | >10 min (too slow/complex) |

---

## Common Pitfalls

### ❌ Don't Do This

1. **Inferring motion from static image**
   - "This car looks like it's moving fast" → You can't know from one frame
   - Use observable cues only: motion blur, tire spray, position in lane

2. **Assuming parking = safe**
   - Parking lot can have maneuvering vehicles
   - Mark based on spatial relationship, not assumed vehicle state

3. **Considering pedestrian intent**
   - "This person is about to cross" → Not observable
   - Label current position, not predicted future

4. **Over-using NULL**
   - NULL means "genuinely cannot decide"
   - Use for ~5-15% of cases, not 40%

5. **Changing labels after seeing system output**
   - Once annotated, labels are frozen
   - Exception: Correct actual errors (e.g., mislabeled class)

### ✅ Do This

1. **Be consistent**
   - Apply same criteria to similar scenes
   - Use decision tree systematically

2. **Document uncertainty**
   - Use `confidence_gt` field honestly
   - Write notes for ambiguous cases

3. **Focus on observables**
   - Spatial overlap? Measurable.
   - Relative position? Measurable.
   - Motion state? Mostly unmeasurable from single frame.

4. **Annotate for the task**
   - Task: "Does this frame show evidence of collision risk?"
   - Not: "Is this person actually in danger?"

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-10-23 | Initial guidelines |

---

## Questions or Issues?

If you encounter:
- A case not covered by these guidelines
- Systematic ambiguity in a category
- Disagreement between annotators that guidelines don't resolve

**STOP and document the issue. Do not invent ad-hoc rules.**

Add notes to the annotation, flag for review, and consider whether guidelines need refinement.

The goal is defensible, consistent labels — not perfect labels. Perfect is impossible for inherently ambiguous scenes.
