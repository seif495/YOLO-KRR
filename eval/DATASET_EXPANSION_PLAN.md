# Evaluation Dataset Expansion Plan

## Current State

**Existing baseline dataset** (`annotations.json`):
- 24 images total
- 6 dangerous people (25% positive rate)
- Sources: COCO128 (18 images) + custom examples (6 images)
- Will be **preserved as stable baseline** for comparing improvements

## Problem: Current Dataset Limitations

1. **Too small**: 6 dangerous cases insufficient for statistical significance
2. **Unbalanced**: Most cases are safe scenes, hard to measure recall
3. **Limited diversity**: Missing key scenarios:
   - Pedestrians clearly crossing in vehicle path
   - Small/distant pedestrians
   - Ambiguous cases (is the vehicle moving? parked?)
   - Different lighting conditions
   - Various vehicle types
4. **No error attribution**: Can't separate YOLO failures from reasoning failures

---

## Expansion Strategy

### Dataset Structure

```
eval/
├── annotations.json              # STABLE BASELINE (24 images, 6 dangerous)
├── annotations_dev.json          # DEVELOPMENT SET (new, ~50-100 images)
├── annotations_test.json         # HOLD-OUT TEST SET (new, ~30-50 images)
├── images/                       # Downloaded/collected images
│   ├── baseline/                 # Original 24 images
│   ├── dev/                      # Development set images
│   └── test/                     # Test set images
└── ERROR_CATEGORIES.md           # Error taxonomy and attribution guide
```

### Target Distribution (Development Set)

| Category | Target Count | Dangerous | Safe | Purpose |
|---|---|---|---|---|
| **Clear danger** | 20 | 20 | 0 | Baseline recall measurement |
| **Beside parked vehicles** | 15 | 0 | 15 | False positive control |
| **Behind vehicles (hidden)** | 10 | 0 | 10 | Hidden detection accuracy |
| **Crosswalk/crossing** | 15 | 10 | 5 | Mixed scenarios |
| **Small/distant pedestrians** | 10 | 5 | 5 | Detection limit testing |
| **Crowded scenes** | 10 | 3 | 7 | Multi-object reasoning |
| **Ambiguous cases** | 10 | ? | ? | Inter-annotator agreement check |
| **Safe street scenes** | 10 | 0 | 10 | Specificity control |
| **TOTAL** | **100** | **~40** | **~60** | Balanced dataset |

---

## Detailed Category Specifications

### 1. Clear Danger (20 images)
**Description**: Pedestrians unambiguously in front of moving/oncoming vehicles

**Subcategories**:
- Person crossing street with car approaching (5)
- Person stepping off curb into traffic lane (5)
- Child running into road (3)
- Person between lanes with traffic both ways (3)
- Person in front of large vehicle (bus/truck) (4)

**Ground truth requirements**:
- `dangerous: true`
- Clear overlap between person and vehicle bounding boxes
- Person base visibly lower in image than vehicle base
- Vehicle in lane/on road (if road detection available)

**Expected system behavior**: Should flag all 20

### 2. Beside Parked Vehicles (15 images)
**Description**: People standing or walking next to stationary vehicles

**Subcategories**:
- Person on sidewalk next to parked car (5)
- Person loading/unloading parked vehicle (5)
- Person waiting at bus stop (3)
- Person at crosswalk with stopped traffic (2)

**Ground truth requirements**:
- `dangerous: false`
- Person and vehicle may overlap
- No motion cues visible

**Expected system behavior**: Should NOT flag (current system over-flags these)

### 3. Behind Vehicles / Hidden (10 images)
**Description**: Pedestrians partially occluded by vehicles

**Subcategories**:
- Person walking behind large vehicle (4)
- Person emerging from behind parked car (3)
- Person partially visible behind bus/truck (3)

**Ground truth requirements**:
- `dangerous: false` (unless also in front of another vehicle)
- `hidden: true`
- Significant overlap between person and vehicle boxes
- Person base higher in image than vehicle base

**Expected system behavior**: Should flag as hidden, not dangerous

### 4. Crosswalk/Crossing Scenarios (15 images)
**Description**: Pedestrians in crosswalks or crossing roads

**Subcategories**:
- Person in marked crosswalk with green light (5 safe)
- Person in crosswalk with red light, car approaching (5 dangerous)
- Person jaywalking mid-block (5 dangerous)

**Ground truth requirements**:
- Mixed `dangerous` labels based on context
- Note: System cannot see traffic signals (limitation to document)

**Expected system behavior**: Will flag based on geometry only, not traffic state

### 5. Small/Distant Pedestrians (10 images)
**Description**: Test detection limits with far-away or small people

**Subcategories**:
- Pedestrians >50m away (5)
- Children or small people (3)
- Partially occluded distant people (2)

**Ground truth requirements**:
- Manual labels include ALL people visible to human annotator
- Compare YOLO detections to human labels
- Mixed danger labels based on actual vehicle proximity

**Expected system behavior**: High detection failure rate (measure perception limit)

### 6. Crowded Scenes (10 images)
**Description**: Multiple people and vehicles, complex spatial relationships

**Subcategories**:
- Busy intersection (3)
- Marketplace or event with vehicles (3)
- Parking lot with pedestrians (2)
- Sidewalk café next to street (2)

**Ground truth requirements**:
- 0-3 dangerous people per scene
- Multiple person-vehicle pairs to test
- Test reasoning scalability (SNePS performance with many facts)

**Expected system behavior**: May have increased FPs, measure reasoning overhead

### 7. Ambiguous Cases (10 images)
**Description**: Scenarios where ground truth is uncertain or controversial

**Subcategories**:
- Person very close to slow-moving vehicle (3)
- Person in parking lot with maneuvering vehicle (3)
- Delivery person near vehicle (2)
- Person on bicycle next to car (2)

**Ground truth requirements**:
- Multi-annotator labels required
- Record disagreement rate
- Note: "ambiguous" in label

**Expected system behavior**: No strong expectation; measure consistency

### 8. Safe Street Scenes (10 images)
**Description**: Clear negatives with people and vehicles safely separated

**Subcategories**:
- Sidewalk scenes (5)
- Pedestrian-only areas (3)
- Far separation between people and vehicles (2)

**Ground truth requirements**:
- `dangerous: false` for all people
- No overlap between person and vehicle boxes

**Expected system behavior**: Should produce zero false positives

---

## Ground Truth Annotation Schema

Extend current schema with additional fields:

```json
{
  "images": [
    {
      "source": "dev|test|baseline",
      "file": "filename.jpg",
      "split": "dev|test|baseline",
      "category": "clear_danger|beside_parked|hidden|crossing|small_distant|crowded|ambiguous|safe",
      "lighting": "day|night|dawn_dusk",
      "weather": "clear|rain|fog|snow",
      "persons": [
        {
          "box": [x1, y1, x2, y2],
          "dangerous": true|false|null,
          "hidden": true|false|null,
          "alert": true|false|null,
          "confidence_gt": "high|medium|low",
          "notes": "optional annotation notes",
          "detected_by_yolo": true|false  // filled during evaluation
        }
      ],
      "hazards": [
        {
          "class": "car|bus|truck|...",
          "box": [x1, y1, x2, y2],
          "motion_state": "moving|stopped|parked|unclear",
          "detected_by_yolo": true|false  // filled during evaluation
        }
      ],
      "pairs": [
        {
          "person": 0,
          "hazard": 0,
          "nearer": "person|hazard|unclear",
          "infrontof_cue": "person|hazard|none"  // filled during evaluation
        }
      ],
      "annotation_metadata": {
        "annotator": "annotator_id",
        "date": "YYYY-MM-DD",
        "time_seconds": 120,
        "ambiguous": false,
        "notes": "any relevant context"
      }
    }
  ]
}
```

---

## Error Attribution Taxonomy

### Error Categories (Priority 5)

For each incorrect prediction, classify root cause:

#### 1. Object Detection Failure
- **1a. Missing person**: YOLO didn't detect the person at all
- **1b. Missing vehicle**: YOLO didn't detect the vehicle
- **1c. Wrong class**: YOLO misclassified object (e.g., truck → car)
- **1d. Poor localization**: Bounding box significantly misplaced

#### 2. Geometric Estimation Failure
- **2a. Incorrect depth order**: infrontof cue produces wrong nearer/farther
- **2b. Overlap misdetection**: Fails to detect geometric overlap
- **2c. Spatial relation error**: leftof/rightof/above incorrectly computed

#### 3. Knowledge Representation Failure
- **3a. Missing fact**: Correct visual information not asserted to KB
- **3b. Wrong atom form**: Fact structure doesn't match rule expectations
- **3c. Confidence threshold**: Object filtered out before reaching KB

#### 4. Rule Failure
- **4a. Correct facts, wrong inference**: Rules produce incorrect conclusion
- **4b. Rule too broad**: Fires on cases it shouldn't
- **4c. Rule too narrow**: Doesn't fire when it should
- **4d. Chained inference failure**: Multi-step reasoning breaks

#### 5. Alert Policy Failure
- **5a. Dangerous but low confidence**: Correctly dangerous, filtered by alert threshold
- **5b. Not dangerous but confident**: Alert fires on false positive

#### 6. Ground Truth Ambiguity
- **6a. Annotator disagreement**: Multiple annotators give different labels
- **6b. Inherently uncertain**: Scene genuinely ambiguous

### Error Attribution Process

For each **false positive** or **false negative**:

1. Check YOLO outputs: Were person and vehicle detected?
   - If NO → **Detection Failure (1)**
   
2. Check geometric facts: Does infrontof match ground truth?
   - If NO → **Geometric Failure (2)**
   
3. Check asserted facts: Are correct predicates in KB?
   - If NO → **KR Failure (3)**
   
4. Check SNePS answers: Does inference produce expected result?
   - If NO → **Rule Failure (4)**
   
5. Check alert vs dangerous: Is policy filtering incorrectly?
   - If YES → **Policy Failure (5)**

---

## Image Sourcing Strategy

### Sources (in priority order)

1. **COCO dataset** (free, already integrated)
   - Person class: 262,465 instances
   - Vehicle classes available
   - Diverse scenes
   - **Action**: Use `coco128` and `val2017` splits

2. **OpenImages V7** (free, Creative Commons)
   - Urban street scenes
   - Pedestrian crossings
   - **Action**: Download relevant subsets

3. **Dashcam footage frames** (various licenses)
   - KITTI dataset (academic use)
   - BDD100K (academic use)
   - **Action**: Extract frames, manual annotation

4. **Custom collection** (own photos, controlled)
   - Take photos in local area
   - Ensure diverse lighting/weather
   - **Action**: Collect 10-20 controlled examples

### Licensing Requirements

- Document license for each source
- Ensure thesis/research use is permitted
- Attribute sources in `eval/images/LICENSES.md`

---

## Annotation Workflow

### Tools

**Option 1: CVAT (Computer Vision Annotation Tool)**
- Free, open source
- Supports bounding boxes
- Can import/export JSON
- Web-based interface

**Option 2: LabelImg** 
- Simple, Python-based
- Outputs XML (can convert to JSON)
- Good for small datasets

**Option 3: Python script + manual JSON editing**
- Full control
- Good for extending existing annotations
- Can display images with matplotlib

### Process

1. **Collect images** (100 for dev, 50 for test)
2. **Initial annotation** (person/vehicle boxes)
3. **Danger labeling** (mark dangerous/safe/ambiguous)
4. **Pair annotation** (which person-vehicle pairs matter)
5. **Quality check** (review 20% with second annotator)
6. **Inter-annotator agreement** (compute Cohen's kappa on ambiguous subset)

### Time Estimate

- Image collection: 4-6 hours
- Annotation: ~3-5 min per image = 7-12 hours for 100 images
- Quality check: 2-3 hours
- **Total**: ~15-20 hours for full expanded dataset

---

## Evaluation Metrics (Updated)

### Detection Metrics
- **Person recall**: Detected persons / Ground truth persons
- **Person precision**: Detected persons / All detections
- **Vehicle recall/precision**: Same for hazard vehicles

### Relation Metrics
- **infrontof accuracy**: Correct depth order / All annotated pairs
- **Geometric error rate**: Per relation type (leftof, above, overlaps, near)

### Danger Classification Metrics
- **Precision, Recall, F1**: For dangerous(?x)
- **Alert precision, recall, F1**: For alert(?x)
- **Hidden precision, recall**: For hidden(?x)

### Error Attribution Metrics (NEW)
- **Detection error rate**: % of errors due to YOLO failures
- **Geometric error rate**: % due to spatial reasoning
- **KR error rate**: % due to fact representation
- **Rule error rate**: % due to inference failures
- **Breakdown by category**: Error distribution across scene types

### Comparison Metrics
- **Baseline consistency**: Results on original 24 images before/after changes
- **Route comparison**: Typed vs English on same images (answer agreement %)
- **Performance**: Median inference time with IQR

---

## Implementation Plan

### Phase 1: Baseline Preservation (DONE)
- ✅ Current 24 images preserved in `annotations.json`
- ✅ Results saved in `eval/results/` for comparison

### Phase 2: Error Taxonomy (1-2 days)
- Create `ERROR_CATEGORIES.md` with classification guide
- Analyze current 24 images: classify each FP/FN
- Document current error distribution

### Phase 3: Image Collection (2-3 days)
- Download COCO/OpenImages subsets
- Extract relevant frames from dashcam datasets
- Collect custom photos if needed
- Organize into `eval/images/{dev,test}/`

### Phase 4: Annotation (5-7 days)
- Set up annotation tool
- Annotate dev set (100 images)
- Annotate test set (50 images)
- Quality check (20% review)

### Phase 5: Evaluation Pipeline (2-3 days)
- Extend `evaluate.py` to handle new schema fields
- Add error attribution logic
- Generate error breakdown reports
- Update visualization/reporting

### Phase 6: Baseline Experiments (2-3 days)
- Run typed and English routes on full dev set
- Compute error attribution statistics
- Compare to baseline results
- Document findings

---

## Success Criteria

1. **Dataset size**: ≥100 images in dev, ≥30 in test
2. **Balance**: 30-50% positive rate (dangerous people)
3. **Diversity**: All 8 categories represented
4. **Quality**: <10% annotation errors on quality check
5. **Error attribution**: 100% of evaluation errors classified
6. **Baseline stability**: Original 24 images show <5% result variance
7. **Documentation**: Complete provenance and license info

---

## Research Value

This expanded dataset enables:

1. **Statistical significance**: Sufficient samples for valid conclusions
2. **Error understanding**: Separate CV limitations from KRR limitations
3. **Improvement direction**: Identify highest-impact improvement areas
4. **Thesis contribution**: Rigorous evaluation of CV-KRR integration
5. **Reproducibility**: Clear methodology for future work
6. **Benchmarking**: Standard test set for comparing approaches

---

## Next Steps

1. **Immediate (this session)**: 
   - Create error taxonomy document
   - Analyze current dataset errors
   
2. **Short-term (next 1-2 weeks)**:
   - Collect and annotate dev set
   - Extend evaluation pipeline
   
3. **Medium-term (before thesis submission)**:
   - Complete test set annotation
   - Run full evaluation suite
   - Document findings in thesis

---

## Notes

- **Development vs Test split**: Use dev set for tuning rules/parameters, test set ONLY for final evaluation
- **Baseline immutability**: Never modify original 24-image annotations after expansion
- **Version control**: Tag git commits for each major dataset version
- **Replication**: Document exact dataset versions, model versions, random seeds
