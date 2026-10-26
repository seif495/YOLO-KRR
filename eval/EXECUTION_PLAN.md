# Corrected Execution Plan
## From Methodology to Results

**Based on feedback**: Don't start all priorities simultaneously. Follow dependency order.

---

## Phase 1: Define Evaluation Protocol ✅ DONE

**Deliverables**:
- [x] `ANNOTATION_GUIDELINES.md` — Precise label definitions
- [x] `ERROR_TAXONOMY.md` — Root cause + contributing factors framework
- [x] `BENCHMARKING_PROTOCOL.md` — Controlled performance measurement
- [x] `EXECUTION_PLAN.md` — This document

**Status**: Complete. Ready to proceed.

**Review checkpoint**: Have second person review guidelines before annotation starts.

---

## Phase 2: Instrument the Evaluator (NEXT STEP)

**Goal**: Capture all intermediate representations needed for error attribution.

### 2.1 Modify `evaluate.py`

**Add per-image detailed output**:

```python
# Current output (summary only):
{
  "image": "000000000049.jpg",
  "persons": 6,
  "detected": 4,
  "dangerous": 0,
  "flagged": [],
  ...
}

# New output (detailed):
{
  "image": "000000000049.jpg",
  "persons": 6,
  "detected": 4,
  "dangerous": 0,
  "flagged": [],
  "detections": [  # ← ADD THIS
    {"label": "person_1", "class": "person", "conf": 0.85, "box": [...]}
  ],
  "facts": [  # ← ADD THIS
    "isa(person_1, person)",
    "infrontof(person_1, car_1)"
  ],
  "snepslog_transcript": "...",  # ← ADD THIS (full transcript)
  "sneps_output": [...],  # ← ADD THIS (raw SNePS response)
  "errors": [],  # SNePS errors if any
  ...
}
```

**Additional fields per person in ground truth**:
- `detected_by_yolo`: boolean (filled during evaluation)
- `matched_detection_label`: string or null
- `matched_detection_conf`: float or null

**Additional fields per pair**:
- `infrontof_cue_result`: "person" | "hazard" | "none" (filled during evaluation)

**Save two files per run**:
- `{name}.json` — Summary statistics (current format, keep for compatibility)
- `{name}_detailed.json` — Per-image detailed data (new)

### 2.2 Test on Baseline

Run instrumented evaluator on original 24 images:

```bash
python eval/evaluate.py \
  --model yolo11n-seg.pt \
  --backend allegro \
  --name baseline_instrumented
```

**Verify**:
- Detailed JSON has all required fields
- Detections match expectations
- Facts are complete
- Results match previous run (regression check)

**Time estimate**: 4-6 hours (coding + testing)

---

## Phase 3: Baseline Error Attribution

**Goal**: Understand current error distribution before expanding dataset.

### 3.1 Run Error Analysis

```bash
python eval/analyze_errors.py \
  eval/results/baseline_instrumented_detailed.json \
  --annotations eval/annotations.json \
  --output eval/results/baseline_error_attribution.json
```

### 3.2 Manual Review

**Process**:
1. Script proposes root cause for each error
2. Reviewer examines evidence (detections, facts, image)
3. Confirms or corrects attribution
4. Records confidence: "confident" | "uncertain" | "needs_discussion"

**Sample size**: Review ALL errors on 24-image baseline (likely ~12 errors total)

### 3.3 Document Findings

Create `eval/results/BASELINE_ERROR_ANALYSIS.md`:

```markdown
# Baseline Error Analysis (24 images, 6 dangerous)

## Error Distribution (Root Causes)

| Category | FP | FN | Total | % |
|---|---|---|---|---|
| 1a. Missing Person | 0 | 3 | 3 | 25% |
| 2a. Depth Order | 1 | 2 | 3 | 25% |
| 4b. Rule Too Broad | 7 | 0 | 7 | 58% |
| Total | 8 | 4 | 12 | 100% |

## Key Findings

1. **Rule Too Broad dominates FPs** (58%)
   - Parked vehicle problem: 5/7 cases
   - Person beside vehicle: 2/7 cases

2. **Detection failures cause 25% of FNs**
   - Distant pedestrians: 2/3 cases
   - Poor lighting: 1/3 cases

3. **Depth estimation issues: 25%**
   - Off-ground-plane objects: 2/3 cases

## Implications for Dataset Expansion

**Must include more of**:
- Parked vehicle scenarios (test specificity)
- Distant pedestrians (test detection limits)
- Non-ground-plane cases (test geometric assumptions)

**Should stratify by**:
- Lighting conditions
- Vehicle state (moving vs parked, when determinable)
- Distance to camera
```

**Time estimate**: 6-8 hours (run + review + document)

---

## Phase 4: Expand and Annotate Dataset

**Goal**: Create development and test sets addressing identified failure modes.

### 4.1 Image Collection (Week 1)

**Sources**:
1. **COCO val2017** (search for person + vehicle)
   - Filter by class combinations
   - Download 150 candidate images
   - License: Already permissible

2. **OpenImages V7** (if needed)
   - Query: "Person", "Car", "Pedestrian crossing"
   - Download 50 candidates
   - Check Creative Commons licenses

3. **KITTI / BDD100K** (dashcam, if needed)
   - Extract diverse frames
   - Verify academic use allowed

**Selection criteria**:
- Covers all 8 scenario categories
- No near-duplicates
- Clear image quality (not motion-blurred)
- Diverse: lighting, weather, camera angles

**Target**: 200 candidates → 150 selected (100 dev, 50 test)

### 4.2 Annotation (Week 2)

**Process**:
1. Read `ANNOTATION_GUIDELINES.md` completely
2. Practice on 5 examples (not in dataset)
3. Annotate development set (100 images)
4. Annotate test set (50 images)
5. Flag ambiguous cases (confidence_gt == "low")

**Tool**: CVAT or custom Python script with matplotlib display

**Per-image steps** (see ANNOTATION_GUIDELINES.md):
- Draw person bounding boxes
- Draw vehicle bounding boxes
- Classify dangerous/safe/ambiguous for each person
- Classify hidden for each person
- Record person-vehicle pairs with depth order
- Add metadata (category, lighting, weather, notes)

**Time tracking**: Record actual annotation time per image

### 4.3 Quality Control

**Sample review** (20% of dev set):
- Second annotator reviews 20 random images
- Compare labels, compute agreement
- Discuss disagreements
- Identify guideline gaps

**Inter-annotator agreement** (ambiguous cases):
- Second annotator labels ALL low-confidence cases
- Compute Cohen's kappa
- Target: κ ≥ 0.7
- If κ < 0.7: Refine guidelines or exclude truly ambiguous cases

**Distribution checks**:
- % dangerous in expected range (20-40%)
- % hidden in expected range (10-20%)
- % ambiguous not excessive (<15%)
- All categories represented

### 4.4 Finalize Data Splits

Verify:
- No data leakage (same-source images stay together)
- Stratification by category
- Test set balanced across scenarios
- Baseline preserved separately

**Time estimate**: 15-20 hours total (collection 4-6h, annotation 8-12h, QC 3-5h)

---

## Phase 5: Development Set Evaluation

**Goal**: Use dev set to improve system, measure on larger sample.

### 5.1 Run Full Evaluation

Both routes on development set:

```bash
# Typed route
python eval/evaluate.py \
  --model yolo11n-seg.pt \
  --backend allegro \
  --annotations eval/annotations_dev.json \
  --name dev_typed

# English route (if supported on Allegro, otherwise use SNePSpaCy)
python eval/evaluate.py \
  --model yolo11n-seg.pt \
  --backend snepspacy \
  --route english \
  --annotations eval/annotations_dev.json \
  --name dev_english
```

### 5.2 Error Attribution

```bash
python eval/analyze_errors.py \
  eval/results/dev_typed_detailed.json \
  --annotations eval/annotations_dev.json \
  --output eval/results/dev_typed_errors.json
```

Review subset (20%) manually, document patterns.

### 5.3 Identify Improvements

Based on error distribution:
- If perception dominates: Consider larger YOLO model, lower threshold
- If reasoning dominates: Identify specific rule improvements
- If geometric dominates: Improve depth heuristic

**DO NOT touch test set during this phase.**

### 5.4 Iterate (Optional)

If improvements identified:
1. Make changes (e.g., adjust rules, add context)
2. Re-evaluate on dev set only
3. Document changes and rationale
4. Track performance across iterations

**Time estimate**: 8-10 hours

---

## Phase 6: Hold-Out Test Evaluation

**Goal**: Final evaluation on unseen data.

### 6.1 Freeze System

**Before running test**:
- [ ] All rules finalized
- [ ] All thresholds finalized
- [ ] All code changes committed
- [ ] Document exact system configuration

### 6.2 Run Test Evaluation

**ONE TIME ONLY**:

```bash
# Typed route
python eval/evaluate.py \
  --model yolo11n-seg.pt \
  --backend allegro \
  --annotations eval/annotations_test.json \
  --name test_typed_final

# English route
python eval/evaluate.py \
  --model yolo11n-seg.pt \
  --backend snepspacy \
  --route english \
  --annotations eval/annotations_test.json \
  --name test_english_final
```

### 6.3 Error Attribution

Full analysis, review ALL errors manually.

### 6.4 Compare to Baseline

**Three-way comparison**:
- Baseline (24 images, original system)
- Dev set (100 images, possibly improved system)
- Test set (50 images, final evaluation)

**Metrics**:
- Precision, recall, F1 for dangerous, alert, hidden
- Error distribution by category
- Consistency across datasets

**DO NOT make changes based on test results unless**:
- Find actual bug (not "rule could be better")
- Correct bug
- Re-run ENTIRE evaluation (baseline + dev + test)
- Report both versions

**Time estimate**: 4-5 hours

---

## Phase 7: Performance Benchmarking

**Goal**: Rigorous timing comparison following BENCHMARKING_PROTOCOL.md.

**Prerequisites**:
- System frozen (from Phase 6)
- Baseline dataset available
- No background tasks running

### 7.1 Verify Configurations

Test all 4 configs on 3 sample images:
- Config A: Typed + Allegro + Windows
- Config B: English + Allegro + Windows (check if supported)
- Config C: Typed + SNePSpaCy + WSL
- Config D: English + SNePSpaCy + WSL

Document which configs are feasible.

### 7.2 Implement Benchmark Script

`eval/benchmark_performance.py`:
- Component-level timing
- 10 runs per config
- Cold start + steady-state
- Data validation

### 7.3 Run Experiment

Execute on 24 baseline images:

```bash
python eval/benchmark_performance.py \
  --images eval/annotations.json \
  --configs A B C D \
  --runs 10 \
  --output eval/results/benchmark_results.json
```

Monitor: No thermal throttling, no swap, no network.

### 7.4 Statistical Analysis

```bash
python eval/analyze_benchmark.py \
  eval/results/benchmark_results.json \
  --output eval/results/BENCHMARK_RESULTS.md
```

**Compute**:
- Medians, IQRs per component
- Within-backend route comparisons (paired tests)
- Effect sizes, confidence intervals
- First-run vs steady-state

**Report actual findings**, not expected findings.

### 7.5 Document Results

`BENCHMARK_RESULTS.md`:
- Tables with measured times
- Statistical test results (p-values, CIs)
- Component breakdown plots
- Conclusions supported by data

**Time estimate**: 10-12 hours

---

## Phase 8: Thesis Writing

**Chapter 5: Evaluation**

### 5.1 Methodology Section

**Include**:
- Annotation guidelines (reference)
- Dataset composition (table)
- Error taxonomy (diagram)
- Evaluation metrics
- Benchmarking protocol

**Goal**: Reader can reproduce your evaluation.

### 5.2 Results Section

**Structure**:

**5.2.1 Overall Performance**
- Precision, recall, F1 on all three datasets
- Comparison across datasets (baseline, dev, test)
- Statistical tests for consistency

**5.2.2 Error Attribution Analysis** (CRITICAL SECTION)
- Error distribution by category (pie chart)
- Root cause vs contributing factors (table)
- Per-category breakdown (bar chart)
- Example errors with evidence

**Key insight**: "X% of errors originate in perception, Y% in reasoning"

**5.2.3 Scenario Analysis**
- Performance by category (table)
- Failure modes identified
- Ambiguous cases discussion

**5.2.4 Performance Benchmarking**
- Component timing breakdown (table)
- Route comparison results (bar chart with error bars)
- Statistical test results
- Effect sizes

**5.2.5 Comparison of Routes**
- Accuracy: Typed vs English (table)
- Performance: Timing comparison
- Trade-offs discussion

### 5.3 Discussion

**What worked**:
- Integration successful
- Rules capture some danger patterns
- Knowledge representation enables explainability
- [If confirmed] English route provides performance benefit

**What didn't work**:
- Static images cannot distinguish parked vs moving
- Depth estimation limited by ground-plane assumption
- Detection failures block reasoning
- Ambiguous cases require human judgment (X%)

**Lessons**:
- Perception quality gates reasoning effectiveness
- Rule design must match observable facts
- Single-frame analysis has fundamental limits
- Temporal information needed for full solution

### 5.4 Limitations

**Acknowledge openly**:
- Small test set (statistical power limited)
- Single domain (urban pedestrian danger)
- Hardware-specific performance results
- Annotation subjectivity in ambiguous cases

**Time estimate**: 15-20 hours

---

## Timeline

| Phase | Week | Hours | Cumulative |
|---|---|---|---|
| 1. Protocol (done) | 0 | 8 | 8 |
| 2. Instrument | 1 | 5 | 13 |
| 3. Baseline analysis | 1-2 | 7 | 20 |
| 4. Expand dataset | 2-3 | 18 | 38 |
| 5. Dev evaluation | 4 | 9 | 47 |
| 6. Test evaluation | 4 | 5 | 52 |
| 7. Benchmarking | 5 | 11 | 63 |
| 8. Thesis writing | 5-6 | 18 | 81 |

**Total**: ~80 hours over 6 weeks

---

## Success Criteria (Revised)

### Process Success (Can Claim)

- [ ] Evaluation protocol defined before data collection
- [ ] Annotations follow explicit guidelines
- [ ] Test set never used for development
- [ ] All errors attributed with evidence
- [ ] Performance measurements controlled and reproducible
- [ ] Statistical tests appropriate for data
- [ ] Limitations acknowledged

### Outcome Success (Cannot Guarantee)

- ⏳ System achieves ≥X% F1 (depends on task difficulty)
- ⏳ English route faster than typed (hypothesis, not assumption)
- ⏳ Reasoning errors < Perception errors (to be measured)
- ⏳ Inter-annotator agreement ≥ 0.7 (may reveal task ambiguity)

**Key point**: Process rigor matters more than specific metric values.

A thesis showing "System achieves 35% F1; 60% of errors trace to perception limitations; static images fundamentally cannot solve X% of cases" is MORE VALUABLE than "System achieves 85% F1" with no error analysis.

---

## Checkpoints

**Before Phase 2**:
- [ ] Guidelines reviewed by second person
- [ ] Taxonomy makes sense for your system
- [ ] Protocol addresses confounds

**Before Phase 4**:
- [ ] Instrumented evaluator tested on baseline
- [ ] Error analysis script works
- [ ] Baseline error attribution complete

**Before Phase 6**:
- [ ] Dev set fully annotated
- [ ] Inter-annotator agreement measured
- [ ] System configuration frozen

**Before Phase 8**:
- [ ] All evaluations complete
- [ ] All data archived
- [ ] Results reproducible

---

## Red Flags

**STOP and reconsider if**:
- Inter-annotator agreement κ < 0.5 (task too subjective)
- >30% of cases marked ambiguous (labels undefined)
- Test results drastically different from dev (data leakage?)
- Statistical tests show no effects but visual inspection "clearly" shows difference (underpowered or measurement error)
- Benchmarking shows >50% variance (environmental confounds)

These aren't failures — they're informative findings about the task itself.

---

## Deliverables Checklist

- [ ] `ANNOTATION_GUIDELINES.md`
- [ ] `ERROR_TAXONOMY.md`
- [ ] `BENCHMARKING_PROTOCOL.md`
- [ ] `EXECUTION_PLAN.md` (this document)
- [ ] `annotations_dev.json`
- [ ] `annotations_test.json`
- [ ] `BASELINE_ERROR_ANALYSIS.md`
- [ ] `evaluate.py` (modified with detailed output)
- [ ] `analyze_errors.py` (with root cause + contributing factors)
- [ ] `benchmark_performance.py`
- [ ] `analyze_benchmark.py`
- [ ] `BENCHMARK_RESULTS.md`
- [ ] Thesis Chapter 5 draft

---

## Final Notes

**This is a CORRECTED plan based on methodological review.**

Key changes from original:
1. ✅ Precise label definitions BEFORE collection
2. ✅ Root cause vs contributing factors separated
3. ✅ Backend confound fixed in benchmarking
4. ✅ Dependencies sequenced properly
5. ✅ Hypothetical results removed
6. ✅ Test set protection emphasized

**Execute this plan**, not the original roadmap.

The goal is **rigorous research**, not impressive-looking numbers.
