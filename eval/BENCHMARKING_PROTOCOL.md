# Performance Benchmarking Protocol
## Rigorous Measurement of Reasoning Route Performance

**Version**: 1.0  
**Date**: 2026-10-23  
**Status**: Design document — results TBD

---

## Research Question

**Does the English route provide a performance advantage over the typed route for SNePS reasoning?**

**Current observation**: Preliminary single-run comparison showed English route completed in 5.7s vs typed 9.4s per image (39% reduction in total time).

**This protocol**: Establishes controlled, reproducible methodology to test whether that difference is:
1. Statistically reliable
2. Attributable to the route (not backend/environment)
3. Consistent across images

---

## Experimental Design

### Confound Identified

**Problem with initial comparison**:
- Typed route measured on Allegro (Windows)
- English route measured on SNePSpaCy (WSL/Linux)

This confounds TWO variables:
- Route (typed vs English)
- Backend + Environment (Allegro/Windows vs SNePSpaCy/WSL)

**Cannot conclude**: "English is faster" might actually be "SNePSpaCy is faster" or "WSL is faster"

### Corrected Design

**Test all supported configurations**:

| Configuration | Route | Backend | Environment | Feasibility |
|---|---|---|---|---|
| Config A | Typed | Allegro | Windows | ✅ Supported |
| Config B | English | Allegro | Windows | ❓ Check if supported |
| Config C | Typed | SNePSpaCy | WSL | ✅ Supported |
| Config D | English | SNePSpaCy | WSL | ✅ Supported |

**Primary comparisons** (within same backend):
- **Allegro**: Config A vs Config B (typed vs English on Allegro)
- **SNePSpaCy**: Config C vs Config D (typed vs English on SNePSpaCy)

**Secondary comparison** (if both routes work on both backends):
- Check if English advantage consistent across backends

**Avoid**: Cross-backend comparisons (A vs D) unless explicitly investigating backend differences

---

## Timing Components

Measure separately for EACH image:

### 1. Preprocessing
- Image loading from disk
- Resizing to inference size
- Format conversion (if needed)

### 2. YOLO Inference
- Model execution (detection + segmentation)
- Postprocessing (NMS, filtering)

### 3. Fact Generation
- Geometric relation computation
- Filtering (focus pairs, confidence threshold)
- SNePSLOG formatting

### 4. Translation (English route only)
- English sentence generation
- SNePSpaCy parser invocation (if applicable)

### 5. SNePS Setup
- Knowledge base initialization
- Rule file loading
- Session start (if not persistent)

### 6. SNePS Reasoning
- Fact assertion
- Query execution (all 3 queries)
- Answer parsing

### 7. Total End-to-End
- Complete pipeline from image file to final answers

### Implementation

```python
import time
from contextlib import contextmanager

@contextmanager
def timer():
    start = time.perf_counter()
    yield lambda: time.perf_counter() - start

timings = {}

with timer() as t:
    # component work here
    pass
timings["component"] = t()
```

---

## Procedure

### Phase 1: Environment Setup

1. **GPU warmup**: Run 3 dummy inferences before measurement
2. **Backend warmup**: Initialize SNePS, run 2 dummy queries
3. **Verify configurations**: Confirm all 4 configs can run
4. **Document limitations**: If English + Allegro unsupported, note it

### Phase 2: Data Collection

**For each configuration**:
1. Cold start run (measure first-image overhead)
2. 10 subsequent runs (steady-state performance)
3. Same 24 baseline images in fixed order
4. Same YOLO model, confidence, image size
5. Clear backend state between images (unless testing persistent KB)

**Total measurements**: 
- 4 configs × 11 runs × 24 images = 1,056 timing records
- Or fewer if some configs unsupported

### Phase 3: Statistical Analysis

**For each configuration, compute**:
- Median time per component
- Interquartile range (Q3 - Q1)
- Mean and standard deviation (for comparison)
- Per-image variance (is one image consistently slower?)

**For route comparisons within backend**:
- Paired analysis (same image, different route)
- Compute differences: Δ = T_typed - T_english
- Test hypothesis: Is median(Δ) significantly different from 0?
- Report: median Δ, 95% confidence interval, effect size

**Statistical test**:
- Wilcoxon signed-rank test (paired, non-parametric)
- Or paired t-test if data approximately normal
- Two-tailed test (don't assume direction)
- α = 0.05

### Phase 4: Reporting

**Present**:
1. Component timing breakdown (table + chart)
2. Route comparison within each backend
3. Effect sizes (absolute time difference, percentage)
4. Confidence intervals
5. First-run overhead analysis
6. Variance across images

**DO NOT present**:
- Cross-backend comparisons as evidence of route differences
- Hypothetical or expected results as actual measurements
- Statistical significance without reporting the test used
- Percentage improvement without absolute times

---

## Expected Output Format

### Component Timing Table

```
Configuration: Typed route, Allegro backend, Windows
Dataset: 24 baseline images, 10 runs (steady-state)

Component         | Median (s) | IQR (s)    | Mean (s) | SD (s)
------------------+------------+------------+----------+--------
Preprocessing     | 0.12       | 0.11-0.13  | 0.12     | 0.01
YOLO Inference    | 0.28       | 0.27-0.30  | 0.28     | 0.02
Fact Generation   | 0.05       | 0.04-0.05  | 0.05     | 0.01
Translation       | —          | —          | —        | —
SNePS Setup       | 1.20       | 1.18-1.25  | 1.21     | 0.05
SNePS Reasoning   | 9.40       | 9.10-9.80  | 9.45     | 0.40
------------------+------------+------------+----------+--------
Total             | 11.05      | 10.75-11.4 | 11.11    | 0.45

First-run total: 12.34s (overhead: +1.23s, +11%)
```

### Route Comparison Table

```
Backend: Allegro

Component         | Typed (s)  | English (s) | Δ (s)     | % Change | CI (95%)
------------------+------------+-------------+-----------+----------+-----------
SNePS Setup       | 1.20       | 1.18        | -0.02     | -1.7%    | [-0.05, +0.01]
SNePS Reasoning   | 9.40       | [TBD]       | [TBD]     | [TBD]    | [TBD]
Translation       | —          | [TBD]       | +[TBD]    | N/A      | [TBD]
------------------+------------+-------------+-----------+----------+-----------
Total             | 11.05      | [TBD]       | [TBD]     | [TBD]    | [TBD]

Statistical test: Wilcoxon signed-rank, W=[TBD], p=[TBD]
Effect size: Cohen's d=[TBD]
Conclusion: [To be determined from actual results]
```

**Possible conclusions**:
- "English route reduces reasoning time by X seconds (Y%, p<0.05, CI: [a,b])"
- "No statistically significant difference detected (p=0.27, power=0.45)"
- "English route total time similar due to translation overhead (p=0.82)"
- "Results inconclusive; larger sample needed"

---

## Data Validity Checks

Before accepting results:

1. **Sanity checks**:
   - Total = sum of components (within 5% tolerance)
   - YOLO time consistent across configs (should be identical)
   - No timing < 0 or > reasonable maximum

2. **Consistency checks**:
   - Same images take similar time across runs (CV < 20%)
   - First run slower than median (expected warmup)
   - No single run is massive outlier (>3 SD from median)

3. **Environmental checks**:
   - No other heavy processes running
   - GPU not throttling (check temperatures if available)
   - Disk not swapping
   - Network not accessed during benchmark (local only)

---

## Limitations to Acknowledge

1. **Hardware-specific**: Results apply to tested hardware (Quadro M2000M, i7-6920HQ)
2. **Dataset-specific**: Results apply to 24 baseline images (may not generalize)
3. **Backend-specific**: Cannot compare Allegro vs SNePSpaCy directly
4. **Single-threaded**: No parallelization tested
5. **Memory state**: Assumes fresh KB per image (may differ in production)

---

## If English + Allegro Unsupported

**Scenario**: English route requires SNePSpaCy translation, which is Linux-only.

**What you CAN claim**:
- "On SNePSpaCy (Linux/WSL), English route reduces reasoning time by X%"
- "Comparison with Allegro not possible due to backend requirements"

**What you CANNOT claim**:
- "English route is inherently faster"
- "The difference is due to representation, not backend"

**Alternative**: If you can run English on Allegro by pre-translating:
1. Pre-translate all images to SNePSLOG using SNePSpaCy
2. Feed pre-translated facts to Allegro
3. Measure only reasoning time (exclude translation)
4. Compare reasoning time fairly on Allegro

This tests "Does English-style SNePSLOG reason faster?" separately from "Does the full English pipeline run faster?"

---

## Hypothesis Testing

### H₁: English Route Reduces Total Time

**Null hypothesis (H₀)**: No difference in total end-to-end time between routes  
**Alternative (H₁)**: English route total time ≠ Typed route total time  
**Test**: Wilcoxon signed-rank on paired differences, α=0.05  
**Decision rule**: 
- If p < 0.05 and CI excludes 0 → Reject H₀, routes differ
- Otherwise → Cannot conclude difference exists

### H₂: English Route Reduces Reasoning Time Specifically

**Null hypothesis (H₀)**: No difference in SNePS reasoning component  
**Alternative (H₁)**: English reasoning time ≠ Typed reasoning time  
**Test**: Same as H₁, but on reasoning component only  
**Interpretation**: If H₂ rejects H₀ but H₁ doesn't, translation overhead canceled reasoning gains

### H₃: Effect Size is Meaningful

Even if statistically significant, is the difference practically meaningful?

**Cohen's d effect sizes**:
- d < 0.2: Negligible
- 0.2 ≤ d < 0.5: Small
- 0.5 ≤ d < 0.8: Medium
- d ≥ 0.8: Large

Report both statistical significance AND effect size.

---

## Timeline

| Phase | Duration | Tasks |
|---|---|---|
| Setup | 1-2 hours | Verify configs, implement timing, test on 3 images |
| Cold start | 30 min | Run first-image measurements |
| Data collection | 2-3 hours | 10 runs × 4 configs × 24 images |
| Analysis | 2-3 hours | Compute statistics, generate plots |
| Validation | 1 hour | Check sanity, review outliers |
| **TOTAL** | **7-10 hours** | From protocol to final results |

---

## Deliverables

1. **Raw data file**: `benchmark_results.json` with all timing records
2. **Analysis script**: `analyze_benchmark.py` for reproducible stats
3. **Report**: `BENCHMARK_RESULTS.md` with tables, plots, conclusions
4. **Plots**:
   - Component breakdown by config (stacked bar chart)
   - Route comparison per component (grouped bar with error bars)
   - Per-image timing distribution (box plots)

---

## Review Before Running

- [ ] All 4 configurations identified and tested
- [ ] Timing instrumentation implemented and verified
- [ ] Statistical method chosen and implemented
- [ ] Output format defined
- [ ] Environmental controls in place (no background tasks)
- [ ] Expected run time acceptable (~10 hours)
- [ ] This protocol reviewed by second person

---

## Post-Experiment Checklist

- [ ] All planned measurements collected
- [ ] Data validity checks passed
- [ ] Outliers investigated (not just removed)
- [ ] Statistical tests run correctly
- [ ] Results match or contradict preliminary findings
- [ ] Limitations documented
- [ ] Conclusions supported by data (no overclaiming)
- [ ] Results reproducible (script + data archived)

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-10-23 | Initial protocol, corrected confound |

---

## Notes

**This is a design document.** Do not cite hypothetical results as findings.

The goal is to establish WHETHER the English route provides a measurable performance advantage, not to confirm that it does.

Negative results ("no significant difference found") are valid findings if the experiment is properly controlled.
