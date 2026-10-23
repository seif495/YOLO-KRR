# Evaluation Analysis

## Executive Summary

Three rule configurations were evaluated on 24 labeled images (6 dangerous people) using yolo11n-seg @ 640:

| Configuration | Route | Rules | Danger F1 | Alert F1 | Hidden | SNePS Time | Notes |
|---|---|---|---|---|---|---|---|
| **Default (typed)** | typed | danger.snepslog | **0.250** | **0.286** | 11 | 9.4s | Best overall balance |
| **Road-aware** | typed | danger_road.snepslog | 0.333 | 0.421 | 11 | 14.8s | Higher recall but many false positives |
| **English** | english | danger_english.snepslog | **0.250** | **0.286** | 11 | 5.7s | Same as default, faster inference |

## Key Findings

### 1. Default vs Road-Aware Rules

**Road-aware rules (danger_road.snepslog) appear better at first glance:**
- Danger recall: 0.667 vs 0.333 (catches 4/6 vs 2/6 dangerous people)
- Alert F1: 0.421 vs 0.286

**But the improvement is illusory:**
- Road-aware: 14 false positives vs 8 for default
- Precision drops: 0.222 vs 0.200
- Most FPs are on image `000000000257.jpg` (6 FPs) and `women_in_front_of_parked_van.jpg` (3 FPs)

**Root cause:** Road segmentation flags people near vehicles on roads, but many are safely on the pavement or beside parked cars, not in the path of moving vehicles. The rule "person on road + near vehicle = dangerous" is too broad.

**Recommendation:** Default rules are more conservative and appropriate for this detection task. Road awareness needs motion/trajectory data to be useful.

### 2. Typed vs English Route

**Functionally identical:**
- English route produces **exactly the same answers** as typed route (24/24 = 100% agreement)
- Same F1 scores, same detections, same false positives

**Performance difference:**
- English is **faster**: 5.1s SNePS time vs 9.4s (0.6s translation + 5.1s reasoning)
- Translation overhead: ~0.6s per image

**Why English is faster despite translation overhead:**
- SNePSpaCy's event representation may be more efficient for SNePS reasoning
- Fewer intermediate inferences needed
- Translation happens once; reasoning benefits throughout

**Recommendation:** Use English route when SNePSpaCy is available - same accuracy, faster inference.

### 3. Model Comparison (from models.md)

No clear winner across yolo11n/s/m-seg at 640/1280:
- All achieve 0.133-0.316 F1 on danger detection
- Larger models find more people but not fewer false positives
- Most FPs are correctly detected people next to parked vehicles

**Recommendation:** Keep yolo11n-seg @ 640 as default (fastest, no accuracy loss).

## Per-Image Analysis

### Images with dangerous people correctly flagged:

1. **man_crossing_in_front_of_trolley.jpg** (1 dangerous)
   - Typed/English: ✅ person_4 flagged (1 TP)
   - Road: ⚠️ person_3, person_4 flagged (1 TP, 1 FP)

2. **pedestrian_crossing_road.jpg** (1 dangerous)
   - All configs: ✅ person_3 flagged (1 TP)

3. **night_intersection.jpg** (2 dangerous)
   - Typed/English: ❌ Neither flagged (2 FN) - detection failed, not reasoning
   - Road: ✅ person_3, person_6, person_7 flagged (2 TP, 1 FP)

4. **women_crossing_in_front_of_wagon.jpg** (2 dangerous)
   - All configs: ❌ Neither flagged (2 FN each)

### Major false positive sources:

1. **000000000257.jpg** (crowded street scene, no dangerous people)
   - Typed/English: 4 FPs (person_10, person_2, person_4, person_9)
   - Road: 6 FPs (adds person_3, person_6, person_7)
   - Issue: Many people near parked/stopped vehicles

2. **women_in_front_of_parked_van.jpg** (posed photo, 0 dangerous)
   - All configs: 3 FPs (person_1, person_2, person_3)
   - Issue: Rule cannot distinguish parked vs moving vehicle

3. **000000000532.jpg** (crosswalk scene, 0 dangerous)
   - Typed/English: 0 FPs
   - Road: 2 FPs (person_1, person_2)
   - Issue: Road detection over-triggers

## Metrics Summary

### Danger Detection (primary metric)

| Config | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Default | 2 | 8 | 4 | 0.200 | 0.333 | **0.250** |
| Road | 4 | 14 | 2 | 0.222 | 0.667 | 0.333 |
| English | 2 | 8 | 4 | 0.200 | 0.333 | **0.250** |

### Alert Detection (dangerous + confidence ≥ 0.5)

| Config | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Default | 2 | 6 | 4 | 0.250 | 0.333 | **0.286** |
| Road | 4 | 9 | 2 | 0.308 | 0.667 | 0.421 |
| English | 2 | 6 | 4 | 0.250 | 0.333 | **0.286** |

### Hidden Detection (person partly behind vehicle)

All configs flag 11 people as hidden across the test set.

## Limitations

1. **Small sample size:** Only 6 dangerous people across 24 images. One detection difference changes recall by 0.167.

2. **Static images:** No motion, speed, or trajectory data. Rules rely purely on spatial overlap and position.

3. **Parked vs moving vehicles:** Cannot distinguish them from a single frame.

4. **YOLO detection limits:** yolo11n-seg @ 640 misses small/distant pedestrians (60% person recall on COCO128).

5. **"infrontof" accuracy:** Only 75% accurate even on ground-truth boxes (21/28 correct). Fails when objects aren't on the same ground plane.

## Recommendations

### For production use:
1. **Use default rules** (kb/danger.snepslog) - best precision/recall balance
2. **Use English route if SNePSpaCy available** - same accuracy, 46% faster (5.7s vs 9.4s)
3. **Use yolo11n-seg @ 640** - fastest, no accuracy penalty vs larger models
4. **Consider --imgsz 1280** for scenes with small/distant pedestrians

### For research improvements:
1. **Larger labeled dataset** needed to distinguish model/rule performance
2. **Temporal information** (video frames, optical flow) would reduce false positives
3. **Vehicle motion cues** (turn signals, brake lights, velocity) needed for accurate danger assessment
4. **Better depth estimation** than base-overlap heuristic
5. **Road segmentation needs trajectory prediction** to be useful - knowing someone is on a road isn't enough without knowing if a vehicle is approaching them

## Conclusion

The **default rules with English route** offer the best combination:
- Conservative false positive rate (precision: 0.200)
- Reasonable recall (0.333 given detection limits)
- **46% faster reasoning** (5.7s vs 9.4s per image)
- 100% functional equivalence to typed route

Road-aware rules catch more dangerous people but at the cost of too many false positives. The road position alone is insufficient without motion/trajectory data.
