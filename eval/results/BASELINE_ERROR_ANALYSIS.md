# Baseline Error Analysis (24 images, 6 dangerous people)

Phase 3 of `eval/EXECUTION_PLAN.md`. Status: **draft, manual review (step 3.2) pending**.

| | |
|---|---|
| Run | `baseline_instrumented` (committed in `0a51271`): yolo11n-seg, 640 px, conf 0.25, `kb/danger.snepslog`, typed route, Allegro backend |
| Records | `eval/results/baseline_instrumented_detailed.jsonl`, summary `baseline_instrumented.json` |
| Attribution | `eval/results/baseline_error_attribution.json`, from `eval/analyze_errors.py` |
| Audit | `eval/audit_baseline_v2.py`: 5 of 5 checks pass (reconciliation, matcher, detection and FN accounting, evidence) |

This report supersedes `BASELINE_AUDIT_REPORT.md`, `AUDIT_SUMMARY.txt`, `AUDIT_V2_FINDINGS.md`, `AUDIT_OF_AUDIT_REPORT.md`, `STEP2_ANSWERS.md` and the v2/v3 attribution files; the corrections are listed at the end.

## Metrics

| Measure | TP / FP / FN | Precision | Recall | F1 |
|---|---|---|---|---|
| `dangerous(x)` | 2 / 8 / 4 | 0.20 | 0.33 | 0.25 |
| `alert(x)` (dangerous and confidence >= 0.5) | 2 / 6 / 4 | 0.25 | 0.33 | 0.29 |

`hidden(x)` flags 11 people (no ground truth). The infrontof cue on the annotated pairs' true boxes is right for 21 of 28 pairs with a known depth order (no answer for 5). Person recall on the coco128 images is 50/83.

## Error distribution (root causes)

| Root cause | FP | FN | Total | % |
|---|---|---|---|---|
| 4b Rule Too Broad | 7 | 0 | 7 | 58% |
| 4c Rule Too Narrow | 0 | 4 | 4 | 33% |
| Unmatched detection (duplicate box) | 1 | 0 | 1 | 8% |
| **Total** | **8** | **4** | **12** | 100% |

By stage: reasoning (rules) 11 of 12; the remaining one is a duplicate person box (perception). No error traces to detection, geometry or knowledge representation, but see limitation 1 before reading that as a finding about perception.

Contributing factor: 5b (Not Dangerous but Confident) on 6 of the 8 FPs: these people were also alerted, which accounts for all 6 alert FPs.

## Errors with evidence

Every error is reconciled with the evaluator image by image. "Vehicle" is the detection the rule fired on (FP) or the nearest hazard (FN), linked to the annotation by box overlap.

| # | Type | Image | GT person | Detection (conf) | Root cause | Evidence | Needs review |
|---|---|---|---|---|---|---|---|
| 1 | FP | 000000000257.jpg | 8 | person_2 (0.31) | 4b | `infrontof(person_2, bus_1)`; bus_1 is the annotated truck (IoU 0.91), pair says person nearer | |
| 2 | FP | 000000000257.jpg | 0 | person_4 (0.78) | 4b, +5b | `infrontof(person_4, bus_1)`, same truck, pair says person nearer | |
| 3 | FP | 000000000257.jpg | 4 | person_9 (0.69) | 4b, +5b | `infrontof(person_9, truck_1)`, pair says person nearer | |
| 4 | FP | 000000000257.jpg | 7 | person_10 (0.60) | 4b, +5b | `infrontof(person_10, truck_1)`, pair says person nearer | |
| 5 | FP | 000000000260.jpg | 0 | person_1 (0.51) | 4b, +5b | `infrontof(person_1, car_1)`, pair says person nearer | |
| 6 | FN | women_crossing_in_front_of_wagon.jpg | 0 | person_2 (0.84) | 4c | only `leftof`/`near` with horse_1 (32 px apart); no hazard overlaps the person, detected or annotated; no pair annotated | yes |
| 7 | FN | women_crossing_in_front_of_wagon.jpg | 2 | person_1 (0.65) | 4c | as #6, horse_1 218 px apart | yes |
| 8 | FN | night_intersection.jpg | 0 | person_7 (0.81) | 4c | only `leftof`/`near` with motorcycle_1 (176 px apart); no overlap with any hazard; no pair annotated | yes |
| 9 | FN | night_intersection.jpg | 1 | person_6 (0.71) | 4c | as #8, motorcycle_1 90 px apart | yes |
| 10 | FP | women_in_front_of_parked_van.jpg | 0 | person_1 (0.90) | 4b, +5b | `infrontof(person_1, truck_1)`; truck_1 is the annotated "car" (the van), pair says person nearer | |
| 11 | FP | women_in_front_of_parked_van.jpg | 1 | person_2 (0.34) | 4b | as #10 | |
| 12 | FP | women_in_front_of_parked_van.jpg | - | person_3 (0.66) | unmatched, +5b | second box on GT person 1 (IoU 0.56), who is matched to person_2 (IoU 1.00) | yes |

Numbers follow the attribution file and the overlays from `python eval/render_errors.py` (written to `eval/review/`, not committed). The errors come from 5 images: 257 (4), van (3), wagon (2), night intersection (2), 260 (1).

## Key findings

**1. False positives: the rule fires on a true premise in scenes annotated safe (7 of 8).** In every case the annotated pair agrees that the person is nearer the camera than the vehicle, so detection and geometry are right and the rule concludes `dangerous` from a premise that holds. What the annotator used to call the scene safe is not recorded in the annotations; "parked vehicle" is a guess, not evidence. Guidelines v1.0 explicitly exclude motion but do use location (Q3: a vehicle on a sidewalk, in a parking lot or in another safe area means not dangerous). The typed route has no location facts, so it cannot make that distinction. The existing road-context run (`road-yolo11n-seg-640`, `kb/danger_road.snepslog`) does not fix it on this set: it has 14 FPs against 8. Rule changes belong to Phase 5 and the dev set, not to this baseline.

YOLO named the annotated truck in 257 a bus and the van a truck. Both are hazard classes, so the outcome is unaffected. The earlier analyzer matched hazards by class name and so cited the wrong vehicles for #1, #2, #10 and #11.

The overlays show two different mechanisms behind these seven FPs (first-pass observation, to be confirmed in review):
- **A. The vehicle is parked in a pedestrian area, or the person is on the pavement (#1, #3, #4, #10, #11).** In 257 it is a food truck parked on a plaza with its serving hatch open, with customers at the hatch. In the van image the van stands at the kerb and the two women walk on the pavement in front of it. Guidelines Q3 and "pedestrian on sidewalk" make these not dangerous; the rule has no fact that could tell.
- **B. The overlap is in the picture only (#2, #5).** A person close to the camera overlaps a vehicle that is many metres behind them: the man with a stroller in the foreground of the 257 plaza, and the woman with a luggage trolley on a terminal kerb in 260, with a car far across the road. `infrontof` is true (the person is nearer the camera), but the person is nowhere near the vehicle. The rule has no bound on how far in front the person may be. `near` already bounds the gap between the two bases, which suggests a hypothesis for Phase 5.

A and B need different fixes (location context; a depth-proximity bound), so they should be counted separately on the dev set.

**2. False negatives: the danger rule cannot fire for people beside a vehicle (4 of 4). This is not a depth or occlusion failure.** All four people were detected with confidence 0.65 to 0.84, and the relations asserted for them (`leftof`, `near`) are correct. None of their boxes overlaps any vehicle, in the detections or in the annotations. `infrontof` is only asserted for overlapping boxes (`yolo_sneps/relations.py`), and the danger rule only uses `infrontof`, so the rule cannot fire. The earlier reports blamed "depth estimation or occlusion"; there is no depth estimation in the pipeline and nothing is occluded here.

These four labels also conflict with `ANNOTATION_GUIDELINES.md` v1.0, which was written after the baseline was annotated (annotations 2026-10-22, guidelines 2026-10-23). The guidelines label "pedestrian beside vehicle with no overlap" as FALSE, and the decision tree stops at Q1 when boxes do not overlap. So either:
- the labels are wrong under the guidelines, or
- the guidelines and the rule together are too narrow, because they miss people stepping into a vehicle's path who do not yet overlap it in the image (the wagon scene).

The overlays point the same way (first-pass observation). In the wagon image the horse stands hitched to a loaded cart and faces away from the two women, who walk alongside the cart, level with its wheel. The cart is the vehicle they are next to, but it is not a COCO class, so neither YOLO nor the annotation has it. In the night intersection both people are on a zebra crossing to the right of a scooter that is stopped at the crossing and angled towards them, while other people on the same crossing are labelled safe. Both labels rest on where the vehicle will go next, and the guidelines exclude that ("whether vehicle is actually moving" is not considered). The frame alone gives FALSE or NULL.

This is a question about the definition of danger. It has to be settled on its merits and applied to every image before Phase 4 annotation starts. Relabelling these four people as safe would raise recall from 2/6 to 2/2 without any change to the system, so that is not a valid way to settle it.

No person-hazard pairs are annotated for these four people (see `ANNOTATION_FIXES_REQUIRED.md`). Adding pairs makes the attribution checkable but cannot change the outcome, because the boxes still do not overlap.

**3. One duplicate detection becomes a false positive.** person_3 in the van image is a second box on the woman already matched to person_2. Duplicate suppression in `yolo_sneps/scene.py` let it through, and the evaluator correctly counts it as an FP. Eight of the 24 images have person boxes overlapping each other at IoU > 0.3.

**4. The evaluator's matcher is correct.** The earlier audit reported a "first-match bug" in `evaluate_instrumented.py` for 000000000136.jpg, but the matching is right:
- person_1 overlaps GT person 1 (IoU 0.87) more than GT person 0 (0.71), so one-to-one matching rightly gives person_1 to GT person 1 and person_2 to GT person 0 (0.53).
- The swap is impossible: person_2 overlaps GT person 1 at only 0.34, below the 0.5 threshold.

The audit now checks that matchings are stable instead of checking that each person got the box that overlaps them most. The first-match bug was real only in the old `analyze_errors.py`, which also dropped flagged detections matching nobody; that is how 2 of the 8 FPs went missing.

## Limitations

1. **Recall on dangerous people cannot show detection errors.** All six dangerous people are in the six `examples/` images. All 24 annotated person boxes in those images match a YOLO box at IoU >= 0.995, so they were evidently seeded from the detector's output. A person YOLO missed there was never annotated, which makes 1a (missing person) impossible for dangerous people in this baseline. Phase 4 ground truth must be drawn independently of the detector.
2. **The sample is small.** 12 errors from 5 images, and 6 dangerous people in 4 images. The distribution above describes these images; it does not estimate rates.
3. **The annotations predate the guidelines.** They have no `confidence_gt`, `hidden` or scene metadata, and pairs are missing for the four FN people. Category 6 (ambiguity) cannot be assigned without `confidence_gt`.
4. **Only `dangerous(x)` is attributed.** Alert errors appear only as the 5b contributing factor, and `hidden(x)` has no ground truth.

## Manual review (plan step 3.2): to do

For each error the reviewer examines the image, detections and facts (`python eval/render_errors.py` draws them), then records a verdict and a confidence. Errors marked "Needs review" above are ones the script could not settle from the records.

The first-pass notes come from looking at the overlays while drafting this report. They are not the reviewer's verdict; the last two columns are for the reviewer.

| # | Proposed root cause | First-pass notes | Reviewer verdict | Confidence (confident / uncertain / needs_discussion) |
|---|---|---|---|---|
| 1 | 4b | A: woman at a drinking fountain on the plaza; the "truck" is a food truck parked on the plaza | | |
| 2 | 4b | B: man with a stroller in the foreground; the food truck is far behind him | | |
| 3 | 4b | A: customer at the food truck's serving hatch | | |
| 4 | 4b | A: as #3 | | |
| 5 | 4b | B: woman with a luggage trolley on the kerb; the car is across the road | | |
| 6 | 4c | Beside a standing horse and cart, walking level with the cart; the horse faces away. Label rests on assumed motion | | |
| 7 | 4c | As #6 | | |
| 8 | 4c | On the zebra crossing, right of a stopped scooter angled towards her; others on the crossing are labelled safe | | |
| 9 | 4c | As #8 | | |
| 10 | 4b | A: walking on the pavement in front of a van at the kerb | | |
| 11 | 4b | A: as #10 | | |
| 12 | unmatched (duplicate box) | Confirmed: person_3 is a narrower second box on the woman person_2 covers | | |

Also settled in the first pass, to be confirmed: the van image's car_1, which matches no annotated hazard, is a second YOLO box on the van's front, not a car missing from the annotations. #10 to #12 also fire on it, which leaves their root causes unchanged.

Still open: where in the source data do the example images' person boxes come from (limitation 1)?

## Implications for Phase 4

- **Include scenes that separate the FP mechanisms:** people in front of vehicles in parking lots, at kerbs and in active lanes (mechanism A), and people near the camera with vehicles far behind them (mechanism B). Record the vehicle's location so that location context can be tested.
- **Include pedestrians next to but not overlapping a moving vehicle's path.** Whichever way the definition question is settled, the dataset must contain such cases to measure it.
- **Annotate person boxes independently of YOLO** (limitation 1), and record pairs for every person within about 50 px of a vehicle, as guidelines step 3.1 requires.

## Corrections to the earlier Phase 3 reports

| Earlier claim | Correct |
|---|---|
| 10 errors, all confirmed (`BASELINE_AUDIT_REPORT.md`, `AUDIT_SUMMARY.txt`) | 12 errors: 8 FP + 4 FN |
| `evaluate_instrumented.py` has a first-match matcher bug that must be fixed before Phase 3 (`AUDIT_OF_AUDIT_REPORT.md`) | No such bug; see finding 4. No re-run is needed for it. |
| The 4 FNs are depth estimation or occlusion failures, "reasoning failures (depth cue failures)" | 4c: the rule needs overlapping boxes and these people do not overlap any vehicle (finding 2) |
| The FNs to review in night_intersection.jpg are persons 6 and 7 | GT persons 0 and 1; person_6 and person_7 are detection labels |
| The FPs in 257 (persons 0 and 8) and in the van image fire on the vehicles of the annotated class | They fire on bus_1 and truck_1, the detections that overlap the annotated truck and van |
| The detailed results' SHA-256 is `FECF1A2B...` | That is `annotations.json`'s hash. `HASHES.txt` hashes CRLF checkouts, so it will not match on WSL or Linux. |
| `STEP2_ANSWERS.md` line citations (`evaluate_instrumented.py:420-435`, `kb/danger.snepslog:87`) | Those lines do not exist; matching is `evaluate.match`, facts come from `yolo_sneps/relations.py` |

## Reproduce

```bash
python eval/analyze_errors.py eval/results/baseline_instrumented_detailed.jsonl --annotations eval/annotations.json --output eval/results/baseline_error_attribution.json
python eval/audit_baseline_v2.py
python eval/render_errors.py
python -m unittest discover -s tests
```
