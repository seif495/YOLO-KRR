# Baseline Error Analysis (24 images)

Phase 3 of `eval/EXECUTION_PLAN.md`. Status: **complete**. The manual review (step 3.2) and the decision on what counts as dangerous were made by Claude on the author's behalf on 2026-10-27, and the author can overrule either.

| | |
|---|---|
| Run | `baseline_instrumented` (committed in `0a51271`): yolo11n-seg, 640 px, conf 0.25, `kb/danger.snepslog`, typed route, Allegro backend. Labels as first annotated, before the guidelines existed. |
| Re-scored run | `baseline_v1_1`: the same system re-run on 2026-10-27 against the labels corrected to guidelines v1.1. Its detections, facts and SNePS answers are identical to the first run's; only the ground truth of two images differs. |
| Attribution | `baseline_error_attribution.json` and `baseline_v1_1_error_attribution.json`, from `eval/analyze_errors.py` |
| Audit | `eval/audit_baseline_v2.py`: 5 of 5 checks pass on both runs |

This report supersedes `BASELINE_AUDIT_REPORT.md`, `AUDIT_SUMMARY.txt`, `AUDIT_V2_FINDINGS.md`, `AUDIT_OF_AUDIT_REPORT.md`, `STEP2_ANSWERS.md` and the v2/v3 attribution files; the corrections are listed at the end.

## Metrics

| Measure | Labels | TP / FP / FN | Precision | Recall | F1 |
|---|---|---|---|---|---|
| `dangerous(x)` | original | 2 / 8 / 4 | 0.20 | 0.33 | 0.25 |
| `dangerous(x)` | v1.1 | 2 / 8 / 0 | 0.20 | 1.00 | 0.33 |
| `alert(x)` (dangerous and confidence >= 0.5) | original | 2 / 6 / 4 | 0.25 | 0.33 | 0.29 |
| `alert(x)` | v1.1 | 2 / 6 / 0 | 0.25 | 1.00 | 0.40 |

Under v1.1 the baseline has only two dangerous people, so recall 2/2 means "both were found", not a rate. Precision does not change. The original-label row is the one measured before anyone looked at the errors.

Unchanged by the relabel: `hidden(x)` flags 11 people (no ground truth); the infrontof cue on the annotated pairs' true boxes is right for 21 of 28 pairs with a known depth order (no answer for 5); person recall on the coco128 images is 50/83.

## Decision: what counts as dangerous

**Keep the guidelines' observable definition and fix its overlap test.** Danger means the person's box overlaps the vehicle's, the person's base is lower in the image, the vehicle is in a traffic area and no barrier separates them. The guidelines are now v1.1. The new version was applied to the baseline by checking all 107 labelled people, not only the errors:
- **Q1 used IoU > 0.1, which is the wrong measure.** The clearest positive in the set, a man crossing in front of a tram, overlaps it at IoU 0.05, because IoU is tiny when a person stands before a large vehicle. v1.1 asks whether the boxes overlap at all.
- **The four people the system missed overlap no vehicle.** Like v1.0, v1.1 labels a "pedestrian beside vehicle with no overlap" FALSE, so their labels changed to FALSE, each with a note in `eval/annotations.json`.
- **All 20 people labelled safe whose boxes pass the overlap and base tests stay safe.** Each was checked on the image; all are in a safe area or behind a barrier (Q3/Q4):
  - the food-truck plaza in 257 (11 people);
  - the parking at the edge of the kite field in 149;
  - a bench behind a fence in 328;
  - a tennis court in 531;
  - a terminal kerb in 260;
  - the pavement in the van image (2 people);
  - the man at the door of the stopped bus in 532, who stands level with it at its side.

  In 443 the "hazard" is a cat.
- **Both TRUE labels hold.** Four labels changed, all from TRUE to FALSE.

**Why not broaden the definition instead.** Calling those four people dangerous requires predicting where the scooter or the horse goes next. The guidelines exclude that, because it is not visible in one frame and annotators would disagree on it. A rule could not check it from one frame either.

**What this costs, to be stated wherever these results are reported:**
- The relabel was made after seeing the system's errors, and it removes all four false negatives. Both results are therefore reported, and the original-label one is the blind measurement.
- Under v1.1 the definition of danger is close to the rule's own geometry (overlap plus a lower base). Against these labels the system is tested on detection, on the depth cue, and on the context the rule lacks (Q3/Q4). It is not tested on whether "in front and overlapping" is the right notion of danger; that notion is a design choice of the project, and results against these labels should say so.
- People about to step into a vehicle's path are out of scope for single-frame labels. Phase 4 should still collect them, label them per v1.1 and tag them `category: crossing`, so they can be counted separately.

## Error distribution (root causes)

| Root cause | FP (original) | FN (original) | FP (v1.1) | FN (v1.1) |
|---|---|---|---|---|
| 4b Rule Too Broad | 7 | 0 | 7 | 0 |
| 4c Rule Too Narrow | 0 | 4 | 0 | 0 |
| Unmatched detection (duplicate box) | 1 | 0 | 1 | 0 |
| **Total** | **8** | **4** | **8** | **0** |

Under the original labels, rules account for 11 of 12 errors; under v1.1 they account for 7 of 8. The remaining error is a duplicate person box (perception). No error traces to detection, geometry or knowledge representation; see limitation 1 before reading that as a finding about perception.

Contributing factor: 5b (Not Dangerous but Confident) on 6 of the 8 FPs. These people were also alerted, which accounts for all 6 alert FPs.

## Errors with evidence

Every error is reconciled with the evaluator image by image. "Vehicle" is the detection the rule fired on (FP) or the nearest hazard (FN), linked to the annotation by box overlap. #6 to #9 are errors only under the original labels.

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

The numbers follow the original-label attribution file and the overlays from `python eval/render_errors.py`, which are written to `eval/review/` and not committed. The errors come from 5 images: 257 (4), van (3), wagon (2), night intersection (2), 260 (1).

## Key findings

**1. False positives: the rule fires on a true premise in scenes annotated safe (7 of 8).** In every case the annotated pair agrees that the person is nearer the camera than the vehicle, so detection and geometry are right and the rule concludes `dangerous` from a premise that holds. Guidelines v1.1 exclude motion but do use location: Q3 says a vehicle on a sidewalk, in a parking lot or in another safe area means not dangerous. The typed route has no location facts, so it cannot make that distinction. The existing road-context run (`road-yolo11n-seg-640`, `kb/danger_road.snepslog`) does not fix it on this set: it has 14 FPs against 8. Rule changes belong to Phase 5 and the dev set, not to this baseline.

YOLO named the annotated truck in 257 a bus and the van a truck. Both are hazard classes, so the outcome is unaffected. The earlier analyzer matched hazards by class name and so cited the wrong vehicles for #1, #2, #10 and #11.

The seven FPs come about in two ways:
- **A. The vehicle is parked in a pedestrian area, or the person is on the pavement (#1, #3, #4, #10, #11).** In 257 the vehicle is a food truck parked on a plaza with its serving hatch open and customers at the hatch. In the van image the van stands at the kerb and the two women walk on the pavement in front of it.
- **B. The overlap is in the picture only (#2, #5).** A person close to the camera overlaps a vehicle many metres behind them: the man with a stroller in the foreground of the 257 plaza, and the woman with a luggage trolley on a terminal kerb in 260, with a car far across the road. `infrontof` is true, since the person is nearer the camera, but the person is nowhere near the vehicle.

B looks like it needs a bound on how far in front of the vehicle the person may be. The true positive in `pedestrian_crossing_road.jpg`, however, is also far in front of the cars he overlaps: his base is 18% of the image height below theirs, against 25% for #2 and 36% for #5. A threshold between 18% and 25% would separate the three, but it would be fitted to three people. What visibly separates them is location: he is on the carriageway, while #2 and #5 are on a plaza and a kerb. A and B therefore both come down to location context. Count them separately on the dev set, but test location context first.

**2. False negatives (original labels): the danger rule cannot fire for people beside a vehicle (4 of 4). This is not a depth or occlusion failure.**
- All four people were detected with confidence 0.65 to 0.84, and the relations asserted for them (`leftof`, `near`) are correct.
- None of their boxes overlaps any vehicle, in the detections or in the annotations. `infrontof` is only asserted for overlapping boxes (`yolo_sneps/relations.py`), and the danger rule only uses `infrontof`.
- The earlier reports blamed "depth estimation or occlusion"; there is no depth estimation in the pipeline and nothing is occluded here.
- In the wagon image, the horse stands hitched to a loaded cart and faces away from the two women, who walk alongside the cart, level with its wheel. The cart is not a COCO class, so neither YOLO nor the annotation has it.
- In the night intersection, both people are on a zebra crossing to the right of a scooter that is stopped at the crossing and angled towards them. Other people on the same crossing are labelled safe.

Both labels rest on where the vehicle goes next, which guidelines v1.1 rule out, so they are FALSE under v1.1 (see the decision above).

**3. One duplicate detection becomes a false positive.** person_3 in the van image is a second box on the woman already matched to person_2. Duplicate suppression in `yolo_sneps/scene.py` let it through, and the evaluator correctly counts it as an FP. In the same image, car_1 is a second box on the van's front. Eight of the 24 images have person boxes overlapping each other at IoU > 0.3.

**4. The evaluator's matcher is correct.** The earlier audit reported a "first-match bug" in `evaluate_instrumented.py` for 000000000136.jpg, but the matching is right:
- person_1 overlaps GT person 1 (IoU 0.87) more than GT person 0 (0.71), so one-to-one matching rightly gives person_1 to GT person 1 and person_2 to GT person 0 (0.53).
- The swap is impossible: person_2 overlaps GT person 1 at only 0.34, below the 0.5 threshold.

The audit now checks that matchings are stable instead of checking that each person got the box that overlaps them most. The first-match bug was real only in the old `analyze_errors.py`, which also dropped flagged detections matching nobody; that is how 2 of the 8 FPs went missing.

## Limitations

1. **Recall on dangerous people cannot show detection errors.** All of the baseline's dangerous people are in the six `examples/` images. All 24 annotated person boxes in those images match a YOLO box at IoU >= 0.995, so they were evidently seeded from the detector's output, and the repository does not say otherwise. A person YOLO missed there was never annotated, which makes 1a (missing person) impossible for dangerous people in this baseline. Phase 4 ground truth must be drawn independently of the detector.
2. **The sample is small.** The original labels give 12 errors from 5 images; v1.1 leaves 2 dangerous people. The distributions above describe these images; they do not estimate rates.
3. **The labels only partly follow the guidelines.** The `dangerous` labels were checked against v1.1 (see the decision), but there are still no `confidence_gt`, `hidden` or scene metadata fields. Category 6 (ambiguity) cannot be assigned without `confidence_gt`. The hazards still include a cat and a dog, which the rules do not treat as hazards.
4. **v1.1 labels share the rule's geometry**, so they test the rule's context, not its notion of danger (see the decision).
5. **Only `dangerous(x)` is attributed.** Alert errors appear only as the 5b contributing factor, and `hidden(x)` has no ground truth.

## Manual review (plan step 3.2)

The reviewer was Claude, on the author's behalf, on 2026-10-27, working from the overlays and the full images. Verdicts are on the original-label errors.

| # | Proposed root cause | Verdict | Confidence | Notes |
|---|---|---|---|---|
| 1 | 4b | 4b confirmed | confident | A: woman at a drinking fountain on the plaza; the "truck" is a food truck parked on the plaza |
| 2 | 4b | 4b confirmed | confident | B: man with a stroller in the foreground; the food truck is far behind him |
| 3 | 4b | 4b confirmed | confident | A: customer at the food truck's serving hatch |
| 4 | 4b | 4b confirmed | confident | A: as #3 |
| 5 | 4b | 4b confirmed | confident | B: woman with a luggage trolley on the kerb; the car is across the road |
| 6 | 4c | Label error under v1.1, relabelled FALSE; not a system error | confident | Beside a standing horse and cart, walking level with the cart; the horse faces away |
| 7 | 4c | As #6 | confident | As #6 |
| 8 | 4c | Label error under v1.1, relabelled FALSE; not a system error | uncertain | On a zebra crossing beside a stopped scooter angled towards her. FALSE follows from the rule "beside vehicle, no overlap"; if the definition is ever broadened, this is the first case to flip |
| 9 | 4c | As #8 | uncertain | As #8 |
| 10 | 4b | 4b confirmed | confident | A: walking on the pavement in front of a van at the kerb |
| 11 | 4b | 4b confirmed | confident | A: as #10 |
| 12 | unmatched | Confirmed: duplicate person box | confident | person_3 is a narrower second box on the woman person_2 covers |

Also settled: in the van image, car_1, which matches no annotated hazard, is a second YOLO box on the van's front, not a car missing from the annotations.

Still open: where the example images' person boxes come from (limitation 1). Treat them as detector-seeded.

## Implications for Phase 4

- **Annotate with guidelines v1.1 and draw person boxes independently of YOLO** (limitation 1). Record pairs for every person within about 50 px of a vehicle (guidelines step 3.1), plus `confidence_gt`.
- **Include scenes that separate the FP mechanisms:** people in front of vehicles in parking lots, at kerbs and in active lanes (A), and people near the camera with vehicles far behind them, both on and off the carriageway (B). Record the vehicle's and the person's location, so that location context can be tested.
- **Include pedestrians next to but not overlapping a vehicle's path,** labelled per v1.1 and tagged `category: crossing`, so the cost of the definition can be measured.

## Corrections to the earlier Phase 3 reports

| Earlier claim | Correct |
|---|---|
| 10 errors, all confirmed (`BASELINE_AUDIT_REPORT.md`, `AUDIT_SUMMARY.txt`) | 12 errors: 8 FP + 4 FN (original labels) |
| `evaluate_instrumented.py` has a first-match matcher bug that must be fixed before Phase 3 (`AUDIT_OF_AUDIT_REPORT.md`) | No such bug; see finding 4 |
| The 4 FNs are depth estimation or occlusion failures, "reasoning failures (depth cue failures)" | 4c: the rule needs overlapping boxes and these people do not overlap any vehicle (finding 2); relabelled FALSE under v1.1 |
| The FNs to review in night_intersection.jpg are persons 6 and 7 | GT persons 0 and 1; person_6 and person_7 are detection labels |
| The FPs in 257 (persons 0 and 8) and in the van image fire on the vehicles of the annotated class | They fire on bus_1 and truck_1, the detections that overlap the annotated truck and van |
| The detailed results' SHA-256 is `FECF1A2B...` | That is `annotations.json`'s hash. `HASHES.txt` hashes CRLF checkouts, so it will not match on WSL or Linux. |
| `STEP2_ANSWERS.md` line citations (`evaluate_instrumented.py:420-435`, `kb/danger.snepslog:87`) | Those lines do not exist; matching is `evaluate.match`, facts come from `yolo_sneps/relations.py` |

## Reproduce

```bash
python eval/evaluate_instrumented.py --model yolo11n-seg.pt --backend allegro --sneps-dir <SNePS folder> --name baseline_v1_1
python eval/analyze_errors.py eval/results/baseline_v1_1_detailed.jsonl --annotations eval/annotations.json --output eval/results/baseline_v1_1_error_attribution.json
python eval/audit_baseline_v2.py --results eval/results/baseline_v1_1_detailed.jsonl --summary eval/results/baseline_v1_1.json --attribution eval/results/baseline_v1_1_error_attribution.json
python eval/analyze_errors.py eval/results/baseline_instrumented_detailed.jsonl --output eval/results/baseline_error_attribution.json
python eval/audit_baseline_v2.py
python eval/render_errors.py
python -m unittest discover -s tests
```

The original run was scored against the labels as of `0a51271` (`git show 0a51271:eval/annotations.json`), so it is analysed without `--annotations`.
