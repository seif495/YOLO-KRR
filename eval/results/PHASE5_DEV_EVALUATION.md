# Phase 5: Dev Evaluation and Rule Variants

Status: **dev complete; test not run.** Every number below comes from the 192-image dev set (`eval/annotations_dev.json`, guidelines v1.2). The test set has not been scored by any variant. The choice of variant and the decision to stop tuning were made by Claude on the author's behalf on 2026-10-31, and the author can overrule either.

| | |
|---|---|
| System | yolo11n-seg, 640 px, conf 0.25, typed route, Allegro backend (SNePS 2.7) |
| Road model | `nvidia/segformer-b0-finetuned-cityscapes-1024-1024`, asserting `onroad(x)` / `onsidewalk(x)` for people (`--road`) |
| Runs | `dev_typed`, `dev_v1_road`, `dev_v2_road_front`, `dev_v3_riders`, `dev_v4_road_front_riders` (`.json`, `.md`, `_detailed.jsonl`, `_config.json`) |
| Attribution | `<run>_error_attribution.json` from `eval/analyze_errors.py`; FP reasons from `eval/fp_breakdown.py` |

Dev has 854 annotated people. 19 of them are dangerous, in 11 images, all in the val2017 front stratum. Any one TP changes recall by 5 points, so read the recall column as counts.

## Variants

| Run | Rules | Danger rule |
|---|---|---|
| `dev_typed` (baseline) | `kb/danger.snepslog` | `infrontof(x,y), isa(x,human), isa(y,hazard)` |
| V1 `dev_v1_road` | `kb/danger_road.snepslog` | V2's rule, plus `near(x,y)` / `near(y,x)` with `onroad(x)` |
| V2 `dev_v2_road_front` | `kb/danger_road_front.snepslog` | `infrontof(x,y), onroad(x), isa(x,human), isa(y,hazard)` |
| V3 `dev_v3_riders` (`--riders`) | `kb/danger_riders.snepslog` | `infrontof(x,y), pedestrian(x), isa(y,hazard)` |
| V4 `dev_v4_road_front_riders` (`--road --riders`) | `kb/danger_road_front_riders.snepslog` | `infrontof(x,y), onroad(x), pedestrian(x), isa(y,hazard)` |

`--riders` adds `rides(p, v)` facts from `relations.riders()` and `pedestrian(p)` for every person who rides nothing. In V3 and V4, `hidden(x)` also requires `pedestrian(x)`.

## Results

| Run | `dangerous` TP / FP / FN | Precision | Recall | F1 | `alert` TP / FP / FN | `alert` precision | Images with a dangerous person found | SNePS s / image |
|---|---|---|---|---|---|---|---|---|
| baseline | 6 / 102 / 13 | 0.056 | 0.316 | 0.094 | 6 / 84 / 13 | 0.067 | 5/11 | 7.9 |
| V1 road + near | 6 / 137 / 13 | 0.042 | 0.316 | 0.074 | 6 / 110 / 13 | 0.052 | 5/11 | 15.9 |
| V2 road | 6 / 51 / 13 | 0.105 | 0.316 | 0.158 | 6 / 47 / 13 | 0.113 | 5/11 | 9.4 |
| V3 riders | 6 / 90 / 13 | 0.062 | 0.316 | 0.104 | 6 / 73 / 13 | 0.076 | 5/11 | 7.7 |
| **V4 road + riders** | **6 / 43 / 13** | **0.122** | 0.316 | **0.176** | **6 / 40 / 13** | **0.130** | 5/11 | 8.6 |

| Run | `hidden` TP / FP / FN | Precision | Recall |
|---|---|---|---|
| baseline, V1, V2 | 34 / 101 / 25 | 0.252 | 0.576 |
| V3, V4 | 32 / 76 / 27 | 0.296 | 0.542 |

**By stratum (`dangerous` FP).** The front stratum carries almost every FP: 101 for the baseline, 42 for V4. The behind and apart strata (24 and 26 images, no dangerous people) give 1 and 0 FPs in every variant except V1, which gives 17 and 5. Each run's `.md` has the full per-stratum table.

### What the variants show

- **No rule change moved recall.** All five variants find the same 6 of 19 dangerous people. Every FN comes from perception, not the rules:

  | FN cause | Count |
  |---|---|
  | Bus not detected (`1b`), all in one image, `000000353180` | 7 |
  | Depth order wrong (`2a`) | 3 |
  | Person not detected (`1a`) | 2 |
  | Poor localization (`1d`) | 1 |

  A rule can only narrow what the baseline flags, so recall cannot rise until detection or the depth cue improves.
- **The road filter halves the FPs with no TP lost** (V2: 102 to 51). All six TPs stand on segmented road.
- **`near` is rejected** (V1: 35 more FPs than baseline, no TP). Two people at the same distance from the camera are rarely in each other's path, and `near` fires most in the behind and apart strata. It also doubles SNePS time. `analyze_errors.py` counts only `infrontof` as a trigger, so it cannot attribute V1's `near` FPs (85 `unknown`).
- **Rider detection removes FPs and improves hidden precision** (V3: rider/occupant/depiction FPs 21 to 9). The costs are 2 hidden TPs and the 13 safe non-riders the rider rule catches.
- **The two filters combine** (V4: 43 FPs). Precision doubles over the baseline, and the alert FPs fall from 84 to 40.

## Where V4's errors remain

`eval/fp_breakdown.py` tags each FP with every reason the annotator recorded, so one FP can carry several tags:

| Reason (from the judgments) | Baseline | V4 |
|---|---|---|
| Person judged off the road | 62 | 29 |
| Vehicle the rule fired on is not in a traffic area, or unclear | 40 | 23 |
| Rider, occupant or depiction | 21 | 3 |
| Flagged box matches no annotated person | 11 | 3 |
| None of these | 5 | 4 |
| **FPs** | **102** | **43** |

- **29 off-road people that segmentation put on the road.** Of these, 13 are in scenes the annotator judged safe as a whole, and 11 stand beside parked vehicles. Why SegFormer's mask covers their feet (paved ground, the edge of the mask, a person at a kerb) has not been checked image by image.
- **23 FPs on a vehicle outside the traffic area.** The vehicle overlaps the person only in the picture and stands somewhere else in the world. Examples:
  - cars parked beyond a sports field or behind a fence;
  - vehicles parked far off;
  - cars seen through a window or reflected in shop glass;
  - a bus parked on a quay.

  The rules have no fact about where the vehicle is, because `onroad` is asserted only for people.
- **4 FPs with none of these reasons.** They fire on a truck the annotations do not include, at an airport stand and in a car park, both scenes judged to be outside the traffic area.

## Decisions

- **V4 is the candidate for the test set.** It gives the best precision and F1 on every query except `hidden` recall, at about 9 s per image.
- **The dev numbers for V3 and V4 are optimistic.** The rider thresholds in `relations.riders()` were set on the dev ground truth, so dev measures fit, not generalization. Only the test run will give an honest figure.
- **The test set is run once, with V4 and the baseline side by side,** and only after the author agrees. No further variant is tried on test.

## Next steps (dev only)

1. **Vehicle location.** Assert `onroad(y)` for hazards as well as people, and try requiring it. This targets the 23 traffic-area FPs. Trucks and buses at a kerb or a stop may still count as on road.
2. **Recall.** A larger detector or a higher image size for the bus in `000000353180` would recover 7 of the 13 FNs. `eval/results/models.md` holds earlier model comparisons.
3. **Attribute `near`.** Extend `analyze_errors.py` to `near` triggers only if `near` comes back into a rule.
