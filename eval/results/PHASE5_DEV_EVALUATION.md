# Phase 5: Evaluation and Rule Variants

Status: **complete.** The variants were compared on the 192-image dev set (`eval/annotations_dev.json`, guidelines v1.2). The chosen variant, V5, and the baseline were then run once on the 295-image test set (see [Test set](#test-set)). Every section before that one uses dev only. Claude made the choice of variant and the decision to stop tuning on the author's behalf on 2026-10-31, and the author can overrule either.

| | |
|---|---|
| System | yolo11n-seg, 640 px, conf 0.25, typed route, Allegro backend (SNePS 2.7) |
| Road model | `nvidia/segformer-b0-finetuned-cityscapes-1024-1024`, asserting `onroad(x)` / `onsidewalk(x)` for people (`--road`), and for the rules' hazard classes too with `--road-hazards` |
| Runs | `dev_typed`, `dev_v1_road`, `dev_v2_road_front`, `dev_v3_riders`, `dev_v4_road_front_riders`, `dev_v5_road_vehicle_riders` (`.json`, `.md`, `_detailed.jsonl`, `_config.json`) |
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
| V5 `dev_v5_road_vehicle_riders` (`--road --road-hazards --riders`) | `kb/danger_road_vehicle_riders.snepslog` | `infrontof(x,y), onroad(x), onroad(y), pedestrian(x), isa(y,hazard)` |

`--riders` adds `rides(p, v)` facts from `relations.riders()` and `pedestrian(p)` for every person who rides nothing. In V3, V4 and V5, `hidden(x)` also requires `pedestrian(x)`.

## Results

| Run | `dangerous` TP / FP / FN | Precision | Recall | F1 | `alert` TP / FP / FN | `alert` precision | Images with a dangerous person found | SNePS s / image |
|---|---|---|---|---|---|---|---|---|
| baseline | 6 / 102 / 13 | 0.056 | 0.316 | 0.094 | 6 / 84 / 13 | 0.067 | 5/11 | 7.9 |
| V1 road + near | 6 / 137 / 13 | 0.042 | 0.316 | 0.074 | 6 / 110 / 13 | 0.052 | 5/11 | 15.9 |
| V2 road | 6 / 51 / 13 | 0.105 | 0.316 | 0.158 | 6 / 47 / 13 | 0.113 | 5/11 | 9.4 |
| V3 riders | 6 / 90 / 13 | 0.062 | 0.316 | 0.104 | 6 / 73 / 13 | 0.076 | 5/11 | 7.7 |
| V4 road + riders | 6 / 43 / 13 | 0.122 | 0.316 | 0.176 | 6 / 40 / 13 | 0.130 | 5/11 | 8.6 |
| **V5 road + vehicle on road + riders** | **6 / 27 / 13** | **0.182** | 0.316 | **0.231** | **6 / 26 / 13** | **0.188** | 5/11 | 9.8 |

| Run | `hidden` TP / FP / FN | Precision | Recall |
|---|---|---|---|
| baseline, V1, V2 | 34 / 101 / 25 | 0.252 | 0.576 |
| V3, V4, V5 | 32 / 76 / 27 | 0.296 | 0.542 |

**By stratum (`dangerous` FP).** The front stratum carries almost every FP: 101 for the baseline and 27 for V5. The behind stratum has 24 images and the apart stratum 26, with no dangerous people in either. Every variant except V1 gives at most 1 FP there, and V5 gives none. V1 gives 17 and 5. Each run's `.md` has the full per-stratum table.

### What the variants show

- **No rule change moved recall.** All six variants find the same 6 of 19 dangerous people. Every FN comes from perception, not the rules:

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
- **Requiring the vehicle to be on the road removes 16 more FPs with no TP lost** (V5: 27 FPs, precision 0.182, 26 alert FPs). All six TPs have a vehicle on segmented road.
- **The vehicle-ground cue is coarse.** `ground_under` reads the same band below a vehicle as below a person. On the dev ground-truth boxes it finds road under 50 of 92 vehicles judged in a traffic area, and under 39 of 133 judged outside one. When it drops a vehicle, it mostly finds no ground at all: the band is covered by other objects, or reads as building, fence or terrain.
- **How V5 was chosen.** Three vehicle conditions were first simulated on V4's recorded facts, using the dev segmentations. All three kept the 6 TPs:

  | Vehicle condition | FPs |
  |---|---|
  | On road | 27 |
  | Not on sidewalk, terrain, vegetation, fence or wall | 33 |
  | Not on terrain, vegetation, fence or wall | 38 |

  The simulation is exact. With no condition it reproduces V4 (6 / 43 / 13), and the SNePS run of the chosen condition gives the simulated 6 / 27 / 13.

## Where the errors remain

`eval/fp_breakdown.py` tags each FP with every reason the annotator recorded, so one FP can carry several tags:

| Reason (from the judgments) | Baseline | V4 | V5 |
|---|---|---|---|
| Person judged off the road | 62 | 29 | 15 |
| Vehicle the rule fired on is not in a traffic area, or unclear | 40 | 23 | 12 |
| Rider, occupant or depiction | 21 | 3 | 3 |
| Flagged box matches no annotated person | 11 | 3 | 2 |
| None of these | 5 | 4 | 4 |
| **FPs** | **102** | **43** | **27** |

In V4, 23 FPs fired on a vehicle outside the traffic area. Most of those vehicles overlap the person only in the picture: cars parked beyond a sports field or behind a fence, vehicles far off, cars seen through a window or reflected in shop glass, and a bus parked on a quay. V5's vehicle condition removes 11 of them.

What V5 still gets wrong:
- **15 people off the road that segmentation puts on it.** Many stand at a kerb or a stop beside a vehicle that really is on the road: people at a bus stop, a man on a bus-station platform, a guide on the kerb at a coach terminal. Both ground facts hold, and the person is simply on the other side of the kerb. Why SegFormer's mask covers their feet has not been checked image by image.
- **12 FPs on a vehicle outside the traffic area that segmentation puts on the road.** Examples are cars at a kerbside loading bay or in driveways, vans at a motorcycle show, and a scooter parked at a market in a car park.
- **3 people who are not pedestrians:**
  - a cyclist at the image edge;
  - a father riding a scooter with his daughter;
  - a statue on a bench.
- **2 boxes that match no annotated person.**
- **4 FPs with none of these reasons.** They fire on a truck the annotations do not include, at an airport stand and in a car park. The annotator judged both scenes to be outside the traffic area.

## Decisions

- **V5 is the candidate for the test set.** It gives the best precision and F1 on `dangerous` and `alert`, and the same `hidden` figures as V3, at about 10 s per image.
- **The dev numbers for V3, V4 and V5 are optimistic.** The rider thresholds in `relations.riders()` were set on the dev ground truth, and V5's vehicle condition was picked from three simulated on dev. Dev therefore measures fit, not generalization, and only the test run will give an honest figure.
- **The test set is run once, with V5 and the baseline side by side,** and only after the author agrees. No further variant is tried on test. The author asked for the run on 2026-10-31.

## Test set

The test set was run on 2026-10-31, once, with the baseline and V5 side by side as decided above. The runs are `test_typed` and `test_v5_road_vehicle_riders`. Neither the rules nor the thresholds were changed afterwards.

The test set has 295 images and 16 dangerous people in 10 images:

| Stratum | Images |
|---|---|
| val2017 front | 70 |
| val2017 behind | 12 |
| val2017 apart | 13 |
| train2017 front | 200 |

| Run | `dangerous` TP / FP / FN | Precision | Recall | F1 | `alert` TP / FP / FN | `alert` precision | Images with a dangerous person found |
|---|---|---|---|---|---|---|---|
| baseline | 11 / 224 / 5 | 0.047 | 0.688 | 0.088 | 10 / 194 / 6 | 0.049 | 7/10 |
| **V5** | **8 / 67 / 8** | **0.107** | 0.500 | **0.176** | 7 / 58 / 9 | **0.108** | 6/10 |

| Run | `hidden` TP / FP / FN | Precision | Recall |
|---|---|---|---|
| baseline | 40 / 157 / 57 | 0.203 | 0.412 |
| V5 | 38 / 124 / 59 | 0.235 | 0.392 |

`dangerous` TP / FP / FN by stratum:

| Stratum | Baseline | V5 |
|---|---|---|
| val2017 front | 1 / 64 / 2 | 0 / 25 / 3 |
| val2017 behind | 0 / 2 / 0 | 0 / 1 / 0 |
| val2017 apart | 0 / 0 / 0 | 0 / 0 / 0 |
| train2017 front | 10 / 158 / 3 | 8 / 41 / 5 |

**What held up on test:**
- **The FP cut held.** V5 removes 70% of the baseline's FPs on test (224 to 67), against 74% on dev.
- **Precision and F1 doubled.** Both still roughly double: precision 0.047 to 0.107, F1 0.088 to 0.176.
- **The depth cue behaved the same.** `infrontof` is right on 729 of 1182 annotated pairs (62%), against 56% on dev.

**What did not hold:**
- **Recall fell from 11 to 8 of 16.** On dev V5 lost no TP; on test it loses 3.
- **All three are missing facts (`3a`).** The person is annotated on the road, but SegFormer found neither road nor sidewalk under their feet, so `onroad(x)` was never asserted:
  - a rainy Mumbai street seen from a taxi;
  - a bus-crash scene with police among stopped cars;
  - a New York crosswalk in manhole steam.

  In the Mumbai street the truck had no `onroad(y)` either. Dev had no scene like these: wet, steamy or cluttered roads that a dash-camera model was not trained on.

**Which filter costs what on test.** This table is a diagnostic only, not a choice: it was made after the test run and is not used to pick a variant. Each combination of V5's three premises is recomputed from V5's recorded facts and statements. The recomputation reproduces every real run exactly: all five dev variants, the test baseline and test V5.

| Danger rule premises besides `infrontof`, `isa` | Dev TP / FP / FN | Test TP / FP / FN | Test F1 |
|---|---|---|---|
| none (baseline) | 6 / 102 / 13 | 11 / 224 / 5 | 0.088 |
| `onroad(x)` (V2) | 6 / 51 / 13 | 8 / 122 / 8 | 0.110 |
| `pedestrian(x)` (V3) | 6 / 90 / 13 | 11 / 193 / 5 | 0.100 |
| `onroad(x)`, `pedestrian(x)` (V4) | 6 / 43 / 13 | 8 / 102 / 8 | 0.127 |
| `onroad(y)` | 6 / 47 / 13 | 10 / 119 / 6 | 0.138 |
| `onroad(y)`, `pedestrian(x)` | 6 / 41 / 13 | 10 / 99 / 6 | 0.160 |
| all three (V5) | 6 / 27 / 13 | 8 / 67 / 8 | 0.176 |

What each premise does on test:
- **`onroad(x)` (the person on the road)** costs all 3 lost TPs and still pays for itself: with it, F1 is higher than without.
- **`onroad(y)` (the vehicle on the road)** costs 1 TP, in the Mumbai street.
- **`pedestrian(x)` (the rider check)** costs nothing.

**Remaining errors on test.**
- **FNs:**
  - the 3 missing road facts above;
  - 2 people YOLO boxed badly (`1d`);
  - 1 missed motorcycle (`1b`);
  - 1 depth order wrong (`2a`);
  - 1 missed person (`1a`).
- **FPs:** of V5's 67, 39 fire on a vehicle the annotator judged outside the traffic area and 36 on a person judged off the road. One FP can carry both reasons; `eval/fp_breakdown.py` gives the counts.

## Next steps (dev only)

1. **Recall.** A larger detector or a higher image size for the bus in `000000353180` would recover 7 of the 13 FNs. `eval/results/models.md` holds earlier model comparisons.
2. **People at the kerb.** Many of V5's remaining off-road FPs stand on the kerb beside a vehicle on the road. Two changes may separate them: a tighter ground band under the feet, or requiring most of the person's band to be road, not just its most common class.
3. **Attribute `near`.** Extend `analyze_errors.py` to `near` triggers only if `near` comes back into a rule.
4. **When no ground is found.** On test every lost TP had no ground class at all under the person. A variant could block only people found on a sidewalk and leave people with no ground unblocked. That would be tuned on dev, but the test set has now been seen: its result here should be quoted as V5's held-out figure, and any later variant needs a new held-out set.
