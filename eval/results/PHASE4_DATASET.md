# Phase 4 Dataset: Dev and Test Sets

Phase 4 of `eval/EXECUTION_PLAN.md`. Status: **dev and test sets annotated and checked**.

| | Dev | Test |
|---|---|---|
| File | `eval/annotations_dev.json` | `eval/annotations_test.json` |
| Images | 192 val2017 (142 front, 24 behind, 26 apart) | 95 val2017 (70 front, 12 behind, 13 apart) + 200 train2017 front; 1 excluded and replaced |
| People | 854 | 1,336 |
| Dangerous | 19 people in 11 images | **16 people in 10 images** (3 in val2017, 7 in train2017) |
| Hidden | 59 | 97 |
| Either label null | 56 | 173 |
| Riders / occupants / depictions | 66 / 83 / 14 | 110 / 115 / 22 |
| Night or dusk images | 13 | 21 |

The system has not been run on either set. All labels were made without seeing any system output, and the test set stays unused until Phase 6.

## Source and selection

**Images.** All images come from COCO, using COCO's human-drawn boxes; the detector is never involved. This avoids the baseline's problem, where the example images' person boxes were seeded from YOLO.

**Eligible images.** An image is eligible if it has 1 to 12 people, at least one car, motorcycle, bus, truck or train, and no crowd region. Each eligible image falls in one stratum, decided from COCO's boxes:
- **front:** a person overlaps a hazard and stands lower in the picture. Everyone who can be dangerous under the guidelines is in one of these images.
- **behind:** a hazard covers part of a person who stands higher. These are the candidates for hidden.
- **apart:** the rest.

val2017 has 498 eligible images (212 front, 174 behind, 112 apart); train2017 has 11,819 (5,488 front, 3,942 behind, 2,389 apart).

**How the sets were drawn.** Every rule below was fixed before any of its images were seen:
1. **Main draw (val2017).** Seeded random draw, seed 2026. Dev takes 50 front, 24 behind and 26 apart; test takes 25, 12 and 13.
2. **Front supplement (val2017).** The rest of the val2017 front stratum, 137 images. In draw order they went dev, dev, test, repeating, so 92 to dev and 45 to test. After this, val2017's front stratum is a census: every eligible image is in a set.
3. **train2017 draw (test only).** The val2017 census held only 3 test images with a dangerous person, so 200 front images were drawn from train2017 into the test set: shuffled with seed 2026, the baseline's 3 coco128 images left out, near-duplicates of already-selected images skipped. The next 50 images are the reserve. These form their own stratum, a random sample of train2017's front images.

**Reporting.** Results must be reported per stratum, or weighted. `check_annotations.py` prints each stratum's weight (eligible images ÷ images in the set):

| Stratum | Dev weight | Test weight |
|---|---|---|
| val2017 front | 1.49 | 3.03 |
| val2017 behind | 7.25 | 14.50 |
| val2017 apart | 4.31 | 8.62 |
| train2017 front | n/a | 27.44 |

**Exclusions and near-duplicates.**
- An image can only be excluded for a declared reason, and is replaced by the next reserve image of its stratum, COCO split and set.
- One test image was excluded as a near-duplicate of a dev image: the same skateboard jump taken 4 s apart, 11 bits apart in difference hash.
- Images closer than 11 bits are skipped automatically. An unrelated train2017 pair also sat at 11 bits, so the automatic threshold is now 10 bits, and every pair from 11 to 16 bits was checked by eye: 49 pairs, all different scenes.
- COCO's capture times do not identify scenes, so near-duplicates are found by image content.

**Checksums and licences.**
- Every image's SHA-256 is recorded in `eval/coco_selection.json`. The images stay outside the repository, in `<datasets_dir>/coco_<split>/images`.
- COCO's annotations are CC BY 4.0. The images keep their Flickr licences, recorded per image.
- Only image IDs, URLs and boxes are committed.

## Annotation

**Guidelines.** Both sets follow `ANNOTATION_GUIDELINES.md` v1.2, written before annotation started:
- Riders and occupants are not pedestrians.
- Q3 defines the traffic area. A car park's driving aisles count as traffic area; a parking bay or kerbside space does not.
- Boxes come from the dataset, never from the detector.

**Rules added during annotation.** Each addition was applied back to every image already judged:
- At dev image 129: a depicted person (statue, poster, reflection, model) is not a pedestrian.
- At dev image 129: a vehicle that overlaps a person only in the picture, standing far behind them, makes the label null.
- At test image 129: a depicted vehicle (toy, model, picture, reflection) is no hazard (`not_vehicle`).

**Process.** `eval/annotate_coco.py sheets` draws each image with numbered boxes, and the annotator records judgments per image:
- which of each person and nearby vehicle is nearer the camera;
- whether each vehicle is in the traffic area;
- whether each person is off the road;
- barriers between person and vehicle;
- distant vehicles;
- riders, occupants and depictions;
- motion state, confidence and notes.

`annotate_coco.py build` applies the decision tree to those judgments, so every label can be traced to recorded judgments, and it refuses to build if a judgment is missing. Any null label gets `confidence_gt: low`. The overlay never shows which person or vehicle stands lower in the picture, so depth is judged by occlusion and scene layout, not taken from the system's cue.

**Annotators.** Recorded per image in `annotation_metadata.annotator`:

| Annotator | Images |
|---|---|
| Claude Opus, on the author's behalf | all of dev; test images 0–158 |
| Claude Sonnet subagents, briefed with the guidelines and a dozen of Opus's judgments | test images 159–294 (136 train2017 images) |

**Review of the Sonnet labels.** Opus reviewed 27 images; each carries a `reviewed_by` note.
- **Every image Sonnet marked dangerous (6):** five confirmed. In one, a 1910s group posing by freight wagons on a siding, the wagons' traffic area was changed to unclear, so 6 people went from dangerous to null.
- **A random 15% sample (20 images):** drawn with seed 2026 before any were judged (`eval/annotation_review/review_sample.json`). On those 91 people, Sonnet and Opus agree on the dangerous label for 95.6% (Cohen's κ = 0.84). All 4 disagreements are people Sonnet left null and Opus judged safe: a woman on a pavement, and airport crew at a stationary belt loader. Opus's labels are used.
- **Not reviewed:** the sample has no dangerous people, so the κ describes safe-versus-null calls, not positives. The remaining Sonnet null labels outside the sample were not individually re-checked.

## Quality checks

`python eval/check_annotations.py`:
- **Schema checks pass.** Every image and person has the required fields with allowed values, and every pair refers to an existing person and hazard.
- **Split checks pass.** No image is in both sets or in the baseline, and no dev/test pair is a near-duplicate.
- **Rates are flagged as findings, not failures:** dangerous is 2% (dev) and 1% (test), against an expected 20–40%; hidden is 7%, against 10–20%.

| Stratum | Images | Dangerous people (images) | Hidden | Null |
|---|---|---|---|---|
| dev val2017 front | 142 | 19 (11) | 51 | 55 |
| dev val2017 behind | 24 | 0 | 8 | 1 |
| dev val2017 apart | 26 | 0 | 0 | 0 |
| test val2017 front | 70 | 3 (3) | 31 | 33 |
| test val2017 behind | 12 | 0 | 3 | 7 |
| test val2017 apart | 13 | 0 | 0 | 0 |
| test train2017 front | 200 | 13 (7) | 63 | 133 |

## Main finding: COCO holds few positives

Only a small share of images with a person in front of a vehicle show a pedestrian in danger:
- **val2017 front stratum (a census):** 14 of 212 images, 6.6%.
- **train2017 front sample:** 7 of 200 images, 3.5%.

Most people who overlap a vehicle they stand in front of are safe for a reason a box-only rule can't see: the vehicle is parked or outside the traffic area, the person is a rider or occupant, or the person is on a pavement or platform. This is the baseline's false-positive mechanism A at scale, and it makes these sets a strong test of precision and specificity.

**Recall** now rests on 19 positives in 11 images (dev) and 16 positives in 10 images (test). Positives are clustered within images: up to 6 in one dev image and 3 in two test images. Recall should therefore be reported by image as well as by person. With 10 positive test images, a 95% interval on image-level recall is still about ±30 points.

## Limitations

- **Two annotators within one test set.** Opus judged test images 0–158 and Sonnet judged 159–294, with Opus's review as described above. Results can be broken down by `annotation_metadata.annotator`. There is no second human annotator; the 176 test and 56 dev people with `confidence_gt: low` are where one would matter most.
- **The annotators are not independent of the system.** The same model family may later propose rule changes. This is mitigated, not removed: the guidelines were fixed before annotating, rules added midway were applied back to all images, labels follow mechanically from recorded judgments, and the sets have not been run.
- **People COCO did not box are invisible**, and they were not searched for systematically.
- **Some vehicles have no COCO class** (carts, golf carts, tuk-tuks, excavators, high-loaders), so they can only be annotated as their closest class, or not at all.
- **Scenario categories are derived.** `category` is computed from the labels and a scene judgment, so `clear_danger`, `hidden` and `ambiguous` mean "contains such a person", not a curated scenario type.
- **Hidden follows the box rule.** A vehicle nearer than the person must cover at least 20% of the person's box. At shows and markets that rule marks people standing behind parked motorcycles as hidden.

## Reproduce

```bash
python eval/coco_subset.py select --coco-json <datasets_dir>/coco_val2017/instances_val2017.json
python eval/coco_subset.py fetch
python eval/coco_subset.py exclude 000000426203.jpg --reason near_duplicate --note "same skateboard jump as dev image 000000084492.jpg, 4 s apart (11 bits)"
python eval/coco_subset.py supplement --stratum front
python eval/coco_subset.py draw-train --coco-json <datasets_dir>/coco_train2017/instances_train2017.json
python eval/annotate_coco.py build --split dev
python eval/annotate_coco.py build --split test
python eval/check_annotations.py
```

Run in this order, the first five commands rebuild `eval/coco_selection.json`, and `draw-train` also writes `instances_train2017_selected.json`. Both instances files come from COCO's `annotations_trainval2017.zip` (md5 `f4bbac642086de4f52a3fdda2de5fa2c`). The per-annotator judgments behind `eval/annotations_test_judgments.json` are kept in `eval/annotation_review/`: the four Sonnet files, `opus_review.json`, `review_sample.json` and `agreement.json`.
