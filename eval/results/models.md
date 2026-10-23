# Model and image size comparison

`eval/evaluate.py` on the 24 labelled images (6 dangerous people), with the rules as they were
before the rule changes (`kb/danger.snepslog` at commit f4f129e), the Allegro backend, and CPU
inference (Intel Core i7-6920HQ, PyTorch 2.6 CPU build). Per-run details are in `<model>-<imgsz>.md`.

| Model | imgsz | Person recall (coco128) | Danger TP/FP/FN | Precision | Recall | F1 | YOLO s/image |
|---|---|---|---|---|---|---|---|
| yolo11n-seg | 640 | 50/83 = 60% | 2/10/4 | 0.167 | 0.333 | 0.222 | 0.27 |
| yolo11n-seg | 1280 | 52/83 = 63% | 3/10/3 | 0.231 | 0.500 | 0.316 | 0.62 |
| yolo11s-seg | 640 | 48/83 = 58% | 2/7/4 | 0.222 | 0.333 | 0.267 | 0.49 |
| yolo11s-seg | 1280 | 59/83 = 71% | 1/8/5 | 0.111 | 0.167 | 0.133 | 1.37 |
| yolo11m-seg | 640 | 51/83 = 61% | 2/8/4 | 0.200 | 0.333 | 0.250 | 0.77 |

The infrontof cue is measured on ground-truth boxes, so it is 21/28 = 75% in every run.

- Larger models and images find more people (up to 71% recall with yolo11s-seg at 1280), but the
  danger scores do not improve with them. Most false positives are people correctly detected next to
  parked vehicles; a better detector finds more of those people, not fewer.
- With 6 dangerous people, one person more or less changes recall by 0.17, so differences between
  these rows are within noise. A larger labelled set is needed to choose between models on the
  danger task.
- yolo11n-seg at 640 stays the default: it is the fastest and no other setting is clearly better.
  `--imgsz 1280` is worth using for scenes with small, distant pedestrians.
