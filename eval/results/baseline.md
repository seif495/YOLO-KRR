# Evaluation: baseline

| Measure | Value |
|---|---|
| model | yolo11n-seg.pt |
| imgsz | 640 |
| conf | 0.25 |
| rules | danger.snepslog |
| backend | allegro |
| images | 24 |
| person_recall_coco128 | 50/83 = 60% |
| infrontof_accuracy | 21/28 = 75% |
| infrontof_no_answer | 5/28 = 18% |
| danger_tp_fp_fn | [2, 10, 4] |
| danger_precision | 0.167 |
| danger_recall | 0.333 |
| danger_f1 | 0.222 |
| images_with_sneps_errors | 0 |

| Image | People | Detected | Dangerous | Flagged | TP | FP | FN |
|---|---|---|---|---|---|---|---|
| 000000000049.jpg | 6 | 4 | 0 | - | 0 | 0 | 0 |
| 000000000061.jpg | 3 | 2 | 0 | - | 0 | 0 | 0 |
| 000000000074.jpg | 6 | 4 | 0 | - | 0 | 0 | 0 |
| 000000000086.jpg | 1 | 1 | 0 | - | 0 | 0 | 0 |
| 000000000109.jpg | 5 | 3 | 0 | - | 0 | 0 | 0 |
| 000000000136.jpg | 2 | 2 | 0 | - | 0 | 0 | 0 |
| 000000000149.jpg | 12 | 3 | 0 | - | 0 | 0 | 0 |
| 000000000151.jpg | 1 | 0 | 0 | - | 0 | 0 | 0 |
| 000000000257.jpg | 13 | 10 | 0 | person_10, person_2, person_4, person_9 | 0 | 4 | 0 |
| 000000000260.jpg | 2 | 1 | 0 | person_1 | 0 | 1 | 0 |
| 000000000328.jpg | 3 | 3 | 0 | - | 0 | 0 | 0 |
| 000000000419.jpg | 2 | 2 | 0 | - | 0 | 0 | 0 |
| 000000000443.jpg | 3 | 3 | 0 | person_2, person_3 | 0 | 2 | 0 |
| 000000000471.jpg | 1 | 0 | 0 | - | 0 | 0 | 0 |
| 000000000529.jpg | 2 | 1 | 0 | - | 0 | 0 | 0 |
| 000000000531.jpg | 8 | 8 | 0 | - | 0 | 0 | 0 |
| 000000000532.jpg | 4 | 2 | 0 | - | 0 | 0 | 0 |
| 000000000641.jpg | 9 | 1 | 0 | - | 0 | 0 | 0 |
| man_crossing_in_front_of_trolley.jpg | 4 | 4 | 1 | person_4 | 1 | 0 | 0 |
| women_crossing_in_front_of_wagon.jpg | 6 | 6 | 2 | - | 0 | 0 | 2 |
| pedestrian_crossing_road.jpg | 3 | 3 | 1 | person_3 | 1 | 0 | 0 |
| night_intersection.jpg | 9 | 9 | 2 | - | 0 | 0 | 2 |
| women_in_front_of_parked_van.jpg | 2 | 2 | 0 | person_1, person_2, person_3 | 0 | 3 | 0 |
| empty_street.jpg | 0 | 0 | 0 | - | 0 | 0 | 0 |
