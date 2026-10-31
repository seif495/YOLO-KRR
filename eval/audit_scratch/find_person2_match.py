"""Find which GT person person_2 detection matches to."""

import json
from pathlib import Path
import sys

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
from yolo_sneps.scene import iou

# Load detailed
with open('eval/results/v1_frozen/baseline_instrumented_detailed.jsonl') as f:
    for line in f:
        rec = json.loads(line)
        if rec['image'] == '000000000257.jpg':
            det_rec = rec
            break

# Find person_2 detection
person_2_det = next(d for d in det_rec['detections'] if d['label'] == 'person_2')
print(f'person_2 detection box: {person_2_det["box"]}')

# Load annotations
with open('eval/results/v1_frozen/annotations.json') as f:
    ann = json.load(f)
    gt_img = next(img for img in ann['images'] if img['file'] == '000000000257.jpg')

# Check IoU with all GT persons
print(f'\nIoU with all GT persons:')
best_iou = 0
best_idx = None
for idx, person in enumerate(gt_img['persons']):
    gt_box = person['box']
    iou_val = iou(tuple(person_2_det['box']), tuple(gt_box))
    if iou_val > 0.3:
        print(f'  person_idx={idx}: IoU={iou_val:.3f} GT_box={gt_box}')
    if iou_val > best_iou:
        best_iou = iou_val
        best_idx = idx

print(f'\nBest match: person_idx={best_idx} with IoU={best_iou:.3f}')

if best_iou >= 0.5:
    print(f'  Above matching threshold (0.5) -> person_2 matches to GT person_idx={best_idx}')
    gt_dangerous = gt_img['persons'][best_idx].get('dangerous', False)
    pred_dangerous = 'person_2' in det_rec['predictions']['dangerous']
    print(f'  GT dangerous: {gt_dangerous}')
    print(f'  Predicted dangerous: {pred_dangerous}')
    if not gt_dangerous and pred_dangerous:
        print(f'  -> FALSE POSITIVE for person_idx={best_idx}')
else:
    print(f'  Below matching threshold -> person_2 is an UNMATCHED detection')
