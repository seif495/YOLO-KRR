"""Check if multiple detections match the same GT person in 000000000257.jpg."""

import json
from pathlib import Path
import sys

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
from yolo_sneps.scene import iou

# Load files
with open('eval/results/v1_frozen/baseline_instrumented_detailed.jsonl') as f:
    for line in f:
        rec = json.loads(line)
        if rec['image'] == '000000000257.jpg':
            det_rec = rec
            break

with open('eval/results/v1_frozen/annotations.json') as f:
    ann = json.load(f)
    gt_img = next(img for img in ann['images'] if img['file'] == '000000000257.jpg')

print("="*80)
print("CHECKING: Detection conflicts in 000000000257.jpg")
print("="*80)

# For each GT person, find ALL detections above threshold
threshold = 0.5

for person_idx, person in enumerate(gt_img['persons']):
    gt_box = person['box']
    matches = []
    
    for det in det_rec['detections']:
        if det['class'] != 'person':
            continue
        det_box = tuple(det['box'])
        iou_val = iou(tuple(gt_box), det_box)
        if iou_val >= threshold:
            matches.append({
                'label': det['label'],
                'iou': iou_val,
                'conf': det['confidence']
            })
    
    if len(matches) > 1:
        print(f"\nperson_idx={person_idx}: MULTIPLE MATCHES!")
        for m in sorted(matches, key=lambda x: x['iou'], reverse=True):
            print(f"  {m['label']}: IoU={m['iou']:.3f}, conf={m['conf']:.3f}")
    elif len(matches) == 1:
        if person_idx in [0, 4, 7, 8]:  # The FP ones
            print(f"\nperson_idx={person_idx}: {matches[0]['label']} (IoU={matches[0]['iou']:.3f})")
    elif len(matches) == 0:
        if gt_img['persons'][person_idx].get('dangerous', False):
            print(f"\nperson_idx={person_idx}: NO MATCH (dangerous person not detected!)")

# Now check: for person_1 and person_2, which GT person do they match?
print("\n" + "="*80)
print("REVERSE MAPPING: Detection -> GT person")
print("="*80)

for det_label in ['person_1', 'person_2', 'person_4', 'person_9', 'person_10']:
    det = next(d for d in det_rec['detections'] if d['label'] == det_label)
    det_box = tuple(det['box'])
    
    best_iou = 0
    best_idx = None
    for person_idx, person in enumerate(gt_img['persons']):
        gt_box = person['box']
        iou_val = iou(tuple(gt_box), det_box)
        if iou_val > best_iou:
            best_iou = iou_val
            best_idx = person_idx
    
    print(f"{det_label} -> person_idx={best_idx} (IoU={best_iou:.3f})")

# Check matched_persons field from evaluate_instrumented.py
print("\n" + "="*80)
print("MATCHED_PERSONS from evaluate_instrumented.py:")
print("="*80)

for mp in det_rec['matched_persons']:
    if mp['person_idx'] in [0, 4, 7, 8]:
        label = mp.get('matched_detection_label', 'None')
        iou_val = mp.get('match_iou', 0)
        print(f"person_idx={mp['person_idx']} -> {label} (IoU={iou_val:.3f})")
