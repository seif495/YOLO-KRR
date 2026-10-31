"""Compare old analyze_errors.py matching vs evaluator matched_persons.

For every GT person, show:
- Old match (first-match-above-threshold) 
- Evaluator match (best-match from matched_persons)
- Whether this caused error classification to change
"""

import json
import sys
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
from yolo_sneps.scene import iou

def old_match_detection(truth_box, detections, threshold=0.5):
    """OLD LOGIC: Returns FIRST detection above threshold."""
    for d in detections:
        if iou(tuple(truth_box), tuple(d['box'])) >= threshold:
            return d
    return None

def load_jsonl(path):
    records = []
    with open(path) as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records

def load_annotations(path):
    with open(path) as f:
        return {item["file"]: item for item in json.load(f)["images"]}

# Load data
results = load_jsonl('eval/results/v1_frozen/baseline_instrumented_detailed.jsonl')
annotations = load_annotations('eval/results/v1_frozen/annotations.json')
old_attr = json.load(open('eval/results/v1_frozen/baseline_error_attribution.json'))
new_attr = json.load(open('eval/results/baseline_error_attribution_v2.json'))

# Build lookup of old attributions
old_by_key = {}
for e in old_attr['errors']:
    key = (e['image'], e['person_idx'])
    old_by_key[key] = e

# Build lookup of new attributions
new_by_key = {}
for e in new_attr['errors']:
    if e['person_idx'] is not None:  # Exclude unmatched detections
        key = (e['image'], e['person_idx'])
        new_by_key[key] = e

print("="*100)
print("DIVERGENCE SCAN: Old Analyzer Match vs Evaluator Match")
print("="*100)

divergences = []
total_gt_persons = 0

for img_result in results:
    image_name = img_result['image']
    if image_name not in annotations:
        continue
    
    gt_image = annotations[image_name]
    detections = img_result['detections']
    matched_persons = img_result['matched_persons']
    dangerous_flags = set(img_result['predictions']['dangerous'])
    
    # Create evaluator match lookup
    eval_match = {}
    for mp in matched_persons:
        eval_match[mp['person_idx']] = {
            'label': mp.get('matched_detection_label'),
            'iou': mp.get('match_iou', 0)
        }
    
    # Check each GT person
    for person_idx, person in enumerate(gt_image['persons']):
        total_gt_persons += 1
        gt_box = person['box']
        
        # Old match: first above threshold
        old_det = old_match_detection(gt_box, detections)
        old_label = old_det['label'] if old_det else None
        old_iou = iou(tuple(gt_box), tuple(old_det['box'])) if old_det else 0
        
        # Evaluator match
        eval_info = eval_match.get(person_idx, {'label': None, 'iou': 0})
        eval_label = eval_info['label']
        eval_iou = eval_info['iou']
        
        # Compare
        if old_label != eval_label:
            # Mismatch!
            old_flagged = old_label in dangerous_flags if old_label else False
            eval_flagged = eval_label in dangerous_flags if eval_label else False
            
            gt_dangerous = person.get('dangerous', False)
            
            # Determine old classification
            if gt_dangerous and not old_flagged:
                old_class = "FN"
            elif not gt_dangerous and old_flagged:
                old_class = "FP"
            else:
                old_class = "correct"
            
            # Determine evaluator classification
            if gt_dangerous and not eval_flagged:
                eval_class = "FN"
            elif not gt_dangerous and eval_flagged:
                eval_class = "FP"
            else:
                eval_class = "correct"
            
            # Check if this changed error status
            changed = (old_class != eval_class)
            
            # Get attribution info
            key = (image_name, person_idx)
            old_in_attr = key in old_by_key
            new_in_attr = key in new_by_key
            
            divergences.append({
                'image': image_name,
                'person_idx': person_idx,
                'gt_dangerous': gt_dangerous,
                'old_match': old_label,
                'old_iou': old_iou,
                'old_flagged': old_flagged,
                'old_class': old_class,
                'eval_match': eval_label,
                'eval_iou': eval_iou,
                'eval_flagged': eval_flagged,
                'eval_class': eval_class,
                'changed': changed,
                'old_in_attr': old_in_attr,
                'new_in_attr': new_in_attr
            })

print(f"\nTotal GT persons checked: {total_gt_persons}")
print(f"Divergences found: {len(divergences)}")

if divergences:
    print("\n" + "-"*100)
    print(f"{'Image':<42} {'GT_idx':<7} {'Old Match':<12} {'IoU':<6} {'Eval Match':<12} {'IoU':<6} {'Changed?'}")
    print("-"*100)
    
    for div in divergences:
        changed_mark = "***" if div['changed'] else ""
        print(f"{div['image']:<42} {div['person_idx']:<7} "
              f"{div['old_match'] or 'None':<12} {div['old_iou']:<6.3f} "
              f"{div['eval_match'] or 'None':<12} {div['eval_iou']:<6.3f} {changed_mark}")
        if div['changed']:
            print(f"  -> Classification changed: {div['old_class']} (old) -> {div['eval_class']} (evaluator)")
            print(f"  -> GT dangerous={div['gt_dangerous']}, old flagged={div['old_flagged']}, eval flagged={div['eval_flagged']}")
            print(f"  -> In old attr: {div['old_in_attr']}, in new attr: {div['new_in_attr']}")
    
    print("\n" + "="*100)
    print("SUMMARY")
    print("="*100)
    changed_count = sum(1 for d in divergences if d['changed'])
    print(f"Total divergences: {len(divergences)}")
    print(f"  - Classification changed: {changed_count}")
    print(f"  - Classification unchanged: {len(divergences) - changed_count}")
    
    # Detail the classification changes
    if changed_count > 0:
        print("\nClassification changes:")
        for div in divergences:
            if div['changed']:
                key = (div['image'], div['person_idx'])
                old_cat = old_by_key.get(key, {}).get('category', 'N/A')
                new_cat = new_by_key.get(key, {}).get('category', 'N/A')
                print(f"  {div['image']}, person_idx={div['person_idx']}:")
                print(f"    {div['old_class']} (old, category={old_cat}) -> {div['eval_class']} (new, category={new_cat})")
else:
    print("\n✓ ZERO divergences found - all GT persons have matching old/evaluator matches")
    print("  (This would be unexpected given the bug we identified)")
