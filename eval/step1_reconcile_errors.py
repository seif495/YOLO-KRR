"""
STEP 1: Reconcile error counts between summary (8 FP + 4 FN = 12) and attribution (6 FP + 4 FN = 10).
"""

import json
from pathlib import Path

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_jsonl(path):
    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records

print("="*80)
print("STEP 1: ERROR COUNT RECONCILIATION")
print("="*80)

# Load files
inst_json = load_json('eval/results/v1_frozen/baseline_instrumented.json')
attr_json = load_json('eval/results/v1_frozen/baseline_error_attribution.json')
detailed_jsonl = load_jsonl('eval/results/v1_frozen/baseline_instrumented_detailed.jsonl')
annotations = load_json('eval/results/v1_frozen/annotations.json')

# Map detailed records by image
detailed_by_image = {rec['image']: rec for rec in detailed_jsonl}
ann_by_image = {img['file']: img for img in annotations['images']}

print("\n1a. SUMMARY METRICS FROM baseline_instrumented.json:")
print(f"   danger_tp_fp_fn = {inst_json['summary']['danger_tp_fp_fn']}")
print(f"   Expected total errors: TP={inst_json['summary']['danger_tp_fp_fn'][0]}, "
      f"FP={inst_json['summary']['danger_tp_fp_fn'][1]}, "
      f"FN={inst_json['summary']['danger_tp_fp_fn'][2]}")

print("\n1b. ALL FLAGGED (predicted dangerous) PERSONS FROM SUMMARY:")
print("-"*80)

all_flagged = []
for img in inst_json['images']:
    if img['flagged']:
        print(f"\n{img['image']}:")
        print(f"   GT dangerous count: {img['dangerous']}")
        print(f"   Flagged: {img['flagged']}")
        print(f"   TP/FP/FN from summary: {img['tp_fp_fn']}")
        
        for person_label in img['flagged']:
            all_flagged.append({
                'image': img['image'],
                'person_label': person_label,
                'summary_tp_fp_fn': img['tp_fp_fn']
            })

print(f"\nTotal flagged persons from summary: {len(all_flagged)}")

print("\n1c. CROSS-REFERENCE WITH DETAILED JSONL:")
print("-"*80)

for item in all_flagged:
    det = detailed_by_image.get(item['image'])
    if det:
        # Find matched_person entry
        matched = None
        for mp in det.get('matched_persons', []):
            if mp.get('matched_detection_label') == item['person_label']:
                matched = mp
                break
        
        item['in_detailed'] = True
        item['pred_dangerous'] = item['person_label'] in det['predictions'].get('dangerous', [])
        if matched:
            item['gt_person_idx'] = matched['person_idx']
            item['gt_dangerous'] = matched.get('ground_truth_dangerous', None)
            item['detected'] = matched.get('detected', None)
            item['iou'] = matched.get('match_iou', None)
        else:
            item['gt_person_idx'] = 'NO_MATCH'
            item['gt_dangerous'] = None
            item['detected'] = None
            item['iou'] = None
    else:
        item['in_detailed'] = False

print("\nFlagged persons with GT matches:")
for item in all_flagged:
    gt_dang_str = str(item.get('gt_dangerous', '?'))
    result = 'TP' if item.get('gt_dangerous') else 'FP' if item.get('gt_person_idx') != 'NO_MATCH' else 'UNMATCHED'
    print(f"{item['image']:40s} {item['person_label']:10s} "
          f"GT_idx={str(item.get('gt_person_idx','?')):10s} "
          f"GT_dangerous={gt_dang_str:5s} -> {result}")

print("\n1d. ATTRIBUTION FILE COVERAGE:")
print("-"*80)
print(f"Attribution file has {len(attr_json['errors'])} errors:")
print(f"   FP: {attr_json['summary']['by_type']['FP']}")
print(f"   FN: {attr_json['summary']['by_type']['FN']}")

# Find which flagged persons are in attribution
attr_fps = {(e['image'], e['person_label']) for e in attr_json['errors'] if e['type'] == 'FP'}

print("\nFlagged persons NOT in attribution file:")
missing_from_attr = []
for item in all_flagged:
    key = (item['image'], item['person_label'])
    item['in_attribution'] = key in attr_fps
    if not item['in_attribution']:
        missing_from_attr.append(item)
        print(f"  {item['image']:40s} {item['person_label']:10s} (GT_idx={item.get('gt_person_idx','?')})")

print(f"\nMissing count: {len(missing_from_attr)}")

print("\n1e. INVESTIGATE MISSING FPs:")
print("-"*80)

# For each missing FP, examine why analyze_errors.py might have skipped it
for item in missing_from_attr:
    print(f"\n{item['image']} - {item['person_label']}:")
    print(f"   GT match: {item.get('gt_person_idx', 'unknown')}")
    print(f"   GT dangerous: {item.get('gt_dangerous', 'unknown')}")
    
    # Check if this is person_2 in 257 or person_3 in van
    if item['gt_person_idx'] == 'NO_MATCH':
        print("   ** UNMATCHED DETECTION (no GT person with sufficient IoU) **")
        print("   -> analyze_errors.py likely skipped this as it only processes matched persons")
    else:
        det = detailed_by_image.get(item['image'])
        ann = ann_by_image.get(item['image'])
        if det and ann:
            gt_idx = item['gt_person_idx']
            if gt_idx != 'NO_MATCH' and isinstance(gt_idx, int):
                if gt_idx < len(ann['persons']):
                    gt_person = ann['persons'][gt_idx]
                    pairs_for_person = [p for p in ann['pairs'] if p['person'] == gt_idx]
                    print(f"   GT dangerous: {gt_person.get('dangerous', False)}")
                    print(f"   GT pairs: {pairs_for_person}")

print("\n1f. FINAL RECONCILIATION TABLE:")
print("="*80)
print(f"{'Category':<30} {'Count':<10} {'Source'}")
print("-"*80)
print(f"{'Flagged (predicted dangerous)':<30} {len(all_flagged):<10} Summary JSON 'flagged'")
print(f"{'  - With GT match':<30} {sum(1 for x in all_flagged if x.get('gt_person_idx') != 'NO_MATCH'):<10}")
print(f"{'  - Unmatched detections':<30} {sum(1 for x in all_flagged if x.get('gt_person_idx') == 'NO_MATCH'):<10}")
print(f"{'True Positives (TP)':<30} {inst_json['summary']['danger_tp_fp_fn'][0]:<10} Summary danger_tp_fp_fn[0]")
print(f"{'False Positives (FP)':<30} {inst_json['summary']['danger_tp_fp_fn'][1]:<10} Summary danger_tp_fp_fn[1]")
print(f"{'False Negatives (FN)':<30} {inst_json['summary']['danger_tp_fp_fn'][2]:<10} Summary danger_tp_fp_fn[2]")
print(f"{'FPs in attribution file':<30} {attr_json['summary']['by_type']['FP']:<10} baseline_error_attribution.json")
print(f"{'FNs in attribution file':<30} {attr_json['summary']['by_type']['FN']:<10} baseline_error_attribution.json")
print(f"{'Missing from attribution':<30} {len(missing_from_attr):<10} Flagged - In attribution")

print("\n1g. ANSWER TO BLOCKING QUESTION:")
print("="*80)
if len(all_flagged) != inst_json['summary']['danger_tp_fp_fn'][0] + inst_json['summary']['danger_tp_fp_fn'][1]:
    print("⚠️  DISCREPANCY FOUND:")
    print(f"   Flagged count ({len(all_flagged)}) != TP + FP ({inst_json['summary']['danger_tp_fp_fn'][0] + inst_json['summary']['danger_tp_fp_fn'][1]})")
else:
    print("✓ Flagged count matches TP + FP")

print(f"\nSummary FP count: {inst_json['summary']['danger_tp_fp_fn'][1]}")
print(f"Attribution FP count: {attr_json['summary']['by_type']['FP']}")
print(f"Difference: {inst_json['summary']['danger_tp_fp_fn'][1] - attr_json['summary']['by_type']['FP']}")

if len(missing_from_attr) == 2:
    print(f"\nHYPOTHESIS: The 2 missing FPs are unmatched detections (no GT person with IoU > threshold).")
    print(f"analyze_errors.py only processes persons that match a GT person.")
    print(f"These unmatched detections are counted in the summary FP total but have no GT person")
    print(f"to attribute the error to, so they are excluded from per-person attribution.")

# Check all GT dangerous persons (for FN verification)
print("\n1h. ALL GT DANGEROUS PERSONS (TP + FN verification):")
print("="*80)
all_gt_dangerous = []
for img_data in annotations['images']:
    for idx, person in enumerate(img_data['persons']):
        if person.get('dangerous', False):
            all_gt_dangerous.append({
                'image': img_data['file'],
                'person_idx': idx,
                'box': person['box']
            })
            
print(f"Total GT dangerous persons: {len(all_gt_dangerous)}")
print(f"Expected TP + FN: {inst_json['summary']['danger_tp_fp_fn'][0] + inst_json['summary']['danger_tp_fp_fn'][2]}")

if len(all_gt_dangerous) == inst_json['summary']['danger_tp_fp_fn'][0] + inst_json['summary']['danger_tp_fp_fn'][2]:
    print("✓ GT dangerous count matches TP + FN")
else:
    print(f"⚠️  MISMATCH: {len(all_gt_dangerous)} GT dangerous != {inst_json['summary']['danger_tp_fp_fn'][0] + inst_json['summary']['danger_tp_fp_fn'][2]} TP+FN")

print("\nGT dangerous persons:")
for gd in all_gt_dangerous:
    # Find in detailed
    det = detailed_by_image.get(gd['image'])
    if det:
        matched = None
        for mp in det['matched_persons']:
            if mp['person_idx'] == gd['person_idx']:
                matched = mp
                break
        if matched:
            pred_dangerous = matched.get('matched_detection_label') in det['predictions'].get('dangerous', [])
            result = 'TP' if pred_dangerous else 'FN'
            print(f"  {gd['image']:40s} person_idx={gd['person_idx']} -> {result}")
        else:
            print(f"  {gd['image']:40s} person_idx={gd['person_idx']} -> NOT DETECTED (FN)")
    else:
        print(f"  {gd['image']:40s} person_idx={gd['person_idx']} -> NO DETAILED RECORD")
