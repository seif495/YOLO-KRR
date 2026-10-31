"""Report duplicate/overlapping detections that could cause matching ambiguity."""

import json
from pathlib import Path
import sys

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
from yolo_sneps.scene import iou

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

results = load_jsonl('eval/results/v1_frozen/baseline_instrumented_detailed.jsonl')
annotations = load_annotations('eval/results/v1_frozen/annotations.json')

print("="*100)
print("DUPLICATE / OVERLAPPING DETECTIONS REPORT")
print("="*100)

all_duplicates = []
total_images_with_dups = 0

for img_result in results:
    image_name = img_result['image']
    if image_name not in annotations:
        continue
    
    gt_image = annotations[image_name]
    detections = img_result['detections']
    dangerous_flags = set(img_result['predictions']['dangerous'])
    
    # Find person detections
    person_dets = [d for d in detections if d['class'] == 'person']
    
    # 1. Mutual IoU > 0.3 (overlapping detections)
    overlaps = []
    for i, d1 in enumerate(person_dets):
        for j, d2 in enumerate(person_dets[i+1:], i+1):
            mutual_iou = iou(tuple(d1['box']), tuple(d2['box']))
            if mutual_iou > 0.3:
                overlaps.append({
                    'det1': d1['label'],
                    'det2': d2['label'],
                    'iou': mutual_iou,
                    'conf1': d1['confidence'],
                    'conf2': d2['confidence'],
                    'flagged1': d1['label'] in dangerous_flags,
                    'flagged2': d2['label'] in dangerous_flags
                })
    
    # 2. Multiple detections matching same GT person (IoU >= 0.5)
    multi_matches = []
    for person_idx, person in enumerate(gt_image['persons']):
        gt_box = person['box']
        matches = []
        for d in person_dets:
            det_iou = iou(tuple(gt_box), tuple(d['box']))
            if det_iou >= 0.5:
                matches.append({
                    'label': d['label'],
                    'iou': det_iou,
                    'conf': d['confidence'],
                    'flagged': d['label'] in dangerous_flags
                })
        
        if len(matches) > 1:
            multi_matches.append({
                'person_idx': person_idx,
                'gt_dangerous': person.get('dangerous', False),
                'matches': matches
            })
    
    if overlaps or multi_matches:
        total_images_with_dups += 1
        all_duplicates.append({
            'image': image_name,
            'overlaps': overlaps,
            'multi_matches': multi_matches
        })

print(f"\nImages with duplicate/overlapping detections: {total_images_with_dups} of {len(results)}")

if all_duplicates:
    for dup_info in all_duplicates:
        print(f"\n{'='*100}")
        print(f"IMAGE: {dup_info['image']}")
        print('='*100)
        
        if dup_info['overlaps']:
            print("\nOVERLAPPING DETECTIONS (mutual IoU > 0.3):")
            print(f"  {'Det1':<12} {'Det2':<12} {'Mutual IoU':<12} {'Conf1':<8} {'Conf2':<8} {'Flag1':<7} {'Flag2':<7}")
            print("  " + "-"*70)
            for ov in dup_info['overlaps']:
                print(f"  {ov['det1']:<12} {ov['det2']:<12} {ov['iou']:<12.3f} "
                      f"{ov['conf1']:<8.3f} {ov['conf2']:<8.3f} "
                      f"{str(ov['flagged1']):<7} {str(ov['flagged2']):<7}")
        
        if dup_info['multi_matches']:
            print("\nMULTIPLE DETECTIONS MATCHING SAME GT PERSON (IoU >= 0.5):")
            for mm in dup_info['multi_matches']:
                print(f"\n  GT person_idx={mm['person_idx']} (dangerous={mm['gt_dangerous']})")
                print(f"    {'Detection':<12} {'IoU':<8} {'Conf':<8} {'Flagged':<8}")
                print("    " + "-"*40)
                for m in sorted(mm['matches'], key=lambda x: x['iou'], reverse=True):
                    print(f"    {m['label']:<12} {m['iou']:<8.3f} {m['conf']:<8.3f} {str(m['flagged']):<8}")

# Special analysis for 000000000257.jpg person_idx=8
print("\n" + "="*100)
print("SPECIAL CASE: 000000000257.jpg, GT person_idx=8 (person_1 vs person_2)")
print("="*100)

target_img = next((d for d in all_duplicates if d['image'] == '000000000257.jpg'), None)
if target_img:
    mm = next((m for m in target_img['multi_matches'] if m['person_idx'] == 8), None)
    if mm:
        print(f"\nGT person_idx=8 has {len(mm['matches'])} detections above IoU >= 0.5:")
        for m in mm['matches']:
            print(f"  {m['label']}: IoU={m['iou']:.3f}, conf={m['conf']:.3f}, flagged={m['flagged']}")
        
        print(f"\nThis is why old analyzer (first-match) incorrectly matched person_1")
        print(f"while evaluator (best-match) correctly matched person_2.")
        print(f"Result: 1 FP (person_2) was silently excluded from old attribution.")

# Count how many FPs and FNs are affected by duplicate detection issues
print("\n" + "="*100)
print("IMPACT ON ERROR COUNTS")
print("="*100)

# Load new attribution to see which errors involved duplicate detections
new_attr = json.load(open('eval/results/baseline_error_attribution_v2.json'))

fp_with_dups = 0
fn_with_dups = 0

for error in new_attr['errors']:
    if error['person_idx'] is None:
        continue  # Skip unmatched
    
    # Check if this error's image has duplicates
    img_dup = next((d for d in all_duplicates if d['image'] == error['image']), None)
    if img_dup:
        # Check if this specific GT person has multiple matches
        mm = next((m for m in img_dup['multi_matches'] if m['person_idx'] == error['person_idx']), None)
        if mm:
            if error['type'] == 'FP':
                fp_with_dups += 1
            elif error['type'] == 'FN':
                fn_with_dups += 1

print(f"\nErrors where GT person had multiple detection matches:")
print(f"  FP: {fp_with_dups} of {sum(1 for e in new_attr['errors'] if e['type'] == 'FP' and e['person_idx'] is not None)}")
print(f"  FN: {fn_with_dups} of {sum(1 for e in new_attr['errors'] if e['type'] == 'FN')}")
print(f"\nNote: These errors are correctly attributed in V2 (uses evaluator best-match).")
print(f"      But V1 analyzer could have matched to wrong detection if lower-IoU one listed first.")
