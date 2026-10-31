"""Analyze unmatched detection person_3 in women_in_front_of_parked_van.jpg."""

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

img_result = next(r for r in results if r['image'] == 'women_in_front_of_parked_van.jpg')
gt_image = annotations['women_in_front_of_parked_van.jpg']

# Find person_3 detection
person_3 = next(d for d in img_result['detections'] if d['label'] == 'person_3')

print("="*100)
print("UNMATCHED DETECTION ANALYSIS: person_3 in women_in_front_of_parked_van.jpg")
print("="*100)

print("\nDETECTION INFO:")
print(f"  Label: {person_3['label']}")
print(f"  Class: {person_3['class']}")
print(f"  Box: {person_3['box']}")
print(f"  Confidence: {person_3['confidence']:.3f}")

print("\nGROUND TRUTH PERSONS:")
print(f"  Total: {len(gt_image['persons'])}")
for idx, p in enumerate(gt_image['persons']):
    print(f"    person_idx={idx}: box={p['box']}, dangerous={p.get('dangerous', False)}")

print("\nIoU WITH EACH GT PERSON:")
for idx, p in enumerate(gt_image['persons']):
    gt_box = p['box']
    iou_val = iou(tuple(person_3['box']), tuple(gt_box))
    print(f"  GT person_idx={idx}: IoU={iou_val:.3f}")
    if iou_val >= 0.5:
        print(f"    -> WOULD MATCH (IoU >= 0.5)")

print("\nDETECTION FACTS:")
# Get facts involving person_3
relevant_facts = []
for f in img_result['facts']:
    if isinstance(f, list):
        if 'person_3' in f:
            relevant_facts.append(f)
    elif isinstance(f, str):
        import re
        if re.search(r'\bperson_3\b', f):
            relevant_facts.append(f)

if relevant_facts:
    print(f"  Found {len(relevant_facts)} facts involving person_3:")
    for f in relevant_facts[:10]:  # Show first 10
        print(f"    {f}")
else:
    print("  No facts found involving person_3")

print("\nDETECTION STATEMENTS:")
# Get statements involving person_3
relevant_stmts = []
for s in img_result['statements']:
    import re
    if re.search(r'\bperson_3\b', s):
        relevant_stmts.append(s)

if relevant_stmts:
    print(f"  Found {len(relevant_stmts)} statements involving person_3:")
    for s in relevant_stmts[:10]:
        print(f"    {s}")
else:
    print("  No statements found involving person_3")

print("\nWHY FLAGGED DANGEROUS?")
dangerous_flags = img_result['predictions']['dangerous']
if 'person_3' in dangerous_flags:
    print("  ✓ person_3 IS in dangerous predictions")
    
    # Check for infrontof facts
    infrontof_facts = [f for f in relevant_facts if (isinstance(f, list) and f[0] == 'infrontof' and f[1] == 'person_3')]
    if infrontof_facts:
        print(f"  Found {len(infrontof_facts)} infrontof facts:")
        for f in infrontof_facts:
            print(f"    {f}")
    else:
        print("  No infrontof(person_3, ...) facts found")
else:
    print("  ✗ person_3 NOT in dangerous predictions (unexpected)")

print("\nOVERLAP WITH OTHER DETECTIONS:")
person_dets = [d for d in img_result['detections'] if d['class'] == 'person']
for d in person_dets:
    if d['label'] == 'person_3':
        continue
    mutual_iou = iou(tuple(person_3['box']), tuple(d['box']))
    if mutual_iou > 0.3:
        in_dangerous = d['label'] in dangerous_flags
        print(f"  {d['label']}: mutual IoU={mutual_iou:.3f}, conf={d['confidence']:.3f}, dangerous={in_dangerous}")

print("\nCONCLUSION:")
print("  person_3 is a detection that does not match any GT person (all IoUs < 0.5)")
print("  It overlaps significantly with person_2 (IoU=0.563 from duplicate report)")
print("  Both person_2 and person_3 are flagged dangerous")
print("  This could be:")
print("    a) A duplicate detection of the same physical person (person_2)")
print("    b) An unannotated third person in the image")
print("    c) A false detection (background or partial person)")
print("\n  REQUIRES HUMAN VISUAL INSPECTION to determine which case applies")
