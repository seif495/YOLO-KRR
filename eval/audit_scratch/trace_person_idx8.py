"""Trace why person_idx=8 in 000000000257.jpg wasn't included in attribution."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from yolo_sneps.scene import iou

# Load files
with open('eval/results/v1_frozen/baseline_instrumented_detailed.jsonl') as f:
    for line in f:
        rec = json.loads(line)
        if rec['image'] == '000000000257.jpg':
            image_result = rec
            break

with open('eval/results/v1_frozen/annotations.json') as f:
    ann = json.load(f)
    gt_image = next(img for img in ann['images'] if img['file'] == '000000000257.jpg')

print("="*80)
print("TRACING: analyze_errors.py logic for person_idx=8")
print("="*80)

# Extract from detailed format (mimicking analyze_errors.py line 260-267)
detections = [
    type('Detection', (), {
        'label': d['label'],
        'cls': d['class'],
        'box': tuple(d['box']),
        'conf': d['confidence']
    })() for d in image_result.get("detections", [])
]
facts = image_result.get("facts", [])
dangerous_flags = set(image_result.get("predictions", {}).get("dangerous", []))

print(f"\n1. dangerous_flags: {dangerous_flags}")
print(f"   'person_2' in dangerous_flags: {'person_2' in dangerous_flags}")

# Process person_idx=8
person_idx = 8
person = gt_image["persons"][person_idx]
gt_dangerous = person.get("dangerous", False)
person_box = person["box"]

print(f"\n2. Processing person_idx={person_idx}:")
print(f"   GT box: {person_box}")
print(f"   GT dangerous: {gt_dangerous}")

# Match to detected person (mimicking match_person_to_detection)
def match_person_to_detection(person_box, detections, threshold=0.5):
    for d in detections:
        if iou(person_box, d.box) >= threshold:
            return d
    return None

detected = match_person_to_detection(person_box, detections)

if detected:
    person_label = detected.label
    print(f"   Matched to detection: {person_label}")
    print(f"   Detection box: {detected.box}")
    print(f"   IoU: {iou(person_box, detected.box)}")
else:
    person_label = None
    print(f"   NO DETECTION MATCHED")

# Check if flagged
is_flagged = person_label in dangerous_flags if person_label else False
print(f"\n3. is_flagged: {is_flagged}")
print(f"   person_label='{person_label}' in dangerous_flags={dangerous_flags}")

# Determine if this should be an error
if gt_dangerous and not is_flagged:
    result = "FALSE NEGATIVE"
elif not gt_dangerous and is_flagged:
    result = "FALSE POSITIVE"
else:
    result = "CORRECT (not an error)"

print(f"\n4. RESULT: {result}")

if result == "FALSE POSITIVE":
    print(f"\n5. SHOULD BE IN ATTRIBUTION FILE")
    
    # Check if it's actually there
    with open('eval/results/v1_frozen/baseline_error_attribution.json') as f:
        attr = json.load(f)
        in_attr = any(e['person_idx'] == person_idx and e['image'] == '000000000257.jpg' 
                      for e in attr['errors'])
        print(f"   In attribution file: {in_attr}")
        
        if not in_attr:
            print("\n   *** BUG CONFIRMED: This FP is missing from attribution file ***")
            print("\n   Possible causes:")
            print("   a) The original analyze_errors.py run had a bug")
            print("   b) A different version of the JSONL was used")
            print("   c) The annotations were different")
            print("   d) There's filtering logic we haven't found yet")
