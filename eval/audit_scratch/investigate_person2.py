"""Investigate why person_2 in 000000000257.jpg was excluded from attribution."""

import json

# Load detailed JSONL
with open('eval/results/v1_frozen/baseline_instrumented_detailed.jsonl', 'r') as f:
    for line in f:
        rec = json.loads(line)
        if rec['image'] == '000000000257.jpg':
            detailed = rec
            break

print("="*80)
print("INVESTIGATING: person_2 in 000000000257.jpg")
print("="*80)

print("\n1. PREDICTIONS:")
print(f"   dangerous: {detailed['predictions']['dangerous']}")
print(f"   alert: {detailed['predictions']['alert']}")
print(f"   hidden: {detailed['predictions']['hidden']}")

print("\n2. MATCHED_PERSONS (GT person → detected person mapping):")
for mp in detailed['matched_persons']:
    print(f"   person_idx={mp['person_idx']} -> {mp.get('matched_detection_label', 'NONE')}")
    print(f"      detected={mp.get('detected', '?')}, GT_dangerous={mp.get('ground_truth_dangerous', '?')}")

print("\n3. SEARCH FOR person_2:")
person_2_in_predictions = 'person_2' in detailed['predictions']['dangerous']
print(f"   person_2 in predictions['dangerous']: {person_2_in_predictions}")

# Find if person_2 is matched to any GT person
person_2_match = None
for mp in detailed['matched_persons']:
    if mp.get('matched_detection_label') == 'person_2':
        person_2_match = mp
        break

if person_2_match:
    print(f"   person_2 matched to GT person_idx: {person_2_match['person_idx']}")
    print(f"   GT dangerous: {person_2_match.get('ground_truth_dangerous')}")
    print(f"   IoU: {person_2_match.get('match_iou')}")
else:
    print("   person_2 NOT found in matched_persons!")

# Load annotations to verify
with open('eval/results/v1_frozen/annotations.json') as f:
    ann = json.load(f)
    img_ann = next(img for img in ann['images'] if img['file'] == '000000000257.jpg')

print("\n4. GROUND TRUTH (annotations.json):")
print(f"   Total GT persons: {len(img_ann['persons'])}")
for idx in range(len(img_ann['persons'])):
    person = img_ann['persons'][idx]
    print(f"   person_idx={idx}: dangerous={person.get('dangerous', False)}, box={person['box']}")

# Check if person_idx=8 should be analyzed as FP
if person_2_match:
    gt_idx = person_2_match['person_idx']
    gt_person = img_ann['persons'][gt_idx]
    is_fp = not gt_person.get('dangerous', False) and person_2_in_predictions
    print(f"\n5. IS THIS AN FP?")
    print(f"   GT dangerous: {gt_person.get('dangerous', False)}")
    print(f"   Predicted dangerous: {person_2_in_predictions}")
    print(f"   -> {'YES, this is a FALSE POSITIVE' if is_fp else 'NO'}")
    
    # Check if it's in attribution file
    with open('eval/results/v1_frozen/baseline_error_attribution.json') as f:
        attr = json.load(f)
        in_attr = any(e['person_label'] == 'person_2' and e['image'] == '000000000257.jpg' 
                      for e in attr['errors'])
        print(f"\n6. IN ATTRIBUTION FILE?")
        print(f"   {in_attr}")
        
        if is_fp and not in_attr:
            print(f"\n   *** CONFIRMED: person_2 is a legitimate FP that was excluded ***")
