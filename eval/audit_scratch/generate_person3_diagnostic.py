#!/usr/bin/env python3
"""
Generate diagnostic overlay for person_3 in women_in_front_of_parked_van.jpg
Shows why this detection was not matched to GT person_idx=1 despite IoU=0.563
"""

import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# Load the instrumented results to get bbox and IoU data
results_file = Path("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl")
van_record = None
with open(results_file) as f:
    for line in f:
        record = json.loads(line)
        if record["image"] == "women_in_front_of_parked_van.jpg":
            van_record = record
            break

if not van_record:
    print("ERROR: van image record not found")
    exit(1)

# Find person_3 detection
person3_det = None
for det_name, det_data in van_record["detections"].items():
    if det_name == "person_3":
        person3_det = det_data
        break

if not person3_det:
    print("ERROR: person_3 detection not found")
    exit(1)

# Load the image
img_path = Path("examples/women_in_front_of_parked_van.jpg")
img = Image.open(img_path)
draw = ImageDraw.Draw(img)

# Try to load a font, fall back to default
try:
    font = ImageFont.truetype("arial.ttf", 16)
    font_small = ImageFont.truetype("arial.ttf", 12)
except:
    font = ImageFont.load_default()
    font_small = ImageFont.load_default()

# Draw person_3 detection bbox (RED for unmatched FP)
det_bbox = person3_det["bbox"]
det_conf = person3_det["confidence"]
x1, y1, x2, y2 = det_bbox
draw.rectangle([x1, y1, x2, y2], outline="red", width=4)
draw.text((x1, y1 - 20), f"person_3 (FP, conf={det_conf:.3f})", 
          fill="red", font=font)

# Find GT person with best IoU to person_3
annotations = json.load(open("eval/results/v1_frozen/annotations.json"))
van_ann = None
for img_ann in annotations["images"]:
    if img_ann["file_name"] == "women_in_front_of_parked_van.jpg":
        van_ann = img_ann
        break

# Calculate IoU with all GT persons
def calculate_iou(box1, box2):
    x1_inter = max(box1[0], box2[0])
    y1_inter = max(box1[1], box2[1])
    x2_inter = min(box1[2], box2[2])
    y2_inter = min(box1[3], box2[3])
    
    if x1_inter >= x2_inter or y1_inter >= y2_inter:
        return 0.0
    
    inter_area = (x2_inter - x1_inter) * (y2_inter - y1_inter)
    box1_area = (box1[2] - box1[0]) * (box1[3] - box1[1])
    box2_area = (box2[2] - box2[0]) * (box2[3] - box2[1])
    union_area = box1_area + box2_area - inter_area
    
    return inter_area / union_area if union_area > 0 else 0.0

best_gt_idx = None
best_gt_bbox = None
best_iou = 0.0

for person in van_ann["persons"]:
    gt_bbox = person["bbox"]
    iou = calculate_iou(det_bbox, gt_bbox)
    if iou > best_iou:
        best_iou = iou
        best_gt_idx = person["person_idx"]
        best_gt_bbox = gt_bbox

# Draw GT bbox if found
if best_gt_bbox:
    gx1, gy1, gx2, gy2 = best_gt_bbox
    draw.rectangle([gx1, gy1, gx2, gy2], outline="green", width=4)
    draw.text((gx1, gy1 - 20), f"GT person_idx={best_gt_idx} (IoU={best_iou:.3f})", 
              fill="green", font=font)
    
    # Draw overlap annotation
    overlap_x = min(x1, gx1)
    overlap_y = max(y2, gy2) + 10
    
    # Check who GT person matched to
    matched_to = None
    for det_name, det_data in van_record["detections"].items():
        if best_gt_idx in det_data.get("matched_gt_indices", []):
            matched_to = det_name
            break
    
    if matched_to:
        draw.text((overlap_x, overlap_y), 
                  f"IoU={best_iou:.3f} but GT idx={best_gt_idx} matched to {matched_to}",
                  fill="orange", font=font_small)
    else:
        draw.text((overlap_x, overlap_y), 
                  f"IoU={best_iou:.3f} but no match",
                  fill="orange", font=font_small)

# Add explanation text at bottom
img_width, img_height = img.size

kb_facts = [f"{f[0]}({f[1]}, {f[2]})" for f in person3_det.get("kb_facts", [])]
infrontof_facts = [f for f in kb_facts if "infrontof" in f]

explanation = [
    "UNMATCHED DETECTION ANALYSIS:",
    f"• person_3 has IoU={best_iou:.3f} with GT person_idx={best_gt_idx}",
    f"• GT person_idx={best_gt_idx} matched to {matched_to} - best match",
    "• person_3 remains unmatched → false positive",
    f"• person_3 has {len(infrontof_facts)} infrontof facts: {', '.join(infrontof_facts[:2])}",
    "• Depth cue present but detection not matched to GT"
]

text_y = img_height - 140
for line in explanation:
    draw.text((10, text_y), line, fill="white", font=font_small)
    # Add black outline for visibility
    for dx, dy in [(-1,-1), (-1,1), (1,-1), (1,1)]:
        draw.text((10+dx, text_y+dy), line, fill="black", font=font_small)
    text_y += 20

# Save output
output_dir = Path("eval/review_diagnostic")
output_dir.mkdir(exist_ok=True)
output_path = output_dir / "person3_unmatched_diagnostic.png"
img.save(output_path)

print(f"✓ Diagnostic overlay saved to {output_path}")
print(f"  Detection: person_3 [{x1:.0f}, {y1:.0f}, {x2:.0f}, {y2:.0f}] conf={det_conf:.3f}")
if best_gt_bbox:
    gx1, gy1, gx2, gy2 = best_gt_bbox
    print(f"  Closest GT: person_idx={best_gt_idx} [{gx1:.0f}, {gy1:.0f}, {gx2:.0f}, {gy2:.0f}] IoU={best_iou:.3f}")
    print(f"  GT matched to: {matched_to}")
print(f"  KB facts: {len(kb_facts)} total, {len(infrontof_facts)} infrontof")
print(f"  Reason unmatched: GT person_idx={best_gt_idx} already matched to {matched_to}")
