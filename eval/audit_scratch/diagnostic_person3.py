#!/usr/bin/env python3
"""
Generate diagnostic overlay for person_3 in women_in_front_of_parked_van.jpg
"""

import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# Load JSONL and find the van image
with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "women_in_front_of_parked_van.jpg":
            van_rec = rec
            break

# Find person_3 in detections list
person_3 = None
for det in van_rec["detections"]:
    if det["label"] == "person_3":
        person_3 = det
        break

if not person_3:
    print("ERROR: person_3 not found")
    exit(1)

# Load annotations to get GT bboxes
annotations = json.load(open("eval/results/v1_frozen/annotations.json"))
van_ann = None
for img_ann in annotations["images"]:
    if img_ann["file_name"] == "women_in_front_of_parked_van.jpg":
        van_ann = img_ann
        break

# Calculate IoU helper
def iou(box1, box2):
    x1 = max(box1[0], box2[0])
    y1 = max(box1[1], box2[1])
    x2 = min(box1[2], box2[2])
    y2 = min(box1[3], box2[3])
    if x1 >= x2 or y1 >= y2:
        return 0.0
    inter = (x2-x1) * (y2-y1)
    area1 = (box1[2]-box1[0]) * (box1[3]-box1[1])
    area2 = (box2[2]-box2[0]) * (box2[3]-box2[1])
    return inter / (area1 + area2 - inter)

# Find best GT match for person_3
det_bbox = person_3["bbox"]
best_gt_idx = None
best_gt_bbox = None
best_iou = 0.0

for person in van_ann["persons"]:
    gt_bbox = person["bbox"]
    curr_iou = iou(det_bbox, gt_bbox)
    if curr_iou > best_iou:
        best_iou = curr_iou
        best_gt_idx = person["person_idx"]
        best_gt_bbox = gt_bbox

# Find which detection matched that GT person
matched_to = None
for det in van_rec["detections"]:
    if det.get("matched_gt_person_idx") == best_gt_idx:
        matched_to = det["label"]
        break

# Load image and draw
img = Image.open("examples/women_in_front_of_parked_van.jpg")
draw = ImageDraw.Draw(img)

try:
    font = ImageFont.truetype("arial.ttf", 14)
    font_small = ImageFont.truetype("arial.ttf", 11)
except:
    font = ImageFont.load_default()
    font_small = ImageFont.load_default()

# Draw person_3 bbox (RED)
# Parse bbox from string "x1 y1 x2 y2"
det_bbox_str = person_3["box"].split()
det_bbox = [float(v) for v in det_bbox_str]
x1, y1, x2, y2 = det_bbox
draw.rectangle([x1, y1, x2, y2], outline="red", width=3)
draw.text((x1, y1-18), f"person_3 (FP unmatched, conf={person_3['confidence']:.3f})", fill="red", font=font)

# Draw GT bbox (GREEN)
if best_gt_bbox:
    gx1, gy1, gx2, gy2 = best_gt_bbox
    draw.rectangle([gx1, gy1, gx2, gy2], outline="green", width=3)
    draw.text((gx1, gy1-18), f"GT person_idx={best_gt_idx} (matched to {matched_to})", fill="green", font=font)

# Add text overlay at bottom
w, h = img.size
lines = [
    "UNMATCHED DETECTION DIAGNOSTIC:",
    f"• person_3: bbox={[int(v) for v in det_bbox]}, conf={person_3['confidence']:.3f}",
    f"• Best GT match: person_idx={best_gt_idx}, IoU={best_iou:.3f}",
    f"• GT person_{best_gt_idx} matched to: {matched_to} (better IoU)",
    f"• person_3 KB facts: {len(person_3.get('kb_facts', []))} total, including infrontof(person_3, car_1), infrontof(person_3, truck_1)",
    "• Result: person_3 is unmatched FP despite having danger cues"
]

y = h - 130
for line in lines:
    # Black outline
    for dx, dy in [(-1,-1), (-1,1), (1,-1), (1,1)]:
        draw.text((10+dx, y+dy), line, fill="black", font=font_small)
    # White text
    draw.text((10, y), line, fill="white", font=font_small)
    y += 20

# Save
output_dir = Path("eval/review_diagnostic")
output_dir.mkdir(exist_ok=True)
output_path = output_dir / "person3_unmatched_diagnostic.png"
img.save(output_path)

print(f"✓ Diagnostic saved: {output_path}")
print(f"  person_3: {det_bbox}, conf={person_3['confidence']:.3f}")
print(f"  Best GT: person_idx={best_gt_idx}, IoU={best_iou:.3f}, matched to {matched_to}")
print(f"  KB facts: {len(person_3.get('kb_facts', []))}")
