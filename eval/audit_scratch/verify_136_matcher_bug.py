import json

def calculate_iou(box1, box2):
    if isinstance(box1, str):
        box1 = [float(v) for v in box1.split()]
    if isinstance(box2, str):
        box2 = [float(v) for v in box2.split()]
    
    x1 = max(box1[0], box2[0])
    y1 = max(box1[1], box2[1])
    x2 = min(box1[2], box2[2])
    y2 = min(box1[3], box2[3])
    
    if x1 >= x2 or y1 >= y2:
        return 0.0
    
    inter = (x2 - x1) * (y2 - y1)
    area1 = (box1[2] - box1[0]) * (box1[3] - box1[1])
    area2 = (box2[2] - box2[0]) * (box2[3] - box2[1])
    union = area1 + area2 - inter
    
    return inter / union if union > 0 else 0.0

# Load annotations
with open("eval/results/v1_frozen/annotations.json") as f:
    anns = json.load(f)
    img_ann = None
    for img in anns["images"]:
        if img["file"] == "000000000136.jpg":
            img_ann = img
            break

# Load results
with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "000000000136.jpg":
            break

print(f"Image: {rec['image']}")
print(f"\nGT person 0: {img_ann['persons'][0]['box']}")

# Get matched info
matched_list = rec.get("matched_persons", [])
match_0 = [m for m in matched_list if m["person_idx"] == 0][0]

print(f"\nMatched to: {match_0['matched_detection_label']}")
print(f"Matched IoU: {match_0['match_iou']:.3f}")

# Check all person detections
gt_bbox = img_ann['persons'][0]['box']
print(f"\nIoU with all person detections:")
for det in rec["detections"]:
    if det["class"] == "person":
        iou = calculate_iou(gt_bbox, det["box"])
        marker = " <-- MATCHED" if det["label"] == match_0['matched_detection_label'] else ""
        if iou > match_0['match_iou']:
            marker += " [BETTER MATCH!]"
        print(f"  {det['label']}: IoU={iou:.3f}{marker}")
