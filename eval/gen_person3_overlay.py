#!/usr/bin/env python3
"""Simple diagnostic overlay for person_3"""

import json
from PIL import Image, ImageDraw, ImageFont

# Load JSONL
with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "women_in_front_of_parked_van.jpg":
            break

# Find person_3
p3 = None
for det in rec["detections"]:
    if det["label"] == "person_3":
        p3 = det
        break

# Parse bbox (already a list in some versions)
bbox = p3["box"] if isinstance(p3["box"], list) else [float(v) for v in p3["box"].split()]
conf = p3["confidence"]

# Load image
img = Image.open("examples/women_in_front_of_parked_van.jpg")
draw = ImageDraw.Draw(img)

try:
    font = ImageFont.truetype("arial.ttf", 14)
except:
    font = ImageFont.load_default()

# Draw bbox
x1, y1, x2, y2 = bbox
draw.rectangle([x1, y1, x2, y2], outline="red", width=4)
draw.text((x1, y1-20), f"person_3 UNMATCHED FP (conf={conf:.3f})", fill="red", font=font)

# Add text
w, h = img.size
text = [
    "person_3 is an UNMATCHED DETECTION:",
    f"• bbox: [{int(x1)}, {int(y1)}, {int(x2)}, {int(y2)}], conf={conf:.3f}",
    "• Has infrontof KB facts but not matched to any GT person",
    "• Closest GT person was matched to a different detection",
    "• Counted as FALSE POSITIVE in error attribution"
]

y = h - 110
for line in text:
    draw.text((10, y), line, fill="yellow", font=font)
    y += 20

# Save
Path = __import__("pathlib").Path
out_dir = Path("eval/review_diagnostic")
out_dir.mkdir(exist_ok=True)
out_path = out_dir / "person3_unmatched.png"
img.save(out_path)

print(f"✓ Saved: {out_path}")
