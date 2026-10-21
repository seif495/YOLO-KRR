import matplotlib.pyplot as plt
import cv2
import numpy as np
from ultralytics import YOLO
import random

model = YOLO("yolo11n-seg.pt")
results = model("zidane.jpg")

orig_img = results[0].orig_img.copy()
H, W, _ = orig_img.shape

mask_overlay = np.zeros_like(orig_img, dtype=np.uint8)

detected_objects = []
masks = results[0].masks.data.cpu().numpy()  # shape: [num_objs, H, W]
class_ids = results[0].boxes.cls.cpu().numpy().astype(int)
boxes = results[0].boxes.xyxy.cpu().numpy()
class_names = results[0].names
label_counter = {}

for i, box in enumerate(boxes):
    label = class_names[class_ids[i]]
    label_counter[label] = label_counter.get(label, 0) + 1
    unique_label = f"{label}_{label_counter[label]}"
    mask = masks[i]

    # Create color
    color = [random.randint(0, 255) for _ in range(3)]

    # Overlay mask
    # Resize mask to match original image
    resized_mask = cv2.resize(mask.astype(np.uint8), (W, H), interpolation=cv2.INTER_NEAREST)

    # Create colored mask
    colored_mask = np.stack([resized_mask * c for c in color], axis=-1).astype(np.uint8)

    # Apply to overlay
    mask_overlay = np.where(resized_mask[..., None] == 1, colored_mask, mask_overlay)

    # Store info
    detected_objects.append({
        'label': unique_label,
        'base_label': label,
        'box': box.tolist(),
        'mask': resized_mask  # update here too
    })

blended_img = cv2.addWeighted(orig_img, 0.7, mask_overlay, 0.3, 0)

for obj in detected_objects:
    ys, xs = np.where(obj['mask'])
    if len(xs) == 0 or len(ys) == 0:
        continue
    cx, cy = int(xs.mean()), int(ys.mean())
    cv2.putText(blended_img, obj['label'], (cx, cy), cv2.FONT_HERSHEY_SIMPLEX,
                0.6, (255, 255, 255), 2, cv2.LINE_AA)

def analyze_spatial_relationship(obj1, obj2):
    x1_left, y1_top, x1_right, y1_bottom = obj1['box']
    x2_left, y2_top, x2_right, y2_bottom = obj2['box']
    relationships = []

    # Horizontal relationship
    if x1_right < x2_left:
        relationships.append(f"{obj1['label']} is completely to the left of {obj2['label']}")
    elif x2_right < x1_left:
        relationships.append(f"{obj1['label']} is completely to the right of {obj2['label']}")
    elif x1_right < x2_right:
        relationships.append(f"{obj1['label']} is slightly to the left of {obj2['label']}")
    elif x2_right < x1_right:
        relationships.append(f"{obj1['label']} is slightly to the right of {obj2['label']}")

    # Object 1 is fully inside object 2 horizontally
    if x1_left > x2_left and x1_right < x2_right:
        relationships.append(f"{obj1['label']} is in front of {obj2['label']}")
    # Object 1 fully contains object 2 horizontally
    elif x1_left < x2_left and x1_right > x2_right:
        relationships.append(f"{obj1['label']} is behind {obj2['label']}")

    # Vertical relationship
    if y1_bottom < y2_top:
        relationships.append(f"{obj1['label']} is above {obj2['label']}")
    elif y2_bottom < y1_top:
        relationships.append(f"{obj1['label']} is below {obj2['label']}")

    # Object 1 is fully inside object 2 vertically
    if y1_top > y2_top and y1_bottom < y2_bottom:
        relationships.append(f"{obj1['label']} is in front of {obj2['label']}")
    # Object 1 fully contains object 2 vertically
    elif y1_top < y2_top and y1_bottom > y2_bottom:
        relationships.append(f"{obj1['label']} is behind {obj2['label']}")

    return relationships


print("\n--- Spatial relationships based on segmentation masks ---")
for i in range(len(detected_objects)):
    for j in range(i + 1, len(detected_objects)):
        relations = analyze_spatial_relationship(detected_objects[i], detected_objects[j])
        for r in relations:
            print(r)

plt.imshow(cv2.cvtColor(blended_img, cv2.COLOR_BGR2RGB))
plt.axis('off')
plt.title("YOLO Segmentation and Spatial Relationships")
plt.show()
