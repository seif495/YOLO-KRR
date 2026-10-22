import subprocess
import matplotlib.pyplot as plt
import cv2
import numpy as np
from ultralytics import YOLO
import random
import time

sneps_proc = subprocess.Popen(
    ['sbcl'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

def initialize_sneps():
    send_to_sneps('(load "C:/Users/DELL/Downloads/Sneps-Windows-Exe-2.7.0/Sneps-2.7.0-Windows/sneps_config.lisp")')
    time.sleep(3) # Give SNePS time to initialize
    send_to_sneps('(snepslog)')
    time.sleep(3) # Give SNePS time to initialize
    send_to_sneps('(load "C:/Users/DELL/Downloads/Sneps-Windows-Exe-2.7.0/Sneps-2.7.0-Windows/danger_kb.lisp")')
    time.sleep(3)  # Give SNePS time to initialize
    send_to_sneps('(load "C:/Users/DELL/Downloads/Sneps-Windows-Exe-2.7.0/Sneps-2.7.0-Windows/danger_kb.lisp")')


def send_to_sneps(command):
    if sneps_proc.poll() is None:
        sneps_proc.stdin.write(command + "\n")
        sneps_proc.stdin.flush()
        time.sleep(0.2)
        output = []
        while True:
            line = sneps_proc.stdout.readline().strip()
            if not line or line == ">":
                break
            output.append(line)
        return "\n".join(output)
    else:
        print("SNePS process terminated.")

initialize_sneps() # Call this after starting the subprocess

#object_rank = {name: i for i, name in enumerate(sorted_objects)}
detected_objects = []

model = YOLO("yolo11n-seg.pt")
results = model("img_3.png")

for result in results:
    boxes = result.boxes.xyxy
    scores = result.boxes.conf
    class_ids = result.boxes.cls
    class_names = [result.names[int(cls_id)] for cls_id in class_ids]
    label_counter = {}

    for i in range(len(boxes)):
        box = boxes[i]
        label = class_names[i]
        area = (box[2] - box[0]) * (box[3] - box[1])
        label_counter[label] = label_counter.get(label, 0) + 1
        unique_label = f"{label}_{label_counter[label]}"
        detected_objects.append({
            'label': unique_label,
            'base_label': label,
            'area': area.item(),
            #'rank': object_rank.get(label, -1),
            'box': box.tolist()
        })

orig_img = results[0].orig_img
masks = results[0].masks.data
H, W, _ = orig_img.shape

binary_masks = []
for mask in masks:
    mask_np = mask.cpu().numpy()
    mask_resized = cv2.resize(mask_np, (W, H), interpolation=cv2.INTER_NEAREST)
    binary_masks.append(mask_resized > 0.5)

def analyze_spatial_relationship(obj1, obj2):
    x1_left, y1_top, x1_right, y1_bottom = obj1['box']
    x2_left, y2_top, x2_right, y2_bottom = obj2['box']
    relations = []
    if x1_right < x2_left:
        relations.append(("left", obj1['label'], obj2['label']))
    elif x2_right < x1_left:
        relations.append(("right", obj1['label'], obj2['label']))
    elif x1_right < x2_right:
        relations.append(("slightly-left", obj1['label'], obj2['label']))
    elif x2_right < x1_right:
        relations.append(("slightly-right", obj1['label'], obj2['label']))
    if y1_bottom < y2_top:
        relations.append(("above", obj1['label'], obj2['label']))
    elif y2_bottom < y1_top:
        relations.append(("below", obj1['label'], obj2['label']))
    return relations

for i in range(len(detected_objects)):
    for j in range(i + 1, len(detected_objects)):
        obj1 = detected_objects[i]
        obj2 = detected_objects[j]
        relations = analyze_spatial_relationship(obj1, obj2)
        for rel, a, b in relations:
            lisp_describe = f"{rel}({a}, {b})."
            send_to_sneps(lisp_describe)

for i in range(len(detected_objects)):
    for j in range(i + 1, len(detected_objects)):
        obj1 = detected_objects[i]
        obj2 = detected_objects[j]
        box1 = list(map(int, obj1['box']))
        box2 = list(map(int, obj2['box']))
        x1_left, y1_top, x1_right, y1_bottom = box1
        x2_left, y2_top, x2_right, y2_bottom = box2

        if x1_right < x2_left or x2_right < x1_left or y1_bottom < y2_top or y2_bottom < y1_top:
            continue

        overlap_left = max(x1_left, x2_left)
        overlap_top = min(y1_top, y2_top)
        overlap_right = min(x1_right, x2_right)
        overlap_bottom = max(y1_bottom, y2_bottom)

        mask1 = binary_masks[i][overlap_top:overlap_bottom, overlap_left:overlap_right]
        mask2 = binary_masks[j][overlap_top:overlap_bottom, overlap_left:overlap_right]

        pixels1 = np.sum(mask1)
        pixels2 = np.sum(mask2)

        if pixels1 > pixels2:
            lisp_describe = f"in-front-of({obj1['label']}, {obj2['label']})."
        elif pixels2 > pixels1:
            lisp_describe = f"in-front-of({obj2['label']}, {obj1['label']})."
        else:
            lisp_describe = f"same-depth({obj1['label']}, {obj2['label']})."
        send_to_sneps(lisp_describe)

print("\n=== SNePS INFERRED DANGEROUS POSITIONS ===")
response = send_to_sneps('(find dangerous)')
print(response)
# Terminate SNePS (msh lazem)
# sneps_proc.stdin.write("(exit)\n")
# sneps_proc.stdin.flush()

for i, mask in enumerate(masks):
    mask = mask.cpu().numpy()
    mask_resized = cv2.resize(mask, (W, H))
    color = np.random.randint(0, 255, size=3, dtype=np.uint8)
    colored_mask = np.zeros_like(orig_img, dtype=np.uint8)
    for c in range(3):
        colored_mask[:, :, c] = np.where(mask_resized > 0.5, color[c], 0)
    orig_img = cv2.addWeighted(orig_img, 1, colored_mask, 0.5, 0)

for obj in detected_objects:
    box = list(map(int, obj['box']))
    label = obj['label']
    color = tuple(np.random.randint(0, 255, size=3).tolist())
    cv2.rectangle(orig_img, (box[0], box[1]), (box[2], box[3]), color, 2)
    cv2.putText(orig_img, label, (box[0], box[1] - 10), cv2.FONT_HERSHEY_SIMPLEX,
                0.6, color, 2, cv2.LINE_AA)

orig_img = cv2.cvtColor(orig_img, cv2.COLOR_BGR2RGB)
plt.imshow(orig_img)
plt.axis('off')
plt.show()
