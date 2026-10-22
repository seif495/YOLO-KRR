import matplotlib.pyplot as plt
import cv2
import numpy as np
from ultralytics import YOLO
import torch

# Load the YOLO model
model = YOLO("yolo11n-seg.pt")  # Load the segmentation model

# Predict with the model
results = model("https://ultralytics.com/images/bus.jpg")  # Use the image for prediction

for result in results:
    boxes = result.boxes.xyxy  # Bounding boxes (x1, y1, x2, y2)
    scores = result.boxes.conf  # Confidence scores
    class_ids = result.boxes.cls  # Class IDs (indexes)
    class_names = [result.names[int(cls_id)] for cls_id in class_ids]  # Convert class IDs to names

    # Print the information for each detected object
    for i in range(len(boxes)):
        print(f"Object {i + 1}:")
        print(f"  Class: {class_names[i]} (ID: {int(class_ids[i])})")
        print(f"  Bounding Box: {boxes[i].tolist()}")  # Convert to list for readable output
        print(f"  Confidence: {scores[i]:.4f}")

# Extract the original image and mask data from results
orig_img = results[0].orig_img  # Original image in numpy format
masks = results[0].masks.data  # Mask data (num_objects x H x W)
boxes = results[0].boxes.xyxy  # Bounding boxes coordinates (optional if you want to show them)
names = results[0].names  # Class names

# Resize masks to match the original image size
H, W, _ = orig_img.shape  # Get original image dimensions

# Overlay each mask on the original image
for i, mask in enumerate(masks):
    mask = mask.cpu().numpy()  # Convert mask to numpy array
    mask_resized = cv2.resize(mask, (W, H))  # Resize the mask to the original image size

    color = np.random.randint(0, 255, size=3, dtype=np.uint8)  # Generate random color for the mask
    colored_mask = np.zeros_like(orig_img, dtype=np.uint8)

    # Apply the resized mask to the original image
    for c in range(3):  # For each color channel (RGB)
        colored_mask[:, :, c] = np.where(mask_resized > 0.5, color[c], 0)  # Add color where mask is present

    # Blend the mask with the original image (0.5 transparency)
    orig_img = cv2.addWeighted(orig_img, 1, colored_mask, 0.5, 0)

# Convert BGR to RGB for displaying in matplotlib
orig_img = cv2.cvtColor(orig_img, cv2.COLOR_BGR2RGB)

# Display the image with segmentation masks
plt.imshow(orig_img)
plt.axis('off')  # Hide axes
plt.show()
