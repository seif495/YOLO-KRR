import cv2
from ultralytics import YOLO

# Load a pretrained YOLO model
model = YOLO("yolo12n.pt")

results = model.train(data="coco128.yaml", epochs=3)

# Evaluate the model's performance on the validation set
results = model.val()
print(results)

# Perform object detection on the bus image using the model
results = model("https://ultralytics.com/images/bus.jpg")

# Show results (bounding boxes, labels, and confidence scores)
for result in results:
    # Get the original image
    img = result.orig_img

    # Get the bounding boxes, confidence scores, and class IDs
    boxes = result.boxes  # Object containing bounding boxes
    confidences = boxes.conf  # Confidence scores
    xyxy = boxes.xyxy  # Bounding box coordinates
    class_ids = boxes.cls  # Class IDs for the detected objects

    # Get the class names from the 'names' attribute in the result
    class_names = result.names

    # Draw bounding boxes, labels, and confidence scores on the image
    for box, conf, cls_id in zip(xyxy, confidences, class_ids):
        x1, y1, x2, y2 = map(int, box)
        label = class_names[int(cls_id)]  # Get the label name

        # Draw the rectangle on the image
        img = cv2.rectangle(img, (x1, y1), (x2, y2), (255, 0, 0), 2)  # Red box

        # Add the label and confidence score as a label on the image
        text = f'{label} {conf:.2f}'
        img = cv2.putText(img, text, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 2)

    # Save the image with bounding boxes, labels, and confidence scores
    cv2.imwrite('output_with_labels.jpg', img)

print("Image saved as 'labelled_output.jpg'")
