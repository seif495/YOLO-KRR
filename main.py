from ultralytics import YOLO
import torch

# Load a pretrained YOLO model
model = YOLO("yolo12n.pt")

# Train model (optional)
#model.train(data="coco128.yaml", epochs=3)

# Evaluate the model
val_results = model.val(data="coco128.yaml")
print(val_results.results_dict)

#Prepare output file
output_path = "yolo_validation_output.txt"

metrics = val_results.results_dict

# Extract class names
names = model.names  # {class_id: class_name}

# Extract metrics
metrics = val_results.results_dict

# Initialize metric lists
num_classes = len(names)
class_images = metrics.get('class_images', {})
class_instances = metrics.get('class_instances', {})

# Handle overall metrics directly (they are scalar values, not lists)
class_precision = metrics.get('metrics/precision(B)', 0.0)
class_recall = metrics.get('metrics/recall(B)', 0.0)
class_map50 = metrics.get('metrics/mAP50(B)', 0.0)
class_map50_95 = metrics.get('metrics/mAP50-95(B)', 0.0)

# Write to output file
with open(output_path, "w", encoding="utf-8") as file:
    file.write(f"{'Class':<15}{'Images':<10}{'Instances':<12}{'Precision':<12}"
               f"{'Recall':<10}{'mAP50':<10}{'mAP50-95'}\n")
    file.write("=" * 80 + "\n")

    # Writing the overall metrics for all classes
    for class_id, class_name in names.items():
        num_images = class_images.get(class_id, 0)
        num_instances = class_instances.get(class_id, 0)

        file.write(f"{class_name:<15}{num_images:<10}{num_instances:<12}"
                   f"{class_precision:<12.3f}{class_recall:<10.3f}"
                   f"{class_map50:<10.3f}{class_map50_95:.3f}\n")

print(f"✅ YOLO validation output saved to '{output_path}'")
