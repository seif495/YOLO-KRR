from ultralytics import YOLO

from segmentation_test import OcclusionResolver

model = YOLO("yolo11n-seg.pt")

results = model("https://ultralytics.com/images/bus.jpg")

resolver = OcclusionResolver(results[0], iou_threshold=0.01)
relations = resolver.get_occlusion_relations()

for r in relations:
    print(r)
