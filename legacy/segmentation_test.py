import torch

class OcclusionResolver:
    def __init__(self, result, iou_threshold=0.02):
        self.result = result
        self.iou_threshold = iou_threshold
        self.objects = self._prepare_objects()
        self.occlusions = self._resolve_occlusions()

    def _prepare_objects(self):
        # Create a list of detected objects with masks and labels
        names = self.result.names
        objects = []
        masks = self.result.masks.data.cpu().numpy()
        boxes = self.result.boxes.xyxy.cpu().numpy()
        classes = self.result.boxes.cls.cpu().numpy()

        for i, mask in enumerate(masks):
            objects.append({
                "id": i,
                "label": names[int(classes[i])],
                "mask": mask,
                "box": boxes[i],
            })

        return objects

    def _mask_overlap(self, mask1, mask2):
        # Convert to binary masks
        bin1 = mask1.astype(bool)
        bin2 = mask2.astype(bool)

        # Compute overlap (intersection)
        overlap = bin1 & bin2
        intersection = overlap.sum()

        # Compute IOU-like overlap fraction
        smaller_area = min(bin1.sum(), bin2.sum())

        if smaller_area == 0:
            return 0

        return intersection / smaller_area

    def _resolve_occlusions(self):
        relationships = []

        for i, obj_a in enumerate(self.objects):
            for j, obj_b in enumerate(self.objects):
                if i == j:
                    continue

                overlap_ratio = self._mask_overlap(obj_a["mask"], obj_b["mask"])
                if overlap_ratio > self.iou_threshold:
                    # Infer: object A is in front of object B
                    relationships.append(f"{obj_a['label']}_{obj_a['id']} is in front of {obj_b['label']}_{obj_b['id']}")

        return relationships

    def get_occlusion_relations(self):
        occlusion_relations = []
        masks = [obj["mask"] for obj in self.objects]
        names = [f"{obj['label']}_{obj['id']}" for obj in self.objects]

        for i, mask_a in enumerate(masks):
            for j, mask_b in enumerate(masks):
                if i == j:
                    continue

                bin_a = mask_a.astype(bool)
                bin_b = mask_b.astype(bool)

                overlap = (bin_a & bin_b).sum()

                if overlap > 0:
                    ratio = overlap / bin_b.sum()

                    if ratio > self.iou_threshold:
                        occlusion_relations.append(f"{names[i]} is in front of {names[j]}")

        return occlusion_relations



