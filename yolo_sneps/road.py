"""What each person is standing on, from a street-scene segmentation model (optional).

Uses SegFormer trained on Cityscapes (dash-camera street scenes), so it is most reliable on
road-level photos. Needs `pip install transformers`; the model (about 15 MB) downloads on first use.
"""
import numpy as np

MODEL = "nvidia/segformer-b0-finetuned-cityscapes-1024-1024"
ROAD, SIDEWALK = 0, 1
# Cityscapes classes that are objects, not ground: person, rider, car, truck, bus, train, motorcycle, bicycle.
_OBJECTS = {11, 12, 13, 14, 15, 16, 17, 18}


class RoadModel:
    def __init__(self, model=MODEL):
        import torch
        from transformers import SegformerForSemanticSegmentation, SegformerImageProcessor
        self.torch = torch
        self.processor = SegformerImageProcessor.from_pretrained(model)
        self.model = SegformerForSemanticSegmentation.from_pretrained(model).eval()

    def segment(self, image):
        """Cityscapes class index per pixel for an RGB numpy image (H x W x 3)."""
        inputs = self.processor(images=image, return_tensors="pt")
        with self.torch.no_grad():
            logits = self.model(**inputs).logits
        logits = self.torch.nn.functional.interpolate(logits, size=image.shape[:2], mode="bilinear",
                                                      align_corners=False)
        return logits.argmax(1)[0].numpy()


def ground_under(segmentation, box):
    """'road', 'sidewalk' or None: the most common ground class just around the bottom of `box`."""
    height, width = segmentation.shape
    x1, y1, x2, y2 = box
    box_h, box_w = y2 - y1, x2 - x1
    top, bottom = int(max(0, y2 - 0.05 * box_h)), int(min(height, y2 + 0.08 * box_h)) + 1
    left, right = int(max(0, x1 + 0.2 * box_w)), int(min(width, x2 - 0.2 * box_w)) + 1
    band = segmentation[top:bottom, left:right].ravel()
    band = band[~np.isin(band, list(_OBJECTS))]
    if band.size == 0:
        return None
    label = np.bincount(band).argmax()
    return {ROAD: "road", SIDEWALK: "sidewalk"}.get(int(label))
