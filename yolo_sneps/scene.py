"""Turn YOLO output into detections with stable, SNePSLOG-safe labels."""
import re
from dataclasses import dataclass

# Words SNePSLOG gives a meaning of its own, and names of the shape SNePS uses for its own nodes.
_RESERVED = {"all", "and", "andor", "exists", "iff", "nexists", "nil", "or", "t", "thresh"}
_NODE_NAME = re.compile(r"(wff|m|v|b|p)\d+")


@dataclass(frozen=True)
class Detection:
    label: str   # instance atom, e.g. "stop_sign_1"
    cls: str     # class atom, e.g. "stop_sign"
    box: tuple   # (x1, y1, x2, y2) in original-image pixels
    conf: float


def atom(name):
    """Make a SNePSLOG-safe atom: lower case, runs of other characters become '_', and names
    SNePS would misread (a leading digit, a reserved word, a node name like m1) get a 'c_' prefix."""
    a = re.sub(r"[^0-9a-z]+", "_", str(name).lower()).strip("_")
    if not a or a[0].isdigit() or a in _RESERVED or _NODE_NAME.fullmatch(a):
        a = "c_" + a
    return a


def _intersection(a, b):
    return max(0.0, min(a[2], b[2]) - max(a[0], b[0])) * max(0.0, min(a[3], b[3]) - max(a[1], b[1]))


def _area(box):
    return (box[2] - box[0]) * (box[3] - box[1])


def iou(a, b):
    inter = _intersection(a, b)
    union = _area(a) + _area(b) - inter
    return inter / union if union > 0 else 0.0


def containment(a, b):
    """Share of the smaller box that lies inside the other one."""
    smaller = min(_area(a), _area(b))
    return _intersection(a, b) / smaller if smaller > 0 else 0.0


def _is_duplicate(cls, box, kept, dup_iou, same_iou, same_containment):
    for k_cls, k_box, _ in kept:
        overlap = iou(box, k_box)
        if overlap >= dup_iou:
            return True
        if k_cls == cls and overlap >= same_iou and containment(box, k_box) >= same_containment:
            return True
    return False


def build_detections(raw, conf=0.25, dup_iou=0.85, same_iou=0.6, same_containment=0.95):
    """Build labelled detections from (class_name, (x1, y1, x2, y2), confidence) tuples.

    Drops detections below `conf` and drops a box that duplicates a more confident one:
    any box overlapping it with IoU >= `dup_iou` (YOLO's NMS is per class, so one car can come
    back as both car and truck), or a box of the same class that lies almost entirely inside it
    (a second, partial box on the same person survives NMS when its IoU is below 0.7).
    Instances are numbered per class from left to right, so labels follow the picture rather
    than the detector's confidence ranking.
    """
    kept = []
    for name, box, c in sorted(raw, key=lambda r: -r[2]):
        cls, box = atom(name), tuple(float(v) for v in box)
        if c >= conf and not _is_duplicate(cls, box, kept, dup_iou, same_iou, same_containment):
            kept.append((cls, box, float(c)))

    detections, counters = [], {}
    for cls, box, c in sorted(kept, key=lambda k: (k[0], k[1][0], k[1][1])):
        counters[cls] = counters.get(cls, 0) + 1
        detections.append(Detection(f"{cls}_{counters[cls]}", cls, box, c))
    return detections


def detections_from_result(result, conf=0.25):
    """Detections from one ultralytics Result.

    Uses boxes only, so it works with detection and segmentation models alike and
    returns an empty list for an empty scene instead of failing on missing masks.
    """
    boxes = result.boxes
    if boxes is None or len(boxes) == 0:
        return []
    raw = [(result.names[int(k)], xyxy, c)
           for k, xyxy, c in zip(boxes.cls.tolist(), boxes.xyxy.tolist(), boxes.conf.tolist())]
    return build_detections(raw, conf)
