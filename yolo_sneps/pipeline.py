"""From one YOLO result to the scene's detections and SNePSLOG statements (shared by the CLI and eval)."""
from .relations import relations
from .scene import detections_from_result
from .snepslog import scene_statements


def describe(result, conf=0.25, pair_filter=None):
    """Detections of one ultralytics Result and the statements describing the scene."""
    detections = detections_from_result(result, conf=conf)
    facts = relations(detections, result.orig_shape[0], pair_filter=pair_filter)
    return detections, scene_statements(detections, facts)
