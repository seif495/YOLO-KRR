"""From one YOLO result to the scene's detections and SNePSLOG statements (shared by the CLI and eval)."""
from .relations import relations
from .road import ground_under
from .scene import detections_from_result
from .snepslog import scene_statements

CONFIDENT = 0.5  # detections at or above this confidence get a confident(x) fact


def describe(result, conf=0.25, pair_filter=None, road_model=None, focus=("person",)):
    """Detections of one ultralytics Result, their relation facts, and the statements describing the scene.

    Besides isa() and the spatial relations, this asserts confident(x) for detections with
    confidence >= 0.5 and, with a road model, onroad(x) / onsidewalk(x) for the focus classes.
    """
    detections = detections_from_result(result, conf=conf)
    facts = relations(detections, result.orig_shape[0], pair_filter=pair_filter)
    statements = scene_statements(detections, facts)
    statements += [f"confident({d.label})" for d in detections if d.conf >= CONFIDENT]
    if road_model is not None:
        segmentation = road_model.segment(result.orig_img[:, :, ::-1])  # ultralytics images are BGR
        for d in detections:
            if d.cls in focus:
                ground = ground_under(segmentation, d.box)
                if ground:
                    statements.append(f"on{ground}({d.label})")
    return detections, facts, statements
