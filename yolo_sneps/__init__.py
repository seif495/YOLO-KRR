"""Bridge from YOLO detections to a SNePS knowledge base.

YOLO-KRR does the vision work; SNePS (driven through SNePSpaCy's sneps_wrapper, or the
headless Windows build) does the reasoning. The contract between them is typed SNePSLOG:

    isa(person_1, person).          one fact per detection
    infrontof(person_1, car_1).     image-plane relations between detections

Rules (kb/danger.snepslog) map classes to categories and derive dangerous(x).
"""
from .scene import Detection, atom, build_detections, detections_from_result
from .relations import relations, focus_pairs
from .snepslog import scene_statements, check_statement, load_rules, parse_answers

__all__ = ["Detection", "atom", "build_detections", "detections_from_result", "relations",
           "focus_pairs", "scene_statements", "check_statement", "load_rules", "parse_answers"]
