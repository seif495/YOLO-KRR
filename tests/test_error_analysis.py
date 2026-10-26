"""Tests for the error attribution (eval/analyze_errors.py) and its audit (eval/audit_baseline_v2.py).

Run with the other tests: python -m unittest discover -s tests

The scenes are written out by hand and scored with the evaluator's own functions, so these need
neither YOLO nor SNePS; BaselineTest reads the committed baseline run in eval/results.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from analyze_errors import ReconciliationError, analyze, hazard_classes, report  # noqa: E402
from audit_baseline_v2 import (blocking_pairs, check_detections, check_evidence,  # noqa: E402
                               check_false_negatives, check_matcher, check_reconciliation)
from evaluate import score  # noqa: E402
from evaluate_instrumented import match_ground_truth_to_detections  # noqa: E402
from yolo_sneps import Detection, focus_pairs, relations  # noqa: E402

HAZARDS = hazard_classes(ROOT / "kb" / "danger.snepslog")
RESULTS = ROOT / "eval" / "results"

# A bus with a person in front of it (overlapping, feet clearly lower) and a car off to the right.
BUS = (100, 300, 600, 700)
IN_FRONT = (300, 400, 380, 760)
CAR = (800, 300, 950, 450)


def scene(detections, persons, hazards=(), pairs=(), flagged=(), alerted=(), name="scene.jpg"):
    """A record as evaluate_instrumented.py writes it, scored by the evaluator's own functions.

    detections: (label, class, box, confidence); persons: (box, dangerous); hazards: (class, box);
    pairs: (person index, hazard index, nearer).
    """
    dets = [Detection(label, cls, tuple(box), conf) for label, cls, box, conf in detections]
    truth = [{"box": list(box), "dangerous": dangerous} for box, dangerous in persons]
    tp, fp, fn = score(set(flagged), [d for d in dets if d.cls == "person"], truth)
    return {
        "image": name, "image_height": 1000,
        "ground_truth": {"persons": truth, "hazards": [{"class": c, "box": list(b)} for c, b in hazards],
                         "pairs": [{"person": p, "hazard": h, "nearer": n} for p, h, n in pairs]},
        "detections": [{"label": d.label, "class": d.cls, "box": list(d.box), "confidence": d.conf} for d in dets],
        "facts": [list(f) for f in relations(dets, 1000, pair_filter=focus_pairs({"person"}))],
        "matched_persons": match_ground_truth_to_detections(truth, dets),
        "predictions": {"dangerous": sorted(flagged), "alert": sorted(alerted), "hidden": []},
        "evaluation": {"dangerous": {"tp": tp, "fp": fp, "fn": fn}},
    }


def only_error(record):
    errors, _ = analyze([record], HAZARDS)
    assert len(errors) == 1, errors
    return errors[0]


def attribution(records, summary=None):
    errors, counts = analyze(records, HAZARDS, summary)
    return {"hazard_classes": sorted(HAZARDS), "summary": report(errors, counts), "errors": errors}


class FalsePositiveTest(unittest.TestCase):
    def flagged_in_front(self, nearer, alerted=()):
        """person_1 in front of the bus, annotated safe, with the bus annotated as a truck."""
        return scene([("person_1", "person", IN_FRONT, 0.8), ("car_1", "car", CAR, 0.9), ("bus_1", "bus", BUS, 0.9)],
                     [(IN_FRONT, False)], [("truck", BUS), ("car", CAR)], [(0, 0, nearer)],
                     flagged=["person_1"], alerted=alerted)

    def test_rule_too_broad_links_hazard_by_overlap_not_class(self):
        e = only_error(self.flagged_in_front("person"))
        self.assertEqual((e["type"], e["root_cause"], e["person_idx"]), ("FP", "4b_rule_broad", 0))
        [trigger] = e["evidence"]["triggers"]
        self.assertEqual((trigger["detection"], trigger["annotated_class"]), ("bus_1", "truck"))
        self.assertIn("annotated truck", e["explanation"])
        self.assertFalse(e["requires_manual_review"])

    def test_depth_order_and_unclear_pairs(self):
        self.assertEqual(only_error(self.flagged_in_front("hazard"))["root_cause"], "2a_depth_order")
        self.assertEqual(only_error(self.flagged_in_front("unclear"))["root_cause"], "6b_uncertain")

    def test_confident_false_positive_adds_policy_factor(self):
        self.assertEqual(only_error(self.flagged_in_front("person", alerted=["person_1"]))["contributing_factors"],
                         ["5b_conf_high"])

    def test_infrontof_a_non_hazard_is_not_evidence(self):
        e = only_error(scene([("person_1", "person", IN_FRONT, 0.8), ("backpack_1", "backpack", BUS, 0.6)],
                             [(IN_FRONT, False)], flagged=["person_1"]))
        self.assertEqual((e["root_cause"], e["evidence"]["triggers"]), ("unknown", []))
        self.assertTrue(e["requires_manual_review"])

    def test_second_box_on_a_matched_person_is_an_unmatched_detection(self):
        shifted = (310, 400, 400, 760)  # IoU 0.7 with the annotated person
        errors, _ = analyze([scene([("person_1", "person", IN_FRONT, 0.8), ("person_2", "person", shifted, 0.6),
                                    ("bus_1", "bus", BUS, 0.9)],
                                   [(IN_FRONT, False)], [("bus", BUS)], [(0, 0, "person")],
                                   flagged=["person_1", "person_2"])], HAZARDS)
        self.assertEqual([(e["person_label"], e["root_cause"]) for e in errors],
                         [("person_1", "4b_rule_broad"), ("person_2", "unmatched_detection")])
        self.assertIsNone(errors[1]["person_idx"])
        self.assertEqual(errors[1]["evidence"]["closest_person"]["matched_to"], "person_1")


class FalseNegativeTest(unittest.TestCase):
    def missed(self, detections, person_box, hazards, pairs=()):
        return only_error(scene(detections, [(person_box, True)], hazards, pairs))

    def test_undetected_person(self):
        self.assertEqual(self.missed([("bus_1", "bus", BUS, 0.9)], IN_FRONT, [("bus", BUS)])["root_cause"],
                         "1a_missing_person")

    def test_badly_placed_box_is_poor_localization(self):
        e = self.missed([("person_1", "person", (340, 400, 420, 760), 0.8)], IN_FRONT, [("bus", BUS)])
        self.assertEqual((e["root_cause"], e["evidence"]["closest_unmatched_detection"]["label"]),
                         ("1d_poor_localization", "person_1"))

    def test_undetected_hazard(self):
        e = self.missed([("person_1", "person", IN_FRONT, 0.8)], IN_FRONT, [("bus", BUS)], [(0, 0, "person")])
        self.assertEqual(e["root_cause"], "1b_missing_vehicle")

    def test_beside_a_hazard_is_rule_too_narrow_and_names_the_nearest(self):
        beside = (40, 450, 95, 690)  # just left of the bus, no overlap
        e = self.missed([("person_1", "person", beside, 0.8), ("bus_1", "bus", BUS, 0.9), ("car_1", "car", CAR, 0.9)],
                        beside, [("bus", BUS), ("car", CAR)])
        self.assertEqual(e["root_cause"], "4c_rule_narrow")
        self.assertIn("bus_1", e["explanation"])
        self.assertFalse(e["evidence"]["overlaps_annotated_hazard"])
        self.assertTrue(e["requires_manual_review"])  # no pair annotated, and the label conflicts with the guidelines

    def test_true_overlap_lost_by_the_detector_is_poor_localization(self):
        truth, detected = (580, 350, 660, 750), (602, 350, 682, 750)  # IoU 0.57; only the true box overlaps the bus
        e = self.missed([("person_1", "person", detected, 0.8), ("bus_1", "bus", BUS, 0.9)], truth,
                        [("bus", BUS)], [(0, 0, "person")])
        self.assertEqual(e["root_cause"], "1d_poor_localization")

    def test_overlap_without_depth_fact_is_depth_order(self):
        level = (300, 400, 380, 705)  # feet within the 2% depth margin of the bus's
        e = self.missed([("person_1", "person", level, 0.8), ("bus_1", "bus", BUS, 0.9)], level,
                        [("bus", BUS)], [(0, 0, "person")])
        self.assertEqual((e["root_cause"], e["evidence"]["candidates"][0]["relation"]), ("2a_depth_order", "level"))

    def test_premise_asserted_but_not_concluded_is_inference_failure(self):
        e = self.missed([("person_1", "person", IN_FRONT, 0.8), ("bus_1", "bus", BUS, 0.9)], IN_FRONT,
                        [("bus", BUS)], [(0, 0, "person")])
        self.assertEqual(e["root_cause"], "4d_chained")
        self.assertTrue(e["requires_manual_review"])


class ReconciliationTest(unittest.TestCase):
    def test_per_image_mismatch_stops_the_analysis(self):
        record = FalsePositiveTest().flagged_in_front("person")
        record["evaluation"]["dangerous"]["fp"] = 0
        with self.assertRaises(ReconciliationError):
            analyze([record], HAZARDS)

    def test_summary_mismatch_stops_the_analysis(self):
        with self.assertRaises(ReconciliationError):
            analyze([FalsePositiveTest().flagged_in_front("person")], HAZARDS, {"danger_tp_fp_fn": [0, 2, 0]})

    def test_audit_catches_errors_moved_between_images(self):
        records = [FalsePositiveTest().flagged_in_front("person"),
                   scene([("bus_1", "bus", BUS, 0.9)], [(IN_FRONT, True)], [("bus", BUS)], name="other.jpg")]
        result = attribution(records)
        self.assertEqual(check_reconciliation(records, {"danger_tp_fp_fn": [0, 1, 1]}, result)[0], [])
        result["errors"][0]["image"], result["errors"][1]["image"] = "other.jpg", "scene.jpg"
        self.assertTrue(check_reconciliation(records, {"danger_tp_fp_fn": [0, 1, 1]}, result)[0])


class MatcherAuditTest(unittest.TestCase):
    # p1 is annotated person 1 exactly; it also overlaps person 0 (IoU 0.82) more than p2 does (0.54).
    TRUTH = [(0, 0, 10, 10), (1, 0, 11, 10)]
    DETECTED = [(1, 0, 11, 10), (-3, 0, 7, 10)]

    def test_one_to_one_matching_may_give_a_person_their_second_best_box(self):
        self.assertEqual(blocking_pairs(self.TRUTH, self.DETECTED, {0: 1, 1: 0}), [])  # what greedy matching gives

    def test_first_match_is_caught(self):
        self.assertEqual(blocking_pairs(self.TRUTH, self.DETECTED, {0: 0}), [(1, 0, 1.0)])

    def test_scene_matchings_are_stable(self):
        record = FalsePositiveTest().flagged_in_front("person")
        self.assertEqual(check_matcher([record])[0], [])


@unittest.skipUnless((RESULTS / "baseline_instrumented_detailed.jsonl").exists(), "baseline run not present")
class BaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lines = (RESULTS / "baseline_instrumented_detailed.jsonl").read_text(encoding="utf-8").splitlines()
        cls.records = [json.loads(line) for line in lines if line.strip()]
        cls.summary = json.loads((RESULTS / "baseline_instrumented.json").read_text(encoding="utf-8"))["summary"]
        cls.attribution = attribution(cls.records, cls.summary)

    def test_attribution_reconciles_with_the_run(self):
        self.assertEqual(list(self.attribution["summary"]["counts"].values()), self.summary["danger_tp_fp_fn"])

    def test_audit_passes(self):
        for problems, _ in (check_reconciliation(self.records, self.summary, self.attribution),
                            check_matcher(self.records), check_detections(self.records, self.summary),
                            check_false_negatives(self.records, self.summary),
                            check_evidence(self.records, self.attribution)):
            self.assertEqual(problems, [])

    def test_committed_attribution_is_current(self):
        committed = json.loads((RESULTS / "baseline_error_attribution.json").read_text(encoding="utf-8"))
        self.assertEqual((committed["summary"], committed["errors"]),
                         (self.attribution["summary"], self.attribution["errors"]),
                         "re-run eval/analyze_errors.py on the baseline")


if __name__ == "__main__":
    unittest.main()
