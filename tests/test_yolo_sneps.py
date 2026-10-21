"""Unit tests for the YOLO -> SNePSLOG bridge. Run with: python -m unittest discover -s tests

They need neither YOLO weights nor SNePS. Set SNEPS_DIR to the Windows SNePS folder to also
run the end-to-end tests against the real reasoner.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from yolo_sneps import (atom, build_detections, check_statement, focus_pairs, load_rules,
                        parse_answers, relations, scene_statements)
from yolo_sneps.backends import _driver_markers, lisp_string, transcript

RULES = Path(__file__).resolve().parent.parent / "kb" / "danger.snepslog"

# A runner whose feet are lower in the picture than the car's wheels, in front of that car,
# and a second person standing farther back, behind the car.
RUNNER_SCENE = [("car", (10, 50, 370, 165), 0.9), ("person", (180, 30, 330, 245), 0.8),
                ("person", (200, 20, 240, 120), 0.6)]


class AtomTest(unittest.TestCase):
    def test_spaces_and_case(self):
        self.assertEqual(atom("stop sign"), "stop_sign")
        self.assertEqual(atom("Traffic Light"), "traffic_light")

    def test_names_snepslog_would_misread(self):
        self.assertEqual(atom("3d glasses"), "c_3d_glasses")
        self.assertEqual(atom("nil"), "c_nil")
        self.assertEqual(atom("nexists"), "c_nexists")
        self.assertEqual(atom("m1"), "c_m1")


class DetectionTest(unittest.TestCase):
    def test_numbered_left_to_right_whatever_the_input_order(self):
        raw = [("car", (300, 0, 400, 50), 0.9), ("car", (0, 0, 100, 50), 0.5)]
        self.assertEqual(build_detections(raw), build_detections(raw[::-1]))
        first = build_detections(raw)[0]
        self.assertEqual((first.label, first.box[0]), ("car_1", 0.0))

    def test_confidence_threshold(self):
        dets = build_detections([("car", (0, 0, 10, 10), 0.2), ("car", (20, 0, 30, 10), 0.3)], conf=0.25)
        self.assertEqual([d.label for d in dets], ["car_1"])

    def test_cross_class_duplicate_keeps_the_more_confident_box(self):
        dets = build_detections([("truck", (0, 0, 100, 100), 0.4), ("car", (1, 1, 100, 100), 0.7)])
        self.assertEqual([d.label for d in dets], ["car_1"])

    def test_nested_same_class_duplicate_is_dropped(self):
        # img_2.png: YOLO returns the child twice; the weaker box lies inside the stronger (IoU 0.68).
        child = [("person", (245.5, 139.8, 347.1, 291.8), 0.826), ("person", (245.5, 140.3, 320.6, 279.7), 0.295)]
        self.assertEqual([d.conf for d in build_detections(child)], [0.826])

    def test_overlapping_people_are_kept(self):
        # img_1.png: two different people whose boxes overlap.
        people = [("person", (551.6, 874.9, 955.3, 1540.8), 0.772), ("person", (589.5, 819.7, 926.5, 1048.3), 0.321)]
        self.assertEqual(len(build_detections(people)), 2)

    def test_space_in_class_name(self):
        self.assertEqual(build_detections([("stop sign", (0, 0, 10, 10), 0.9)])[0].label, "stop_sign_1")


class RelationTest(unittest.TestCase):
    def facts(self, raw, height=100):
        return set(relations(build_detections(raw), height))

    def test_direction_comes_from_geometry_not_order(self):
        raw = [("person", (0, 0, 10, 10), 0.9), ("car", (50, 0, 60, 10), 0.8)]
        self.assertEqual(self.facts(raw), self.facts(raw[::-1]))
        self.assertIn(("leftof", "person_1", "car_1"), self.facts(raw))

    def test_above(self):
        facts = self.facts([("person", (0, 0, 10, 10), 0.9), ("car", (0, 50, 10, 60), 0.8)])
        self.assertIn(("above", "person_1", "car_1"), facts)

    def test_touching_boxes_get_no_relation(self):
        self.assertEqual(self.facts([("person", (0, 0, 10, 10), 0.9), ("car", (10, 0, 20, 10), 0.8)]), set())

    def test_lower_base_is_in_front(self):
        facts = self.facts(RUNNER_SCENE, height=280)
        self.assertIn(("infrontof", "person_1", "car_1"), facts)
        self.assertIn(("infrontof", "car_1", "person_2"), facts)

    def test_bases_within_margin_give_no_depth_fact(self):
        facts = self.facts([("person", (0, 0, 50, 100), 0.9), ("car", (20, 10, 90, 99), 0.8)], height=100)
        self.assertIn(("overlaps", "car_1", "person_1"), facts)
        self.assertFalse(any(p == "infrontof" for p, _, _ in facts))

    def test_focus_pairs_need_one_focus_object_and_one_other(self):
        raw = [("car", (0, 0, 10, 10), 0.9), ("car", (50, 0, 60, 10), 0.8),
               ("person", (100, 0, 110, 10), 0.7), ("person", (150, 0, 160, 10), 0.7)]
        facts = relations(build_detections(raw), 100, pair_filter=focus_pairs(["person"]))
        self.assertEqual(len(facts), 4)
        for _, x, y in facts:
            self.assertEqual(sorted(label.split("_")[0] for label in (x, y)), ["car", "person"])


class SnepslogTest(unittest.TestCase):
    def test_statements(self):
        dets = build_detections([("stop sign", (0, 0, 10, 10), 0.9)])
        self.assertEqual(scene_statements(dets, [("leftof", "a", "b")]), ["isa(stop_sign_1, stop_sign)", "leftof(a, b)"])

    def test_check_statement(self):
        self.assertIsNone(check_statement("all(x,y)({infrontof(x,y)} &=> {dangerous(x)})"))
        self.assertEqual(check_statement("isa(person_1"), "unbalanced brackets")
        self.assertEqual(check_statement("a)("), "unbalanced brackets")
        self.assertEqual(check_statement("  "), "empty statement")
        self.assertIsNotNone(check_statement("isa(josé_1, person)"))

    def test_rules_file(self):
        rules = load_rules(RULES)
        self.assertEqual(rules[0], "subclass(person, human)")
        self.assertTrue(all(check_statement(r) is None and not r.endswith(".") for r in rules))

    def test_rules_file_with_byte_order_mark_and_bad_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.snepslog"
            path.write_text("subclass(person, human).\n", encoding="utf-8-sig")
            self.assertEqual(load_rules(path), ["subclass(person, human)"])
            path.write_text("subclass(person, human).\nisa(a, b\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 2"):
                load_rules(path)

    def test_answers_from_either_build_in_natural_order(self):
        lines = ["  WFF15!:  DANGEROUS(PERSON_10)    ", "dangerous(person_2)", "dangerous(person_10)",
                 "WFF9!:  all(Y,X)({INFRONTOF(X,Y)} &=> {DANGEROUS(X)})", "CPU time : 0.01"]
        self.assertEqual(parse_answers(lines), ["person_2", "person_10"])

    def test_driver_markers(self):
        lines = ["CPU time : 0.00", "<<LISP ERROR: Bad punctuation", 'in termSequence at: ".">>', "<<TIMEOUT>>",
                 "terror_bird is not an error"]
        self.assertEqual(_driver_markers(lines),
                         ['<<LISP ERROR: Bad punctuation in termSequence at: ".">>', "<<TIMEOUT>>"])

    def test_transcript_and_lisp_string(self):
        self.assertEqual(transcript(["a(b)"], "q(?x)"), ["clearkb", "a(b).", "ask(q(?x))."])
        self.assertEqual(lisp_string('C:\\x "y"'), '"C:\\\\x \\"y\\""')


class SnepspacySessionTest(unittest.TestCase):
    """SnepspacyBackend's session handling, against a stand-in for SNePSpaCy's sneps_api."""

    def backend(self):
        from types import SimpleNamespace
        from yolo_sneps.backends import SnepspacyBackend

        class ApiError(Exception): pass
        class SyntaxErr(ApiError): pass
        class ProcessErr(ApiError): pass

        calls = []

        class FakeApi:
            process = SimpleNamespace(timeout=None)
            def init(self): calls.append("init")
            def clear_kb(self): calls.append("clear_kb")
            def terminate(self): calls.append("terminate")
            def inform(self, s):
                if s == "slow(x)":
                    raise ProcessErr("Timeout during inform")
                if s == "bad(x)!":
                    raise SyntaxErr("Incorrect Syntax")
            def ask(self, q): return ["dangerous(person_1)"]

        backend = object.__new__(SnepspacyBackend)  # skip loading a real SNePSpaCy checkout
        backend.module = SimpleNamespace(SnepsApiError=ApiError, SnepsSyntaxError=SyntaxErr)
        backend.api, backend.timeout, backend.started = FakeApi(), 30, False
        return backend, calls

    def test_rejected_statement_keeps_the_session(self):
        backend, calls = self.backend()
        self.assertEqual(backend.run(["bad(x)!", "a(b)"], "q")[0], ["dangerous(person_1)"])
        backend.run(["a(b)"], "q")
        self.assertEqual(calls, ["init", "clear_kb"])

    def test_timeout_restarts_the_session_for_the_next_image(self):
        backend, calls = self.backend()
        lines, errors = backend.run(["slow(x)", "a(b)"], "q")
        self.assertEqual((lines, len(errors)), ([], 1))
        self.assertEqual(backend.run(["a(b)"], "q"), (["dangerous(person_1)"], []))
        self.assertEqual(calls, ["init", "terminate", "init"])


@unittest.skipUnless(os.environ.get("SNEPS_DIR"), "set SNEPS_DIR to run against the Windows SNePS build")
class AllegroEndToEndTest(unittest.TestCase):
    def run_scene(self, extra=()):
        from yolo_sneps.backends import AllegroBatchBackend
        dets = build_detections(RUNNER_SCENE)
        statements = load_rules(RULES) + list(extra) + scene_statements(dets, relations(dets, 280))
        with AllegroBatchBackend(os.environ["SNEPS_DIR"], timeout=120) as backend:
            lines, errors = backend.run(statements, "dangerous(?x)")
        return parse_answers(lines), errors

    def test_runner_in_front_of_car_is_dangerous(self):
        self.assertEqual(self.run_scene(), (["person_1"], []))

    def test_rejected_statement_is_reported_and_the_rest_still_runs(self):
        answers, errors = self.run_scene(extra=["foo(x)!", "isa(person_9"])
        self.assertEqual(answers, ["person_1"])
        self.assertEqual(len(errors), 2)
        self.assertIn(("isa(person_9", "unbalanced brackets"), errors)


@unittest.skipUnless(os.environ.get("SNEPSPACY_DIR") and sys.platform != "win32",
                     "set SNEPSPACY_DIR on Linux/WSL to run against SNePSpaCy's SNePS build")
class SnepspacyEndToEndTest(unittest.TestCase):
    def test_scenes_in_one_session(self):
        from yolo_sneps.backends import SnepspacyBackend
        rules = load_rules(RULES)
        behind_only = [("car", (10, 50, 370, 245), 0.9), ("person", (200, 20, 240, 120), 0.6)]
        with SnepspacyBackend(os.environ["SNEPSPACY_DIR"], timeout=120) as backend:
            results = []
            for raw, extra in [(RUNNER_SCENE, []), (behind_only, []), (RUNNER_SCENE, ["foo(x)!"])]:
                dets = build_detections(raw)
                lines, errors = backend.run(rules + extra + scene_statements(dets, relations(dets, 280)),
                                            "dangerous(?x)")
                results.append((parse_answers(lines), len(errors)))
        self.assertEqual(results, [(["person_1"], 0), ([], 0), (["person_1"], 1)])


if __name__ == "__main__":
    unittest.main()
