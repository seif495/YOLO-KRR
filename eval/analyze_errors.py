"""Attribute every error of an instrumented evaluation run to a root cause (eval/ERROR_TAXONOMY.md).

    python eval/analyze_errors.py eval/results/<name>_detailed.jsonl [--output FILE]
                                  [--summary FILE] [--rules FILE] [--annotations FILE] [--details N]

Reads the per-image records written by evaluate_instrumented.py and attributes each error of the
dangerous(x) answer:
  FP  a flagged person detection matched to a person annotated safe, or matched to nobody
  FN  a person annotated dangerous whom no flagged detection matches
A person whose label is null (ambiguous) is never an error, as in evaluate.score.
Errors are found with the evaluator's own matching (evaluate.match on the flagged people, as
evaluate.score does) against the ground truth stored in the records, so they are exactly the
TP/FP/FN the evaluator counted. The counts are reconciled per image with the records and in total
with the run's summary (<name>.json by default); any difference stops the analysis.
--annotations only checks that the records were scored against that file.

Each annotated hazard is linked to the detection whose box overlaps it best (IoU >= 0.5, one to
one), whatever class YOLO gave it: YOLO calls some annotated trucks buses and some vans trucks.
Only infrontof facts whose object is of a hazard class (subclass(c, hazard) in the rules) count as
what made dangerous(x) hold, since the danger rule needs isa(y, hazard).

Root causes are ERROR_TAXONOMY.md's codes plus unmatched_detection: a flagged detection that
matches no annotated person (a second box on someone already matched, or a person the annotations
leave out). When several causes apply the earliest pipeline stage is the root cause and the others
are contributing factors. Errors the recorded evidence cannot settle are marked
requires_manual_review. The script cannot see detections below the confidence threshold, so it
reports those people as 1a rather than 3c.
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from evaluate import match  # noqa: E402
from yolo_sneps.scene import atom, iou  # noqa: E402
from yolo_sneps.snepslog import load_rules  # noqa: E402

# In pipeline order: of several causes, the one listed first is the root cause.
ERROR_CATEGORIES = {
    "1a_missing_person": "Missing Person Detection (CV)",
    "1b_missing_vehicle": "Missing Vehicle Detection (CV)",
    "1c_wrong_class": "Wrong Classification (CV)",
    "1d_poor_localization": "Poor Localization (CV)",
    "2a_depth_order": "Incorrect Depth Order (Geometric)",
    "2b_overlap": "Overlap Misdetection (Geometric)",
    "2c_spatial": "Spatial Relation Error (Geometric)",
    "3a_missing_fact": "Missing Fact (KR)",
    "3b_atom_form": "Wrong Atom Form (KR)",
    "3c_threshold": "Confidence Threshold (KR)",
    "4a_wrong_inference": "Correct Facts, Wrong Inference (Rule)",
    "4b_rule_broad": "Rule Too Broad (Rule)",
    "4c_rule_narrow": "Rule Too Narrow (Rule)",
    "4d_chained": "Chained Inference Failure (Rule)",
    "5a_conf_low": "Dangerous but Low Confidence (Policy)",
    "5b_conf_high": "Not Dangerous but Confident (Policy)",
    "6a_disagreement": "Annotator Disagreement (Ambiguous)",
    "6b_uncertain": "Inherently Uncertain (Ambiguous)",
    "unmatched_detection": "Flagged Detection Matching No Annotated Person",
    "unknown": "Could Not Classify",
}
STAGE = {code: i for i, code in enumerate(ERROR_CATEGORIES)}

CATEGORY_GROUPS = {
    "Perception (CV + Geometric)": ("1", "2"),
    "Knowledge Representation": ("3",),
    "Reasoning (Rules)": ("4",),
    "Policy": ("5",),
    "Ambiguity": ("6",),
    "Unmatched detection": ("unmatched",),
    "Unknown": ("unknown",),
}

MATCH_IOU = 0.5          # as evaluate.match
LOCALIZATION_IOU = 0.1   # a missed person with a box at least this close counts as poorly localised


class ReconciliationError(Exception):
    """The attributed errors do not add up to what the evaluator reported."""


def group(code):
    return next(name for name, prefixes in CATEGORY_GROUPS.items() if code.startswith(prefixes))


def hazard_classes(rules_path):
    """The classes c with subclass(c, hazard) in the rules."""
    pattern = re.compile(r"subclass\(\s*(\w+)\s*,\s*hazard\s*\)")
    return {m.group(1) for m in map(pattern.fullmatch, load_rules(rules_path)) if m}


def boxes_intersect(a, b):
    """The test relations.py uses before it asserts overlaps or infrontof."""
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def box_gap(a, b):
    """Pixels between two boxes (0 when they touch or overlap)."""
    dx, dy = max(0.0, b[0] - a[2], a[0] - b[2]), max(0.0, b[1] - a[3], a[1] - b[3])
    return (dx * dx + dy * dy) ** 0.5


def described(t):
    """'bus_1 (bus)', or 'bus_1 (bus, annotated truck)' when YOLO named the hazard differently."""
    other = t["annotated_class"] and t["annotated_class"] != t["detected_class"]
    return f"{t['detection']} ({t['detected_class']}{', annotated ' + t['annotated_class'] if other else ''})"


class Scene:
    """One evaluated image and the matchings the attribution needs."""

    def __init__(self, record, hazards):
        self.image = record["image"]
        self.truth = record["ground_truth"]
        self.detections = record["detections"]
        self.dets = {d["label"]: d for d in self.detections}
        self.facts = {tuple(f) for f in record["facts"]}
        self.flagged = set(record["predictions"]["dangerous"])
        self.alerted = set(record["predictions"]["alert"])
        self.hazards = hazards
        self.people = [d for d in self.detections if d["class"] == "person"]
        persons = [p["box"] for p in self.truth["persons"]]
        # what evaluate.score counts: the flagged people, matched one to one to the annotated people
        flagged = [d for d in self.people if d["label"] in self.flagged]
        self.scored = {flagged[i]["label"]: j for i, j in match([d["box"] for d in flagged], persons).items()}
        # whether YOLO found each annotated person at all: every person detection, matched the same way
        self.found = {j: self.people[i]["label"] for i, j in match([d["box"] for d in self.people], persons).items()}
        others = [d for d in self.detections if d["class"] != "person"]
        hazard_boxes = [h["box"] for h in self.truth["hazards"]]
        self.hazard_det = {j: others[i]["label"] for i, j in match([d["box"] for d in others], hazard_boxes).items()}
        self.det_hazard = {label: j for j, label in self.hazard_det.items()}

    def is_hazard(self, label):
        return atom(self.dets[label]["class"]) in self.hazards

    def triggers(self, label):
        """The hazards `label` is infrontof: the instances of the danger rule's premise."""
        return [d["label"] for d in self.detections
                if ("infrontof", label, d["label"]) in self.facts and self.is_hazard(d["label"])]

    def relation(self, a, b):
        """The depth cue between a and b: 'front' (a infrontof b), 'behind', 'level' or 'apart'.

        'level' means the boxes overlap but their bases are within the depth margin, so no
        infrontof fact was asserted; 'apart' means the boxes do not overlap at all.
        """
        if ("infrontof", a, b) in self.facts:
            return "front"
        if ("infrontof", b, a) in self.facts:
            return "behind"
        return "level" if ("overlaps", *sorted((a, b))) in self.facts else "apart"

    def facts_between(self, a, b):
        return sorted(list(f) for f in self.facts if {a, b} <= set(f[1:]))

    def pair(self, person, hazard):
        return next((p for p in self.truth["pairs"] if p["person"] == person and p["hazard"] == hazard), None)

    def hazard_evidence(self, hazard, label):
        """What is known about one annotated hazard (or None) and one detection (or None)."""
        h = self.truth["hazards"][hazard] if hazard is not None else None
        d = self.dets.get(label)
        return {"hazard_idx": hazard, "annotated_class": h and h["class"],
                "detection": label, "detected_class": d and d["class"],
                "hazard_iou": round(iou(h["box"], d["box"]), 3) if h and d else None}


def error(kind, scene, person_idx, label, root, contributing, review, explanation, evidence):
    contributing = sorted(set(contributing) - {root}, key=STAGE.get)
    return {"type": kind, "image": scene.image, "person_idx": person_idx, "person_label": label,
            "root_cause": root, "contributing_factors": contributing, "requires_manual_review": review,
            "explanation": explanation, "evidence": evidence}


def attribute_fp(scene, label):
    """Why `label` was flagged dangerous although it is no annotated dangerous person."""
    det = scene.dets[label]
    j = scene.scored.get(label)
    triggers = []
    for y in scene.triggers(label):
        h = scene.det_hazard.get(y)
        pair = scene.pair(j, h) if j is not None and h is not None else None
        verdict = ("unannotated_object" if h is None else "no_pair" if pair is None else
                   {"person": "4b_rule_broad", "hazard": "2a_depth_order"}.get(pair["nearer"], "6b_uncertain"))
        triggers.append({**scene.hazard_evidence(h, y), "nearer": pair and pair["nearer"], "verdict": verdict})
    evidence = {"confidence": det["confidence"], "alerted": label in scene.alerted, "triggers": triggers}
    policy = ["5b_conf_high"] if label in scene.alerted else []
    verdicts = [t["verdict"] for t in triggers]
    causes = [v for v in verdicts if v in ERROR_CATEGORIES]
    named = ", ".join(map(described, triggers))

    if j is None:
        best = max(((iou(det["box"], p["box"]), i) for i, p in enumerate(scene.truth["persons"])), default=(0.0, None))
        holder = next((other for other, i in scene.scored.items() if i == best[1]), None)
        evidence["closest_person"] = {"person_idx": best[1], "iou": round(best[0], 3), "matched_to": holder}
        if best[0] >= MATCH_IOU:
            why = f"a second box on annotated person {best[1]} (IoU {best[0]:.2f}), who is matched to {holder}"
        elif best[0] > 0:
            why = f"its closest annotated person ({best[1]}) overlaps it only at IoU {best[0]:.2f}"
        else:
            why = "it overlaps no annotated person: a spurious box or a person missing from the annotations"
        return error("FP", scene, None, label, "unmatched_detection", causes + policy, True,
                     f"{label} matches no annotated person: {why}; infrontof hazards: {named or 'none'}", evidence)

    evidence["match_iou"] = round(iou(det["box"], scene.truth["persons"][j]["box"]), 3)
    if not triggers:
        return error("FP", scene, j, label, "unknown", policy, True,
                     f"dangerous({label}) holds but {label} is infrontof no hazard; check the SNePS output", evidence)
    if "4b_rule_broad" in verdicts:
        y = triggers[verdicts.index("4b_rule_broad")]
        return error("FP", scene, j, label, "4b_rule_broad", causes + policy, False,
                     f"{label} is in front of {described(y)}, which the annotated pair confirms, yet annotated "
                     f"safe: the rule's premise is true here and its conclusion is not", evidence)
    if causes and len(causes) == len(verdicts):
        root = min(causes, key=STAGE.get)
        y = triggers[verdicts.index(root)]
        what = ("the annotation puts the hazard nearer" if root == "2a_depth_order"
                else "the annotation leaves the depth order unclear")
        return error("FP", scene, j, label, root, causes + policy, len(set(causes)) > 1,
                     f"infrontof({label}, {y['detection']}) fired the rule but {what}", evidence)
    return error("FP", scene, j, label, "unknown", causes + policy, True,
                 f"{label} is infrontof {named}, but no annotated pair confirms or refutes the depth order "
                 f"(verdicts: {', '.join(verdicts)})", evidence)


def fn_verdict(scene, person_idx, label, hazard, y, nearer):
    """Why one hazard (annotated index and/or detection) did not make `label` dangerous."""
    if y is None:
        return "1b_missing_vehicle"
    if not scene.is_hazard(y):
        return "1c_wrong_class"
    if nearer == "unclear":
        return "6b_uncertain"
    relation = scene.relation(label, y)
    if relation == "front":
        return "4d_chained"  # the premise was asserted, yet SNePS did not conclude dangerous
    if relation in ("behind", "level"):
        return "2a_depth_order"
    person_box = scene.truth["persons"][person_idx]["box"]
    if hazard is not None and boxes_intersect(person_box, scene.truth["hazards"][hazard]["box"]):
        return "1d_poor_localization"  # the true boxes overlap, the detected ones do not
    return "4c_rule_narrow"  # infrontof needs overlapping boxes, and these do not overlap even in truth


def attribute_fn(scene, j):
    """Why annotated dangerous person j was not flagged."""
    person = scene.truth["persons"][j]
    label = scene.found.get(j)
    overlaps_hazard = any(boxes_intersect(person["box"], h["box"]) for h in scene.truth["hazards"])
    evidence = {"detected": label is not None, "overlaps_annotated_hazard": overlaps_hazard}
    if label is None:
        taken = set(scene.found.values())
        best = max(((iou(person["box"], d["box"]), d["label"]) for d in scene.people if d["label"] not in taken),
                   default=(0.0, None))
        evidence["closest_unmatched_detection"] = {"label": best[1], "iou": round(best[0], 3)}
        if best[0] >= LOCALIZATION_IOU:
            return error("FN", scene, j, None, "1d_poor_localization", [], False,
                         f"YOLO's closest box, {best[1]}, overlaps the person only at IoU {best[0]:.2f}", evidence)
        return error("FN", scene, j, None, "1a_missing_person", [], False,
                     f"no detection overlaps the person at {person['box']}", evidence)

    evidence["confidence"] = scene.dets[label]["confidence"]
    if label in scene.flagged:
        return error("FN", scene, j, label, "unknown", [], True,
                     f"{label} is flagged, but the scorer matched it to annotated person {scene.scored.get(label)}",
                     evidence)

    pairs = [p for p in scene.truth["pairs"] if p["person"] == j]
    usable = [p for p in pairs if p["nearer"] != "hazard"]  # a hazard nearer than the person cannot make them dangerous
    evidence["gt_pairs_annotated"] = bool(pairs)
    if usable:
        candidates = [(p["hazard"], scene.hazard_det.get(p["hazard"]), p["nearer"]) for p in usable]
    else:  # no pair says what endangers them: judge every hazard YOLO found
        candidates = [(scene.det_hazard.get(d["label"]), d["label"], None)
                      for d in scene.detections if d["class"] != "person" and scene.is_hazard(d["label"])]
        if not candidates and scene.truth["hazards"]:
            candidates = [(i, None, None) for i in range(len(scene.truth["hazards"]))]
    if not candidates:
        return error("FN", scene, j, label, "unknown", [], True,
                     "annotated dangerous, but the image has no annotated or detected hazard", evidence)

    box = scene.dets[label]["box"]
    evidence["candidates"] = [
        {**scene.hazard_evidence(h, y), "nearer": nearer, "relation": y and scene.relation(label, y),
         "gap_px": round(box_gap(box, scene.dets[y]["box"]), 1) if y else None,
         "facts": scene.facts_between(label, y) if y else [], "verdict": fn_verdict(scene, j, label, h, y, nearer)}
        for h, y, nearer in candidates]
    verdicts = [c["verdict"] for c in evidence["candidates"]]
    # the earliest stage is the root cause; of hazards failing the same way, the nearest one explains it
    c = min(evidence["candidates"], key=lambda c: (STAGE[c["verdict"]], c["gap_px"] is None, c["gap_px"]))
    root = c["verdict"]
    review = not usable or len(set(verdicts)) > 1 or root == "4d_chained" or not overlaps_hazard
    what = {
        "1b_missing_vehicle": f"the annotated {c['annotated_class']} was not detected",
        "1c_wrong_class": f"the hazard was detected as {c['detected_class']}, which is no hazard class",
        "1d_poor_localization": f"the annotated boxes overlap {c['annotated_class']}, the detected ones do not",
        "2a_depth_order": f"{label} overlaps {c['detection']} but no infrontof({label}, {c['detection']}) was "
                          f"asserted (cue said: {c['relation']})",
        "4c_rule_narrow": f"{label} does not overlap {c['detection']} (facts: {c['facts'] or 'none'}); infrontof "
                          f"needs overlapping boxes, so the danger rule cannot fire",
        "4d_chained": f"infrontof({label}, {c['detection']}) was asserted, yet SNePS did not conclude dangerous",
        "6b_uncertain": f"the annotation leaves the depth order with {c['annotated_class']} unclear",
    }[root]
    if not pairs:
        what += "; no person-hazard pair is annotated for this person"
    if not overlaps_hazard:
        what += ("; no annotated hazard overlaps this person, which ANNOTATION_GUIDELINES.md v1.0 labels "
                 "not dangerous ('beside vehicle with no overlap')")
    return error("FN", scene, j, label, root, verdicts, review, what, evidence)


def image_errors(scene):
    """The FPs and FNs of one image, in detection and then annotation order."""
    errors = []
    for d in scene.people:
        j = scene.scored.get(d["label"])
        if d["label"] in scene.flagged and (j is None or scene.truth["persons"][j]["dangerous"] is False):
            errors.append(attribute_fp(scene, d["label"]))
    hit = set(scene.scored.values())
    errors += [attribute_fn(scene, j) for j, p in enumerate(scene.truth["persons"]) if p["dangerous"] is True and j not in hit]
    return errors


def analyze(records, hazards, summary=None):
    """All errors, reconciled with each record's evaluation and, when given, the run's summary.

    Raises ReconciliationError if the attributed errors are not exactly the evaluator's.
    """
    errors, totals = [], [0, 0, 0]
    for record in records:
        scene = Scene(record, hazards)
        found = image_errors(scene)
        tp = sum(scene.truth["persons"][j]["dangerous"] is True for j in scene.scored.values())
        counts = [tp, sum(e["type"] == "FP" for e in found), sum(e["type"] == "FN" for e in found)]
        reported = [record["evaluation"]["dangerous"][k] for k in ("tp", "fp", "fn")]
        if counts != reported:
            raise ReconciliationError(f"{scene.image}: attributed TP/FP/FN {counts}, evaluator recorded {reported}")
        totals = [a + b for a, b in zip(totals, counts)]
        errors += found
    if summary is not None and list(summary["danger_tp_fp_fn"]) != totals:
        raise ReconciliationError(f"attributed TP/FP/FN {totals}, run summary says {summary['danger_tp_fp_fn']}")
    return errors, totals


def check_annotations(records, path):
    """Raise ReconciliationError unless every record was scored against the annotations in `path`."""
    images = {i["file"]: i for i in json.loads(Path(path).read_text(encoding="utf-8"))["images"]}
    for r in records:
        current = images.get(r["image"])
        if current is None or any(current[k] != r["ground_truth"][k] for k in ("persons", "hazards", "pairs")):
            raise ReconciliationError(f"{r['image']}: the run was scored against different annotations than {path}; "
                                      f"re-run evaluate_instrumented.py to analyse against them")


def report(errors, counts):
    """{type: {root cause: n}}, root causes by stage, contributing factors and the manual-review count."""
    by_root = {kind: dict(Counter(e["root_cause"] for e in errors if e["type"] == kind).most_common())
               for kind in ("FP", "FN")}
    return {"counts": dict(zip(("TP", "FP", "FN"), counts)),
            "by_root_cause": by_root,
            "by_stage": dict(Counter(group(e["root_cause"]) for e in errors).most_common()),
            "contributing_factors": dict(Counter(c for e in errors for c in e["contributing_factors"]).most_common()),
            "requires_manual_review": sum(e["requires_manual_review"] for e in errors)}


def print_report(errors, summary, details):
    c = summary["counts"]
    print(f"\nErrors: {len(errors)} (FP {c['FP']}, FN {c['FN']}; TP {c['TP']}), reconciled with the evaluator")
    print(f"\n{'Root cause':<24}{'FP':>4}{'FN':>4}")
    for code in sorted({e["root_cause"] for e in errors}, key=STAGE.get):
        fp, fn = (summary["by_root_cause"][k].get(code, 0) for k in ("FP", "FN"))
        print(f"  {code:<22}{fp:>4}{fn:>4}   {ERROR_CATEGORIES[code]}")
    print("\nBy pipeline stage:")
    for name, n in summary["by_stage"].items():
        print(f"  {name}: {n} ({n / len(errors):.0%})")
    if summary["contributing_factors"]:
        print("Contributing factors: " + ", ".join(f"{k} x{n}" for k, n in summary["contributing_factors"].items()))
    print(f"Needing manual review: {summary['requires_manual_review']}")
    for i, e in enumerate(errors[:details], 1):
        who = e["person_label"] or "not detected"
        idx = "-" if e["person_idx"] is None else e["person_idx"]
        review = "  [review]" if e["requires_manual_review"] else ""
        print(f"\n{i}. {e['type']} {e['image']} person {idx} ({who}): {e['root_cause']}{review}")
        if e["contributing_factors"]:
            print(f"   contributing: {', '.join(e['contributing_factors'])}")
        print(f"   {e['explanation']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", help="per-image records, eval/results/<name>_detailed.jsonl")
    parser.add_argument("--summary", help="the run's summary (default: <name>.json next to the records)")
    parser.add_argument("--rules", help="rules the run used (default: from <name>_config.json, else kb/danger.snepslog)")
    parser.add_argument("--annotations", help="also check the records were scored against this annotations file")
    parser.add_argument("--details", type=int, default=10, help="number of errors to print in full")
    parser.add_argument("--output", help="write the attribution to this JSON file")
    args = parser.parse_args()

    results = Path(args.results)
    records = [json.loads(line) for line in results.read_text(encoding="utf-8").splitlines() if line.strip()]
    stem = results.name.removesuffix(".jsonl").removesuffix("_detailed")
    summary_path = Path(args.summary) if args.summary else results.with_name(f"{stem}.json")
    if not summary_path.exists():
        parser.error(f"no run summary at {summary_path}; pass --summary")
    run_summary = json.loads(summary_path.read_text(encoding="utf-8"))["summary"]
    rules = Path(args.rules) if args.rules else ROOT / "kb" / "danger.snepslog"
    config = results.with_name(f"{stem}_config.json")
    if not args.rules and config.exists():
        used = Path(json.loads(config.read_text(encoding="utf-8"))["rules_path"])
        rules = used if used.exists() else ROOT / "kb" / used.name
    hazards = hazard_classes(rules)
    rules_name = rules.resolve().relative_to(ROOT).as_posix() if rules.resolve().is_relative_to(ROOT) else str(rules)

    try:
        if args.annotations:
            check_annotations(records, args.annotations)
        errors, counts = analyze(records, hazards, run_summary)
    except ReconciliationError as e:
        sys.exit(f"Reconciliation failed: {e}")

    summary = report(errors, counts)
    print(f"{len(records)} images from {results.as_posix()}; hazard classes from {rules_name}")
    print_report(errors, summary, args.details)
    if args.output:
        Path(args.output).write_text(json.dumps({
            "results_file": results.as_posix(), "summary_file": summary_path.as_posix(), "rules_file": rules_name,
            "hazard_classes": sorted(hazards), "summary": summary, "errors": errors}, indent=1) + "\n",
            encoding="utf-8")
        print(f"\nAttribution written to {args.output}")


if __name__ == "__main__":
    main()
