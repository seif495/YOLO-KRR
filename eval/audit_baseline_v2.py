"""Audit an instrumented evaluation run and the error attribution made from it.

    python eval/audit_baseline_v2.py [--results JSONL] [--summary JSON] [--attribution JSON]

Defaults to the baseline run: eval/results/baseline_instrumented_detailed.jsonl and
baseline_instrumented.json, and eval/results/baseline_error_attribution.json written by
analyze_errors.py. Exits 1 if any check fails.

  1 reconciliation   the run summary, the per-image records and the attribution report the same
                     TP/FP/FN, in total and image by image
  2 matcher          the recorded person matches and the scorer's matches of the flagged people are
                     one to one, at IoU >= 0.5, and stable: no annotated person and detection overlap
                     each other more than they overlap their own partners, which is what greedy IoU
                     matching guarantees. A person need not get the detection that overlaps them most:
                     one to one, that detection rightly goes to another person it overlaps even more.
  3 detections       flagged people = TP + FP
  4 false negatives  annotated dangerous people = TP + FN
  5 evidence         every root cause is a taxonomy code, and the facts it rests on are in the records
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from analyze_errors import ERROR_CATEGORIES, MATCH_IOU, Scene  # noqa: E402
from yolo_sneps.scene import iou  # noqa: E402

RESULTS = ROOT / "eval" / "results"


def blocking_pairs(truth, detected, assignment, threshold=MATCH_IOU):
    """(truth index, detection index, IoU) pairs that would both rather be matched to each other.

    `assignment` maps truth indices to detection indices. A matching with no blocking pair is
    stable; greedy matching by descending IoU always is.
    """
    partner_t = {t: iou(truth[t], detected[d]) for t, d in assignment.items()}
    partner_d = {d: iou(truth[t], detected[d]) for t, d in assignment.items()}
    return [(t, d, round(score, 3)) for t, box_t in enumerate(truth) for d, box_d in enumerate(detected)
            if (score := iou(box_t, box_d)) >= threshold
            and score > partner_t.get(t, 0.0) and score > partner_d.get(d, 0.0)]


def matching_problems(image, truth, detected, assignment, what, threshold=MATCH_IOU):
    """What is wrong with one matching of annotated boxes to detected boxes."""
    problems = []
    if len(set(assignment.values())) != len(assignment):
        problems.append(f"{image}: {what} uses a detection twice")
    for t, d in assignment.items():
        if iou(truth[t], detected[d]) < threshold:
            problems.append(f"{image}: {what} matches person {t} below IoU {threshold}")
    problems += [f"{image}: {what} is unstable: person {t} and detection {d} overlap at IoU {s}, more than "
                 f"either overlaps its partner" for t, d, s in blocking_pairs(truth, detected, assignment, threshold)]
    return problems


def check_reconciliation(records, summary, attribution):
    reported = list(summary["danger_tp_fp_fn"])
    recorded = [sum(r["evaluation"]["dangerous"][k] for r in records) for k in ("tp", "fp", "fn")]
    counts = attribution["summary"]["counts"]
    errors = attribution["errors"]
    problems = []
    if recorded != reported:
        problems.append(f"per-image records add up to TP/FP/FN {recorded}, run summary says {reported}")
    if [counts["TP"], counts["FP"], counts["FN"]] != reported:
        problems.append(f"attribution reports TP/FP/FN {counts}, run summary says {reported}")
    attributed = Counter((e["image"], e["type"]) for e in errors)
    if [sum(e["type"] == k for e in errors) for k in ("FP", "FN")] != reported[1:]:
        problems.append(f"attribution lists {sum(attributed.values())} errors, run summary has "
                        f"FP {reported[1]} + FN {reported[2]}")
    for r in records:
        for kind in ("FP", "FN"):
            if attributed[r["image"], kind] != r["evaluation"]["dangerous"][kind.lower()]:
                problems.append(f"{r['image']}: {attributed[r['image'], kind]} {kind} attributed, "
                                f"{r['evaluation']['dangerous'][kind.lower()]} recorded")
    return problems, f"TP/FP/FN {reported} in summary, records and attribution"


def check_matcher(records):
    problems = []
    for r in records:
        truth = [p["box"] for p in r["ground_truth"]["persons"]]
        people = [d for d in r["detections"] if d["class"] == "person"]
        index = {d["label"]: i for i, d in enumerate(people)}
        recorded = {m["person_idx"]: index[m["matched_detection_label"]] for m in r["matched_persons"] if m["detected"]}
        problems += matching_problems(r["image"], truth, [d["box"] for d in people], recorded, "matched_persons")
        for m in r["matched_persons"]:
            if m["detected"] and abs(m["match_iou"] - iou(truth[m["person_idx"]], m["matched_detection_box"])) > 1e-6:
                problems.append(f"{r['image']}: recorded match_iou of person {m['person_idx']} is wrong")
        flagged = [d for d in people if d["label"] in r["predictions"]["dangerous"]]
        position = {d["label"]: i for i, d in enumerate(flagged)}
        scored = {j: position[label] for label, j in Scene(r, set()).scored.items()}
        problems += matching_problems(r["image"], truth, [d["box"] for d in flagged], scored, "scorer's matching")
    return problems, f"{len(records)} images: matchings one to one, above IoU {MATCH_IOU} and stable"


def check_detections(records, summary):
    tp, fp, _ = summary["danger_tp_fp_fn"]
    flagged = sum(d["class"] == "person" and d["label"] in r["predictions"]["dangerous"]
                  for r in records for d in r["detections"])
    problems = [] if flagged == tp + fp else [f"{flagged} flagged people, TP + FP = {tp + fp}"]
    return problems, f"{flagged} flagged people = TP + FP"


def check_false_negatives(records, summary):
    tp, _, fn = summary["danger_tp_fp_fn"]
    dangerous = sum(p["dangerous"] for r in records for p in r["ground_truth"]["persons"])
    problems = [] if dangerous == tp + fn else [f"{dangerous} annotated dangerous people, TP + FN = {tp + fn}"]
    return problems, f"{dangerous} annotated dangerous people = TP + FN"


def check_evidence(records, attribution):
    """Every root cause is a taxonomy code and the facts it rests on are in the records."""
    by_image = {r["image"]: r for r in records}
    hazards = set(attribution["hazard_classes"])
    problems = []
    for e in attribution["errors"]:
        where = f"{e['image']}/{e['person_label'] or 'person ' + str(e['person_idx'])}"
        unknown = [c for c in [e["root_cause"], *e["contributing_factors"]] if c not in ERROR_CATEGORIES]
        if unknown:
            problems.append(f"{where}: codes not in the taxonomy: {unknown}")
            continue
        r = by_image[e["image"]]
        facts = {tuple(f) for f in r["facts"]}
        classes = {d["label"]: d["class"] for d in r["detections"]}
        label, root, evidence = e["person_label"], e["root_cause"], e["evidence"]
        if e["type"] == "FP":
            if (root == "unmatched_detection") != (e["person_idx"] is None):
                problems.append(f"{where}: unmatched_detection must be exactly the FPs with no person_idx")
            cited = [t for t in evidence["triggers"] if t["verdict"] == root]
            if root in ("4b_rule_broad", "2a_depth_order", "6b_uncertain") and not any(
                    ("infrontof", label, t["detection"]) in facts and classes[t["detection"]] in hazards for t in cited):
                problems.append(f"{where}: {root} without an infrontof fact on a hazard behind it")
        elif root == "1a_missing_person":
            if any(m["person_idx"] == e["person_idx"] and m["detected"] for m in r["matched_persons"]):
                problems.append(f"{where}: 1a_missing_person, but the person was detected")
        else:
            for c in evidence.get("candidates", []):
                y = c["detection"]
                if y is None or c["verdict"] != root:
                    continue
                said = {p for p, a, b in facts if {a, b} == {label, y}}
                if (root == "4c_rule_narrow" and said & {"overlaps", "infrontof"}
                        or root == "4d_chained" and ("infrontof", label, y) not in facts
                        or root == "2a_depth_order" and "overlaps" not in said):
                    problems.append(f"{where}: {root} does not fit the facts between {label} and {y}: {sorted(said)}")
    review = sum(e["requires_manual_review"] for e in attribution["errors"])
    return problems, f"{len(attribution['errors'])} root causes backed by the records ({review} need manual review)"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", default=RESULTS / "baseline_instrumented_detailed.jsonl", type=Path)
    parser.add_argument("--summary", default=RESULTS / "baseline_instrumented.json", type=Path)
    parser.add_argument("--attribution", default=RESULTS / "baseline_error_attribution.json", type=Path)
    args = parser.parse_args()

    records = [json.loads(line) for line in args.results.read_text(encoding="utf-8").splitlines() if line.strip()]
    summary = json.loads(args.summary.read_text(encoding="utf-8"))["summary"]
    attribution = json.loads(args.attribution.read_text(encoding="utf-8"))
    if "counts" not in attribution.get("summary", {}):
        sys.exit(f"{args.attribution} was not written by the current eval/analyze_errors.py; re-run it")
    checks = [("Reconciliation", check_reconciliation(records, summary, attribution)),
              ("Matcher integrity", check_matcher(records)),
              ("Detection accounting", check_detections(records, summary)),
              ("False negative accounting", check_false_negatives(records, summary)),
              ("Attribution evidence", check_evidence(records, attribution))]
    failed = 0
    for number, (name, (problems, passed)) in enumerate(checks, 1):
        print(f"[{number}] {name}: {'FAIL' if problems else 'PASS'} - {passed if not problems else ''}")
        for problem in problems:
            print(f"      {problem}")
        failed += bool(problems)
    print(f"\n{'FAILED' if failed else 'PASSED'}: {len(checks) - failed} of {len(checks)} checks pass")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
