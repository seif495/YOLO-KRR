"""Evaluate YOLO-KRR against the labelled test set in eval/annotations.json.

    python eval/evaluate.py [--model M] [--imgsz N] [--rules FILE] [--road] [--route typed|english]
                            [--backend allegro|snepspacy] [--name NAME]

Three measurements:
  detection  person recall on the coco128 images, whose person boxes come from COCO's own labels
  relation   accuracy of the infrontof cue on the annotated person-hazard pairs, applied to the
             ground-truth boxes so that detector errors do not count against the cue
  danger     the whole system (YOLO, facts, SNePS) against the annotated dangerous people:
             precision, recall and F1 of dangerous(x), and of alert(x) (dangerous and detected
             with confidence >= 0.5), matching flagged objects to people by IoU >= 0.5.
             hidden(x) has no ground truth; only how many people it flags is reported.
--road adds onroad/onsidewalk facts from a road segmentation model and uses kb/danger_road.snepslog.
--route english describes each scene in English and has SNePSpaCy translate it (needs
--snepspacy-dir and spaCy with en_core_web_trf); the typed route then also runs on the same
detections, so the two routes' answers can be compared image by image.
Writes eval/results/<name>.md and .json.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from yolo_sneps.backends import AllegroBatchBackend, SnepspacyBackend  # noqa: E402
from yolo_sneps.pipeline import describe  # noqa: E402
from yolo_sneps.relations import focus_pairs, relations  # noqa: E402
from yolo_sneps.scene import Detection, iou  # noqa: E402
from yolo_sneps.snepslog import load_rules, parse_answers  # noqa: E402

QUESTIONS = ("dangerous", "alert", "hidden")
QUERIES = [f"{q}(?x)" for q in QUESTIONS]


def image_path(item, coco_dir):
    return (ROOT / "examples" / item["file"]) if item["source"] == "examples" else coco_dir / "images/train2017" / item["file"]


def match(predicted, truth, threshold=0.5):
    """Greedy one-to-one matching by IoU: {predicted index: truth index}."""
    pairs = sorted(((iou(p, t), i, j) for i, p in enumerate(predicted) for j, t in enumerate(truth)), reverse=True)
    used_p, used_t, result = set(), set(), {}
    for score, i, j in pairs:
        if score >= threshold and i not in used_p and j not in used_t:
            result[i] = j
            used_p.add(i)
            used_t.add(j)
    return result


def cue(person_box, hazard_box, height):
    """What the infrontof cue says about a person and a hazard: 'person', 'hazard' or 'none'."""
    p, h = Detection("p", "person", tuple(person_box), 1.0), Detection("h", "hazard", tuple(hazard_box), 1.0)
    facts = set(relations([p, h], height))
    if ("infrontof", "p", "h") in facts:
        return "person"
    if ("infrontof", "h", "p") in facts:
        return "hazard"
    return "none"


def score(flagged, people, persons):
    """(tp, fp, fn) of the flagged labels against the annotated dangerous people."""
    flagged_people = [d for d in people if d.label in flagged]
    hits = match([d.box for d in flagged_people], [p["box"] for p in persons])
    tp = sum(persons[j]["dangerous"] for j in hits.values())
    return tp, len(flagged_people) - tp, sum(p["dangerous"] for p in persons) - tp


def prf(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return round(precision, 3), round(recall, 3), round(f1, 3)


def ratio(a, b):
    return f"{a}/{b} = {a / b:.0%}" if b else f"{a}/0"


def ask(session, statements):
    """{question: set of answers} and the errors, with the seconds SNePS took."""
    start = time.perf_counter()
    lines, errors = session.run(statements, QUERIES)
    return {q: set(parse_answers(lines, q)) for q in QUESTIONS}, errors, time.perf_counter() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default=str(ROOT / "yolo11n-seg.pt"))
    parser.add_argument("--imgsz", type=int, default=640)
    parser.add_argument("--conf", type=float, default=0.25)
    parser.add_argument("--rules", help="default: kb/danger.snepslog, danger_road.snepslog with --road, "
                                        "danger_english.snepslog with --route english")
    parser.add_argument("--road", action="store_true", help="assert onroad/onsidewalk from road segmentation")
    parser.add_argument("--route", choices=["typed", "english"], default="typed")
    parser.add_argument("--backend", choices=["allegro", "snepspacy"],
                        default="snepspacy" if os.environ.get("SNEPSPACY_DIR") else "allegro")
    parser.add_argument("--sneps-dir", default=os.environ.get("SNEPS_DIR"))
    parser.add_argument("--snepspacy-dir", default=os.environ.get("SNEPSPACY_DIR"))
    parser.add_argument("--coco-dir", help="coco128 folder (default: Ultralytics' datasets_dir/coco128)")
    parser.add_argument("--name", help="name of the result files (default: <model>-<imgsz>)")
    args = parser.parse_args()
    if args.road and args.route == "english":
        parser.error("--road is not available on the English route")

    from ultralytics import YOLO
    from ultralytics.utils import SETTINGS
    from PIL import Image

    coco_dir = Path(args.coco_dir) if args.coco_dir else Path(SETTINGS["datasets_dir"]) / "coco128"
    annotations = json.load(open(ROOT / "eval" / "annotations.json", encoding="utf-8"))["images"]
    model = YOLO(args.model)
    rules_path = Path(args.rules) if args.rules else ROOT / "kb" / (
        "danger_english.snepslog" if args.route == "english" else
        "danger_road.snepslog" if args.road else "danger.snepslog")
    rules = load_rules(rules_path)
    road_model = translator = None
    if args.road:
        from yolo_sneps.road import RoadModel
        road_model = RoadModel()
    if args.route == "english":
        from yolo_sneps.english import Translator, sentences
        translator = Translator(args.snepspacy_dir)
        typed_rules = load_rules(ROOT / "kb" / "danger.snepslog")
    backend = (SnepspacyBackend(args.snepspacy_dir) if args.backend == "snepspacy"
               else AllegroBatchBackend(args.sneps_dir))
    name = args.name or f"{Path(args.model).stem}-{args.imgsz}"

    totals = {"gt_persons": 0, "found": 0, "pairs": 0, "pairs_correct": 0, "pairs_none": 0,
              "dangerous": [0, 0, 0], "alert": [0, 0, 0], "hidden": 0, "errors": 0, "agree": 0,
              "warnings": 0, "yolo_seconds": 0.0, "sneps_seconds": 0.0, "translate_seconds": 0.0}
    rows = []
    with backend as session:
        for item in annotations:
            path = image_path(item, coco_dir)
            height = Image.open(path).size[1]
            truth = [p["box"] for p in item["persons"]]

            # relation: the cue on the ground-truth boxes
            for pair in item["pairs"]:
                if pair["nearer"] == "unclear":
                    continue
                said = cue(item["persons"][pair["person"]]["box"], item["hazards"][pair["hazard"]]["box"], height)
                totals["pairs"] += 1
                totals["pairs_correct"] += said == pair["nearer"]
                totals["pairs_none"] += said == "none"

            # the whole system
            start = time.perf_counter()
            result = model(str(path), conf=args.conf, imgsz=args.imgsz, verbose=False)[0]
            totals["yolo_seconds"] += time.perf_counter() - start
            detections, facts, scene = describe(result, conf=args.conf, pair_filter=focus_pairs({"person"}),
                                                road_model=road_model)
            row = {"image": item["file"]}
            if translator:
                start = time.perf_counter()
                translated, warnings = translator.statements(sentences(detections, facts))
                totals["translate_seconds"] += time.perf_counter() - start
                totals["warnings"] += len(warnings)
                answers, errors, seconds = ask(session, rules + translated)
                typed, typed_errors, _ = ask(session, typed_rules + scene)
                row["agrees_with_typed"] = answers == typed and not typed_errors
                totals["agree"] += row["agrees_with_typed"]
            else:
                answers, errors, seconds = ask(session, rules + scene)
            totals["sneps_seconds"] += seconds
            totals["errors"] += bool(errors)

            people = [d for d in detections if d.cls == "person"]
            if item["source"] == "coco128":
                totals["gt_persons"] += len(truth)
                totals["found"] += len(match([d.box for d in people], truth))
            counts = {q: score(answers[q], people, item["persons"]) for q in ("dangerous", "alert")}
            for q, c in counts.items():
                totals[q] = [a + b for a, b in zip(totals[q], c)]
            totals["hidden"] += len(answers["hidden"])
            row.update({"persons": len(truth), "detected": len(match([d.box for d in people], truth)),
                        "dangerous": sum(p["dangerous"] for p in item["persons"]),
                        "flagged": sorted(answers["dangerous"]), "alert": sorted(answers["alert"]),
                        "hidden": sorted(answers["hidden"]), "tp_fp_fn": list(counts["dangerous"]),
                        "alert_tp_fp_fn": list(counts["alert"]), "errors": len(errors)})
            rows.append(row)
            print(f"{item['file']}: flagged {row['flagged'] or '-'} alert {row['alert'] or '-'} "
                  f"hidden {row['hidden'] or '-'} tp/fp/fn={row['tp_fp_fn']}")

    t, n = totals, len(annotations)
    summary = {
        "model": Path(args.model).name, "imgsz": args.imgsz, "conf": args.conf,
        "rules": rules_path.name,
        "route": args.route, "road": args.road, "backend": args.backend, "images": n,
        "person_recall_coco128": ratio(t["found"], t["gt_persons"]),
        "infrontof_accuracy": ratio(t["pairs_correct"], t["pairs"]),
        "infrontof_no_answer": ratio(t["pairs_none"], t["pairs"]),
        "danger_tp_fp_fn": t["dangerous"],
        **dict(zip(("danger_precision", "danger_recall", "danger_f1"), prf(*t["dangerous"]))),
        "alert_tp_fp_fn": t["alert"],
        **dict(zip(("alert_precision", "alert_recall", "alert_f1"), prf(*t["alert"]))),
        "hidden_flagged": t["hidden"],
        "images_with_sneps_errors": t["errors"],
        "yolo_seconds_per_image": round(t["yolo_seconds"] / n, 3),
        "sneps_seconds_per_image": round(t["sneps_seconds"] / n, 3),
    }
    if translator:
        summary.update({"translate_seconds_per_image": round(t["translate_seconds"] / n, 3),
                        "translation_warnings": t["warnings"],
                        "same_answers_as_typed_route": ratio(t["agree"], n)})
    out = ROOT / "eval" / "results"
    out.mkdir(exist_ok=True)
    json.dump({"summary": summary, "images": rows}, open(out / f"{name}.json", "w", encoding="utf-8"), indent=1)
    md = [f"# Evaluation: {name}", "", "| Measure | Value |", "|---|---|"]
    md += [f"| {k} | {v} |" for k, v in summary.items()]
    md += ["", "| Image | People | Detected | Dangerous | Flagged | Alert | Hidden | TP | FP | FN |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    md += [f"| {r['image']} | {r['persons']} | {r['detected']} | {r['dangerous']} | {', '.join(r['flagged']) or '-'} | "
           f"{', '.join(r['alert']) or '-'} | {', '.join(r['hidden']) or '-'} | "
           + " | ".join(map(str, r["tp_fp_fn"])) + " |" for r in rows]
    (out / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
