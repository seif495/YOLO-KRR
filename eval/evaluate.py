"""Evaluate YOLO-KRR against the labelled test set in eval/annotations.json.

    python eval/evaluate.py [--model M] [--imgsz N] [--rules FILE] [--backend allegro|snepspacy] [--name NAME]

Three measurements:
  detection  person recall on the coco128 images, whose person boxes come from COCO's own labels
  relation   accuracy of the infrontof cue on the annotated person-hazard pairs, applied to the
             ground-truth boxes so that detector errors do not count against the cue
  danger     the whole system (YOLO, facts, SNePS) against the annotated dangerous people:
             precision, recall and F1, matching flagged objects to people by IoU >= 0.5
Writes eval/results/<name>.md and .json.
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from yolo_sneps.backends import AllegroBatchBackend, SnepspacyBackend  # noqa: E402
from yolo_sneps.pipeline import describe  # noqa: E402
from yolo_sneps.relations import focus_pairs, relations  # noqa: E402
from yolo_sneps.scene import Detection, iou  # noqa: E402
from yolo_sneps.snepslog import load_rules, parse_answers  # noqa: E402

QUERY = "dangerous(?x)"


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


def ratio(a, b):
    return f"{a}/{b} = {a / b:.0%}" if b else f"{a}/0"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default=str(ROOT / "yolo11n-seg.pt"))
    parser.add_argument("--imgsz", type=int, default=640)
    parser.add_argument("--conf", type=float, default=0.25)
    parser.add_argument("--rules", default=str(ROOT / "kb" / "danger.snepslog"))
    parser.add_argument("--backend", choices=["allegro", "snepspacy"],
                        default="snepspacy" if os.environ.get("SNEPSPACY_DIR") else "allegro")
    parser.add_argument("--sneps-dir", default=os.environ.get("SNEPS_DIR"))
    parser.add_argument("--snepspacy-dir", default=os.environ.get("SNEPSPACY_DIR"))
    parser.add_argument("--coco-dir", help="coco128 folder (default: Ultralytics' datasets_dir/coco128)")
    parser.add_argument("--name", help="name of the result files (default: <model>-<imgsz>)")
    args = parser.parse_args()

    from ultralytics import YOLO
    from ultralytics.utils import SETTINGS
    from PIL import Image

    coco_dir = Path(args.coco_dir) if args.coco_dir else Path(SETTINGS["datasets_dir"]) / "coco128"
    annotations = json.load(open(ROOT / "eval" / "annotations.json", encoding="utf-8"))["images"]
    model = YOLO(args.model)
    rules = load_rules(args.rules)
    backend = (SnepspacyBackend(args.snepspacy_dir) if args.backend == "snepspacy"
               else AllegroBatchBackend(args.sneps_dir))
    name = args.name or f"{Path(args.model).stem}-{args.imgsz}"

    totals = {"gt_persons": 0, "found": 0, "pairs": 0, "pairs_correct": 0, "pairs_none": 0,
              "tp": 0, "fp": 0, "fn": 0, "errors": 0}
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
            result = model(str(path), conf=args.conf, imgsz=args.imgsz, verbose=False)[0]
            detections, scene = describe(result, conf=args.conf, pair_filter=focus_pairs({"person"}))
            lines, errors = session.run(rules + scene, QUERY)
            totals["errors"] += bool(errors)
            flagged = set(parse_answers(lines))
            people = [d for d in detections if d.cls == "person"]
            found = match([d.box for d in people], truth)
            if item["source"] == "coco128":
                totals["gt_persons"] += len(truth)
                totals["found"] += len(found)

            flagged_people = [d for d in people if d.label in flagged]
            hits = match([d.box for d in flagged_people], truth)
            tp = sum(item["persons"][j]["dangerous"] for j in hits.values())
            fp = len(flagged_people) - tp
            fn = sum(p["dangerous"] for p in item["persons"]) - tp
            totals["tp"] += tp
            totals["fp"] += fp
            totals["fn"] += fn
            rows.append({"image": item["file"], "persons": len(truth), "detected": len(found),
                         "dangerous": sum(p["dangerous"] for p in item["persons"]),
                         "flagged": sorted(flagged), "tp": tp, "fp": fp, "fn": fn, "errors": len(errors)})
            print(f"{item['file']}: flagged {sorted(flagged) or '-'}  tp={tp} fp={fp} fn={fn}")

    t = totals
    precision = t["tp"] / (t["tp"] + t["fp"]) if t["tp"] + t["fp"] else 0.0
    recall = t["tp"] / (t["tp"] + t["fn"]) if t["tp"] + t["fn"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    summary = {
        "model": Path(args.model).name, "imgsz": args.imgsz, "conf": args.conf, "rules": Path(args.rules).name,
        "backend": args.backend, "images": len(annotations),
        "person_recall_coco128": ratio(t["found"], t["gt_persons"]),
        "infrontof_accuracy": ratio(t["pairs_correct"], t["pairs"]),
        "infrontof_no_answer": ratio(t["pairs_none"], t["pairs"]),
        "danger_tp_fp_fn": [t["tp"], t["fp"], t["fn"]],
        "danger_precision": round(precision, 3), "danger_recall": round(recall, 3), "danger_f1": round(f1, 3),
        "images_with_sneps_errors": t["errors"],
    }
    out = ROOT / "eval" / "results"
    out.mkdir(exist_ok=True)
    json.dump({"summary": summary, "images": rows}, open(out / f"{name}.json", "w", encoding="utf-8"), indent=1)
    md = [f"# Evaluation: {name}", "", "| Measure | Value |", "|---|---|"]
    md += [f"| {k} | {v} |" for k, v in summary.items()]
    md += ["", "| Image | People | Detected | Dangerous | Flagged | TP | FP | FN |", "|---|---|---|---|---|---|---|---|"]
    md += [f"| {r['image']} | {r['persons']} | {r['detected']} | {r['dangerous']} | {', '.join(r['flagged']) or '-'} | "
           f"{r['tp']} | {r['fp']} | {r['fn']} |" for r in rows]
    (out / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
