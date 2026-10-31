"""Instrumented version of evaluate.py that captures detailed intermediate outputs.

It shares evaluate.py's matching and scoring (null labels are ignored, see evaluate.score) and adds:
1. a detailed per-image JSONL with detections, facts, statements and SNePS output
2. explicit matching of ground truth to detections, for error attribution
3. hidden(x) scored against hidden labels where the annotations have them
4. image-level recall of dangerous(x), and danger metrics per sampling stratum (Phase 4 sets)

Usage: python eval/evaluate_instrumented.py [same args as evaluate.py]

Outputs:
  - eval/results/<name>.json (same format as original, for regression testing)
  - eval/results/<name>.md (same format as original)
  - eval/results/<name>_detailed.jsonl (NEW: per-image detailed output)
  - eval/results/<name>_config.json (NEW: full configuration for reproducibility)
"""
import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from evaluate import QUERIES, QUESTIONS, cue, image_path, match, prf, ratio, score  # noqa: E402
from yolo_sneps.backends import AllegroBatchBackend, SnepspacyBackend  # noqa: E402
from yolo_sneps.pipeline import describe  # noqa: E402
from yolo_sneps.relations import focus_pairs  # noqa: E402
from yolo_sneps.scene import iou  # noqa: E402
from yolo_sneps.snepslog import load_rules, parse_answers  # noqa: E402

STRATA_KEY = ("coco_split", "stratum")


def stratum_of(item):
    """The image's sampling stratum (Phase 4 sets), or its source (baseline)."""
    return " ".join(item[k] for k in STRATA_KEY) if "stratum" in item else item["source"]


def ask(session, statements):
    """{question: set of answers} and the errors, with the seconds SNePS took."""
    start = time.perf_counter()
    lines, errors = session.run(statements, QUERIES)
    return {q: set(parse_answers(lines, q)) for q in QUESTIONS}, errors, time.perf_counter() - start, lines


def match_ground_truth_to_detections(ground_truth_persons, detections, threshold=0.5):
    """Match each ground truth person to a detection, return detailed mapping."""
    people_detections = [d for d in detections if d.cls == "person"]
    matches = match([d.box for d in people_detections], [p["box"] for p in ground_truth_persons], threshold)
    
    # Build detailed match records
    matched_persons = []
    for person_idx, person in enumerate(ground_truth_persons):
        matched_det_idx = None
        matched_detection = None
        
        # Find if this person was matched
        for det_idx, gt_idx in matches.items():
            if gt_idx == person_idx:
                matched_det_idx = det_idx
                matched_detection = people_detections[det_idx]
                break
        
        matched_persons.append({
            "person_idx": person_idx,
            "ground_truth_box": person["box"],
            "ground_truth_dangerous": person["dangerous"],
            "detected": matched_detection is not None,
            "matched_detection_label": matched_detection.label if matched_detection else None,
            "matched_detection_conf": matched_detection.conf if matched_detection else None,
            "matched_detection_box": list(matched_detection.box) if matched_detection else None,
            "match_iou": iou(person["box"], matched_detection.box) if matched_detection else 0.0
        })
    
    return matched_persons


def match_pairs_to_facts(ground_truth_pairs, persons, hazards, facts, height):
    """Evaluate infrontof cue on ground truth pairs."""
    pair_results = []
    
    for pair in ground_truth_pairs:
        person_box = persons[pair["person"]]["box"]
        hazard_box = hazards[pair["hazard"]]["box"]
        cue_result = cue(person_box, hazard_box, height)
        nearer_gt = pair.get("nearer", "unclear")
        
        pair_results.append({
            "person_idx": pair["person"],
            "hazard_idx": pair["hazard"],
            "hazard_class": hazards[pair["hazard"]]["class"],
            "ground_truth_nearer": nearer_gt,
            "infrontof_cue_result": cue_result,
            "correct": cue_result == nearer_gt if nearer_gt != "unclear" else None
        })
    
    return pair_results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default=str(ROOT / "yolo11n-seg.pt"))
    parser.add_argument("--imgsz", type=int, default=640)
    parser.add_argument("--conf", type=float, default=0.25)
    parser.add_argument("--rules", help="default: kb/danger.snepslog, danger_road.snepslog with --road, "
                                        "danger_english.snepslog with --route english")
    parser.add_argument("--road", action="store_true", help="assert onroad/onsidewalk from road segmentation")
    parser.add_argument("--riders", action="store_true", help="assert rides(p, v) and pedestrian(p) (for the rider rules)")
    parser.add_argument("--route", choices=["typed", "english"], default="typed")
    parser.add_argument("--backend", choices=["allegro", "snepspacy"],
                        default="snepspacy" if os.environ.get("SNEPSPACY_DIR") else "allegro")
    parser.add_argument("--sneps-dir", default=os.environ.get("SNEPS_DIR"))
    parser.add_argument("--snepspacy-dir", default=os.environ.get("SNEPSPACY_DIR"))
    parser.add_argument("--coco-dir", help="coco128 folder (default: Ultralytics' datasets_dir/coco128)")
    parser.add_argument("--name", help="name of the result files (default: <model>-<imgsz>)")
    parser.add_argument("--annotations", default="eval/annotations.json", help="ground truth annotations file")
    args = parser.parse_args()
    if args.road and args.route == "english":
        parser.error("--road is not available on the English route")

    from ultralytics import YOLO
    from ultralytics.utils import SETTINGS
    from PIL import Image
    import torch

    # Record configuration for reproducibility
    config = {
        "model": args.model,
        "imgsz": args.imgsz,
        "conf": args.conf,
        "rules": str(args.rules) if args.rules else None,
        "road": args.road,
        "riders": args.riders,
        "route": args.route,
        "backend": args.backend,
        "annotations_file": args.annotations,
        "environment": {
            "platform": platform.platform(),
            "python_version": sys.version,
            "pytorch_version": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
            "cuda_version": torch.version.cuda if torch.cuda.is_available() else None,
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    coco_dir = Path(args.coco_dir) if args.coco_dir else Path(SETTINGS["datasets_dir"]) / "coco128"
    annotations = json.load(open(ROOT / args.annotations, encoding="utf-8"))["images"]
    model = YOLO(args.model)
    rules_path = Path(args.rules) if args.rules else ROOT / "kb" / (
        "danger_english.snepslog" if args.route == "english" else
        "danger_road.snepslog" if args.road else "danger.snepslog")
    rules = load_rules(rules_path)
    config["rules_path"] = str(rules_path)
    config["rules_count"] = len(rules)
    
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
              "warnings": 0, "yolo_seconds": 0.0, "sneps_seconds": 0.0, "translate_seconds": 0.0,
              "hidden_tp_fp_fn": [0, 0, 0], "images_dangerous": 0, "images_dangerous_found": 0}
    by_stratum = {}
    rows = []
    detailed_rows = []
    
    with backend as session:
        for item in annotations:
            path = image_path(item, coco_dir)
            height = Image.open(path).size[1]
            truth = [p["box"] for p in item["persons"]]

            # Relation: the cue on the ground-truth boxes
            pair_evaluations = match_pairs_to_facts(
                item["pairs"], item["persons"], item["hazards"], [], height
            )
            for pair_eval in pair_evaluations:
                if pair_eval["ground_truth_nearer"] == "unclear":
                    continue
                totals["pairs"] += 1
                totals["pairs_correct"] += pair_eval["correct"] or 0
                totals["pairs_none"] += pair_eval["infrontof_cue_result"] == "none"

            # The whole system
            start = time.perf_counter()
            result = model(str(path), conf=args.conf, imgsz=args.imgsz, verbose=False)[0]
            yolo_time = time.perf_counter() - start
            totals["yolo_seconds"] += yolo_time
            
            detections, facts, scene = describe(result, conf=args.conf, pair_filter=focus_pairs({"person"}),
                                                road_model=road_model, find_riders=args.riders)
            
            # Match ground truth to detections
            matched_persons = match_ground_truth_to_detections(item["persons"], detections)
            
            row = {"image": item["file"]}
            detailed_row = {
                "image": item["file"],
                "source": item["source"],
                "stratum": stratum_of(item),
                "image_height": height,
                "ground_truth": {
                    "persons": item["persons"],
                    "hazards": item["hazards"],
                    "pairs": item["pairs"]
                },
                "detections": [
                    {
                        "label": d.label,
                        "class": d.cls,
                        "box": list(d.box),
                        "confidence": d.conf
                    } for d in detections
                ],
                "facts": facts,
                "statements": scene,
                "matched_persons": matched_persons,
                "pair_evaluations": pair_evaluations,
                "timing": {
                    "yolo_seconds": yolo_time
                }
            }
            
            if translator:
                start = time.perf_counter()
                translated, warnings = translator.statements(sentences(detections, facts))
                translate_time = time.perf_counter() - start
                totals["translate_seconds"] += translate_time
                totals["warnings"] += len(warnings)
                
                answers, errors, seconds, raw_output = ask(session, rules + translated)
                typed, typed_errors, _, typed_output = ask(session, typed_rules + scene)
                
                row["agrees_with_typed"] = answers == typed and not typed_errors
                totals["agree"] += row["agrees_with_typed"]
                
                detailed_row["english_route"] = {
                    "sentences": sentences(detections, facts),
                    "translated_statements": translated,
                    "translation_warnings": warnings,
                    "translation_time_seconds": translate_time
                }
                detailed_row["typed_comparison"] = {
                    "statements": scene,
                    "answers": {q: sorted(list(typed[q])) for q in QUESTIONS},
                    "errors": typed_errors,
                    "agrees": row["agrees_with_typed"]
                }
                detailed_row["timing"]["translate_seconds"] = translate_time
                detailed_row["sneps_raw_output"] = raw_output
            else:
                answers, errors, seconds, raw_output = ask(session, rules + scene)
                detailed_row["sneps_raw_output"] = raw_output
            
            totals["sneps_seconds"] += seconds
            totals["errors"] += bool(errors)
            detailed_row["timing"]["sneps_seconds"] = seconds

            people = [d for d in detections if d.cls == "person"]
            if item["source"] == "coco128":
                totals["gt_persons"] += len(truth)
                totals["found"] += len(match([d.box for d in people], truth))
            
            counts = {q: score(answers[q], people, item["persons"], "hidden" if q == "hidden" else "dangerous")
                      for q in QUESTIONS}
            for q in ("dangerous", "alert"):
                totals[q] = [a + b for a, b in zip(totals[q], counts[q])]
            totals["hidden_tp_fp_fn"] = [a + b for a, b in zip(totals["hidden_tp_fp_fn"], counts["hidden"])]
            totals["hidden"] += len(answers["hidden"])
            positive = any(p["dangerous"] is True for p in item["persons"])
            totals["images_dangerous"] += positive
            totals["images_dangerous_found"] += positive and counts["dangerous"][0] > 0
            s = by_stratum.setdefault(stratum_of(item), {"images": 0, "danger_tp_fp_fn": [0, 0, 0],
                                                          "images_dangerous": 0, "images_dangerous_found": 0})
            s["images"] += 1
            s["danger_tp_fp_fn"] = [a + b for a, b in zip(s["danger_tp_fp_fn"], counts["dangerous"])]
            s["images_dangerous"] += positive
            s["images_dangerous_found"] += positive and counts["dangerous"][0] > 0

            row.update({"persons": len(truth), "detected": len(match([d.box for d in people], truth)),
                        "dangerous": sum(p["dangerous"] is True for p in item["persons"]),
                        "flagged": sorted(answers["dangerous"]), "alert": sorted(answers["alert"]),
                        "hidden": sorted(answers["hidden"]), "tp_fp_fn": list(counts["dangerous"]),
                        "alert_tp_fp_fn": list(counts["alert"]), "errors": len(errors)})
            
            # Add detailed predictions
            detailed_row["predictions"] = {
                "dangerous": sorted(list(answers["dangerous"])),
                "alert": sorted(list(answers["alert"])),
                "hidden": sorted(list(answers["hidden"]))
            }
            detailed_row["sneps_errors"] = errors
            detailed_row["evaluation"] = {
                "dangerous": {"tp": counts["dangerous"][0], "fp": counts["dangerous"][1], "fn": counts["dangerous"][2]},
                "alert": {"tp": counts["alert"][0], "fp": counts["alert"][1], "fn": counts["alert"][2]},
                "hidden": {"tp": counts["hidden"][0], "fp": counts["hidden"][1], "fn": counts["hidden"][2]},
                "persons_detected": len(match([d.box for d in people], truth)),
                "persons_ground_truth": len(truth)
            }
            
            rows.append(row)
            detailed_rows.append(detailed_row)
            print(f"{item['file']}: flagged {row['flagged'] or '-'} alert {row['alert'] or '-'} "
                  f"hidden {row['hidden'] or '-'} tp/fp/fn={row['tp_fp_fn']}")

    t, n = totals, len(annotations)
    summary = {
        "model": Path(args.model).name, "imgsz": args.imgsz, "conf": args.conf,
        "rules": rules_path.name,
        "route": args.route, "road": args.road, "riders": args.riders, "backend": args.backend, "images": n,
        "person_recall_coco128": ratio(t["found"], t["gt_persons"]),
        "infrontof_accuracy": ratio(t["pairs_correct"], t["pairs"]),
        "infrontof_no_answer": ratio(t["pairs_none"], t["pairs"]),
        "danger_tp_fp_fn": t["dangerous"],
        **dict(zip(("danger_precision", "danger_recall", "danger_f1"), prf(*t["dangerous"]))),
        "alert_tp_fp_fn": t["alert"],
        **dict(zip(("alert_precision", "alert_recall", "alert_f1"), prf(*t["alert"]))),
        "hidden_flagged": t["hidden"],
        "hidden_tp_fp_fn": t["hidden_tp_fp_fn"],
        **dict(zip(("hidden_precision", "hidden_recall", "hidden_f1"), prf(*t["hidden_tp_fp_fn"]))),
        "image_recall_dangerous": ratio(t["images_dangerous_found"], t["images_dangerous"]),
        "images_with_sneps_errors": t["errors"],
        "yolo_seconds_per_image": round(t["yolo_seconds"] / n, 3),
        "sneps_seconds_per_image": round(t["sneps_seconds"] / n, 3),
    }
    if translator:
        summary.update({"translate_seconds_per_image": round(t["translate_seconds"] / n, 3),
                        "translation_warnings": t["warnings"],
                        "same_answers_as_typed_route": ratio(t["agree"], n)})
    summary["by_stratum"] = {k: {**v, **dict(zip(("danger_precision", "danger_recall", "danger_f1"),
                                                 prf(*v["danger_tp_fp_fn"])))} for k, v in by_stratum.items()}

    out = ROOT / "eval" / "results"
    out.mkdir(exist_ok=True)
    
    # Original format outputs (for regression testing)
    json.dump({"summary": summary, "images": rows}, open(out / f"{name}.json", "w", encoding="utf-8"), indent=1)
    md = [f"# Evaluation: {name}", "", "| Measure | Value |", "|---|---|"]
    md += [f"| {k} | {v} |" for k, v in summary.items() if k != "by_stratum"]
    md += ["", "| Stratum | Images | TP / FP / FN | Precision | Recall | Images with a dangerous person found |",
           "|---|---|---|---|---|---|"]
    md += [f"| {k} | {v['images']} | {' / '.join(map(str, v['danger_tp_fp_fn']))} | {v['danger_precision']} | "
           f"{v['danger_recall']} | {ratio(v['images_dangerous_found'], v['images_dangerous'])} |"
           for k, v in summary["by_stratum"].items()]
    md += ["", "| Image | People | Detected | Dangerous | Flagged | Alert | Hidden | TP | FP | FN |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    md += [f"| {r['image']} | {r['persons']} | {r['detected']} | {r['dangerous']} | {', '.join(r['flagged']) or '-'} | "
           f"{', '.join(r['alert']) or '-'} | {', '.join(r['hidden']) or '-'} | "
           + " | ".join(map(str, r["tp_fp_fn"])) + " |" for r in rows]
    (out / f"{name}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    
    # NEW: Detailed per-image output (JSONL format)
    with open(out / f"{name}_detailed.jsonl", "w", encoding="utf-8") as f:
        for detailed_row in detailed_rows:
            f.write(json.dumps(detailed_row) + "\n")
    
    # NEW: Configuration file for reproducibility
    json.dump(config, open(out / f"{name}_config.json", "w", encoding="utf-8"), indent=2)
    
    print("\nOutputs written:")
    print(f"  - {out / f'{name}.json'} (summary, original format)")
    print(f"  - {out / f'{name}.md'} (markdown report)")
    print(f"  - {out / f'{name}_detailed.jsonl'} (per-image detailed, {len(detailed_rows)} lines)")
    print(f"  - {out / f'{name}_config.json'} (configuration)")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
