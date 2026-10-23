"""Detect objects, assert typed SNePSLOG facts, and ask SNePS who is in a dangerous position.

    python -m yolo_sneps IMAGE [IMAGE ...] [--backend none|allegro|snepspacy] [--road] [options]

For every image this writes <out>/<name>.snepslog (the full SNePSLOG transcript: rules, facts
and the queries; replay it with demo "<path>" in a SNePSLOG session, which clears the KB first)
and <out>/<name>.json (detections, facts and, when a backend ran, the answers).
Three questions are asked: dangerous(?x), alert(?x) (dangerous and detected with confidence
>= 0.5) and hidden(?x) (a person partly behind a vehicle). Each answer is null when no backend
ran or when SNePS reported an error, because a rejected statement or a timeout can hide an
answer. The exit status is 1 if any image had an error.

--road also segments the street (SegFormer, needs `pip install transformers`) to tell whether
each person stands on the road or the pavement, and switches to kb/danger_road.snepslog.
--route english describes the scene in English instead and has SNePSpaCy translate it to
SNePSLOG (needs --snepspacy-dir and spaCy with en_core_web_trf); the rules are then
kb/danger_english.snepslog and the sentences are listed under "english" in the JSON.
"""
import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

from .backends import AllegroBatchBackend, SnepspacyBackend, transcript
from .english import sentences
from .pipeline import describe
from .relations import focus_pairs
from .scene import atom
from .snepslog import load_rules, parse_answers

ROOT = Path(__file__).resolve().parent.parent
QUESTIONS = ("dangerous", "alert", "hidden")
QUERIES = [f"{q}(?x)" for q in QUESTIONS]
DEFAULT_MODEL = str(ROOT / "yolo11n-seg.pt") if (ROOT / "yolo11n-seg.pt").is_file() else "yolo11n-seg.pt"


def make_backend(args):
    if args.backend == "allegro":
        sneps_dir = args.sneps_dir or os.environ.get("SNEPS_DIR")
        if not sneps_dir:
            sys.exit("--backend allegro needs --sneps-dir or SNEPS_DIR (the folder with Sneps-2.7.exe)")
        return AllegroBatchBackend(sneps_dir, timeout=args.timeout)
    if args.backend == "snepspacy":
        if sys.platform == "win32":
            sys.exit("--backend snepspacy needs Linux or WSL; on Windows use --backend allegro")
        snepspacy_dir = args.snepspacy_dir or os.environ.get("SNEPSPACY_DIR")
        if not snepspacy_dir:
            sys.exit("--backend snepspacy needs --snepspacy-dir or SNEPSPACY_DIR (a SNePSpaCy checkout)")
        return SnepspacyBackend(snepspacy_dir, timeout=args.timeout)
    return None


def output_name(image, used):
    name = Path(image).stem or "image"
    candidate, n = name, 1
    while candidate in used:
        n += 1
        candidate = f"{name}_{n}"
    used.add(candidate)
    return candidate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("images", nargs="+", help="image files or URLs")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="YOLO weights (default: %(default)s)")
    parser.add_argument("--conf", type=float, default=0.25, help="minimum detection confidence (default: %(default)s)")
    parser.add_argument("--imgsz", type=int, default=640,
                        help="YOLO inference size; larger finds smaller objects (default: %(default)s)")
    parser.add_argument("--rules", help="SNePSLOG rules file (default: kb/danger.snepslog, "
                                        "kb/danger_road.snepslog with --road, "
                                        "kb/danger_english.snepslog with --route english)")
    parser.add_argument("--route", choices=["typed", "english"], default="typed",
                        help="typed: assert SNePSLOG facts directly; english: describe the scene in "
                             "English and translate it with SNePSpaCy (default: %(default)s)")
    parser.add_argument("--road", action="store_true",
                        help="segment the road and assert onroad(x) / onsidewalk(x) for the focus classes")
    parser.add_argument("--focus", default="person",
                        help="comma-separated classes; only pairs of one of them and another object "
                             "get relation facts (default: %(default)s)")
    parser.add_argument("--all-pairs", action="store_true", help="assert relations for every pair of objects")
    parser.add_argument("--backend", choices=["none", "allegro", "snepspacy"], default="none",
                        help="none: only write the transcripts; allegro: headless Windows SNePS; "
                             "snepspacy: SNePSpaCy's sneps_wrapper (Linux/WSL) (default: %(default)s)")
    parser.add_argument("--sneps-dir", help="Windows SNePS folder (contains Sneps-2.7.exe); or set SNEPS_DIR")
    parser.add_argument("--snepspacy-dir", help="SNePSpaCy checkout (Linux/WSL); or set SNEPSPACY_DIR")
    parser.add_argument("--timeout", type=int, default=300,
                        help="seconds allowed for SNePS per image (per SNePS call with snepspacy) "
                             "(default: %(default)s)")
    parser.add_argument("--out", default="outputs", help="output folder (default: %(default)s)")
    args = parser.parse_args(argv)
    if args.route == "english" and args.road:
        parser.error("--road is not available with --route english")

    rules = load_rules(args.rules or ROOT / "kb" / (
        "danger_english.snepslog" if args.route == "english" else
        "danger_road.snepslog" if args.road else "danger.snepslog"))
    translator = None
    if args.route == "english":
        snepspacy_dir = args.snepspacy_dir or os.environ.get("SNEPSPACY_DIR")
        if not snepspacy_dir:
            sys.exit("--route english needs --snepspacy-dir or SNEPSPACY_DIR (a SNePSpaCy checkout)")
        from .english import Translator
        translator = Translator(snepspacy_dir)
    backend = make_backend(args)
    from ultralytics import YOLO  # imported late so --help and argument errors stay fast

    road_model = None
    if args.road:
        from .road import RoadModel
        road_model = RoadModel()

    model = YOLO(args.model)
    focus = {atom(c) for c in args.focus.split(",") if c.strip()}
    unknown = focus - {atom(n) for n in model.names.values()}
    if unknown and not args.all_pairs:
        print(f"warning: --focus classes not detected by this model: {', '.join(sorted(unknown))}", file=sys.stderr)
    pair_filter = None if args.all_pairs else focus_pairs(focus)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    used_names, failed = set(), 0
    with backend or contextlib.nullcontext() as session:
        for image in args.images:
            name = output_name(image, used_names)
            report = {"image": str(image), "detections": [], "facts": [], "errors": []}
            report.update({q: None for q in QUESTIONS})
            try:
                if Path(image).is_dir():
                    raise ValueError("folders are not supported; pass the image files")
                result = model(image, conf=args.conf, imgsz=args.imgsz, verbose=False)[0]
                detections, facts, scene = describe(result, conf=args.conf, pair_filter=pair_filter,
                                                    road_model=road_model, focus=focus)
                if translator:
                    report["english"] = sentences(detections, facts)
                    scene, warnings = translator.statements(report["english"])
                    report["errors"] += [{"statement": s, "message": f"not fully translated: {m}"}
                                         for s, m in warnings]
                statements = rules + scene
                (out_dir / f"{name}.snepslog").write_text(
                    "\n".join(transcript(statements, QUERIES)) + "\n", encoding="utf-8")
                report["detections"] = [{"label": d.label, "class": d.cls, "conf": round(d.conf, 3),
                                         "box": [round(v, 1) for v in d.box]} for d in detections]
                report["facts"] = statements[len(rules):]
                if session is not None:
                    lines, errors = session.run(statements, QUERIES)
                    answers = {q: parse_answers(lines, q) for q in QUESTIONS}
                    report["errors"] += [{"statement": s, "message": m} for s, m in errors]
                    if report["errors"]:
                        report["partial_answers"] = answers
                    else:
                        report.update(answers)
            except Exception as e:  # keep going with the other images; the failure is in this one's report
                report["errors"].append({"statement": None, "message": f"{type(e).__name__}: {e}"})

            (out_dir / f"{name}.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
            if report["errors"]:
                failed += 1
                verdict = f"UNKNOWN ({len(report['errors'])} error(s), see {name}.json)"
            elif session is None:
                verdict = "not evaluated (no backend)"
            else:
                verdict = "; ".join(f"{q}: {', '.join(report[q]) or 'none'}" for q in QUESTIONS)
            print(f"{image}: {len(report['detections'])} objects, {len(report['facts'])} facts, {verdict}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
