"""Detect objects, assert typed SNePSLOG facts, and ask SNePS who is in a dangerous position.

    python -m yolo_sneps IMAGE [IMAGE ...] [--backend none|allegro|snepspacy] [options]

For every image this writes <out>/<name>.snepslog (the full SNePSLOG transcript: rules, facts
and the query; replay it with demo "<path>" in a SNePSLOG session, which clears the KB first)
and <out>/<name>.json (detections, facts and, when a backend ran, the dangerous objects).
"dangerous" is null when no backend ran or when SNePS reported an error, because a rejected
statement or a timeout can hide an answer. The exit status is 1 if any image had an error.
"""
import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

from .backends import AllegroBatchBackend, SnepspacyBackend, transcript
from .relations import focus_pairs, relations
from .scene import atom, detections_from_result
from .snepslog import load_rules, parse_answers, scene_statements

ROOT = Path(__file__).resolve().parent.parent
QUERY = "dangerous(?x)"
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
    parser.add_argument("--rules", default=str(ROOT / "kb" / "danger.snepslog"), help="SNePSLOG rules file")
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

    rules = load_rules(args.rules)
    backend = make_backend(args)
    from ultralytics import YOLO  # imported late so --help and argument errors stay fast

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
            report = {"image": str(image), "detections": [], "facts": [], "dangerous": None, "errors": []}
            try:
                if Path(image).is_dir():
                    raise ValueError("folders are not supported; pass the image files")
                result = model(image, conf=args.conf, imgsz=args.imgsz, verbose=False)[0]
                detections = detections_from_result(result, conf=args.conf)
                facts = relations(detections, result.orig_shape[0], pair_filter=pair_filter)
                statements = rules + scene_statements(detections, facts)
                (out_dir / f"{name}.snepslog").write_text(
                    "\n".join(transcript(statements, QUERY)) + "\n", encoding="utf-8")
                report["detections"] = [{"label": d.label, "class": d.cls, "conf": round(d.conf, 3),
                                         "box": [round(v, 1) for v in d.box]} for d in detections]
                report["facts"] = statements[len(rules):]
                if session is not None:
                    lines, errors = session.run(statements, QUERY)
                    answers = parse_answers(lines)
                    report["errors"] = [{"statement": s, "message": m} for s, m in errors]
                    if errors:
                        report["partial_answers"] = answers
                    else:
                        report["dangerous"] = answers
            except Exception as e:  # keep going with the other images; the failure is in this one's report
                report["errors"].append({"statement": None, "message": f"{type(e).__name__}: {e}"})

            (out_dir / f"{name}.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
            if report["errors"]:
                failed += 1
                verdict = f"UNKNOWN ({len(report['errors'])} error(s), see {name}.json)"
            elif session is None:
                verdict = "not evaluated (no backend)"
            else:
                verdict = ", ".join(report["dangerous"]) or "none"
            print(f"{image}: {len(report['detections'])} objects, {len(report['facts'])} facts, dangerous: {verdict}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
