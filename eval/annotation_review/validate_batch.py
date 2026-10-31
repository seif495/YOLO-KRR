"""Check a batch file of judgments for the test split and print the labels it produces.

    .venv/Scripts/python.exe eval/annotation_review/validate_batch.py eval/annotation_review/<name>.json

Exit 1 if any judged image has a problem (missing or stray judgments), naming it.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval"))

from annotate_coco import default_datasets_dir, label, scenes  # noqa: E402

batch = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
found, bad = set(), 0
for r, persons, hazards, pairs in scenes("test", default_datasets_dir()):
    judged = batch.get(r["file"])
    if judged is None:
        continue
    found.add(r["file"])
    try:
        out, _, _ = label(persons, hazards, pairs, judged)
        flags = [f"P{i}:{'D' if p['dangerous'] else 'd?' if p['dangerous'] is None else ''}"
                 f"{'H' if p['hidden'] else 'h?' if p['hidden'] is None else ''}"
                 for i, p in enumerate(out) if p["dangerous"] is not False or p["hidden"] is not False]
        print(f"ok   {r['file']}  {' '.join(flags) or 'all safe'}")
    except ValueError as e:
        bad += 1
        print(f"FAIL {r['file']}: {e}")
for f in sorted(set(batch) - found):
    bad += 1
    print(f"FAIL {f}: not a test image")
sys.exit(1 if bad else 0)
