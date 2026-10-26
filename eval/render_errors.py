"""Draw the evidence for each attributed error, for the manual review of eval/EXECUTION_PLAN.md step 3.2.

    python eval/render_errors.py [ATTRIBUTION] [--out DIR] [--coco-dir DIR]

ATTRIBUTION defaults to eval/results/baseline_error_attribution.json (from analyze_errors.py); the
records it was made from are read from its results_file. Writes one PNG per error to --out
(default eval/review/), cropped around the boxes involved, with the root cause and explanation below:
  green   the annotated person          red     the person detection
  blue    hazard detections cited        cyan    their annotated hazards
  orange  the detection the scorer matched to the annotated person instead (unmatched FPs)
"""
import argparse
import json
import sys
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from evaluate import image_path  # noqa: E402

COLORS = {"truth": (40, 200, 70), "detection": (230, 40, 40), "hazard": (40, 110, 240),
          "annotated_hazard": (0, 210, 230), "other": (255, 150, 0)}
WIDTH = 1100


def font(size):
    try:
        return ImageFont.truetype("arial.ttf", size)
    except OSError:
        return ImageFont.load_default(size)


def boxes_for(error, record):
    """(box, color key, caption) for everything the error's evidence refers to."""
    dets = {d["label"]: d for d in record["detections"]}
    truth = record["ground_truth"]
    evidence = error["evidence"]
    drawn = []
    if error["person_idx"] is not None:
        drawn.append((truth["persons"][error["person_idx"]]["box"], "truth", f"GT person {error['person_idx']}"))
    if error["person_label"]:
        d = dets[error["person_label"]]
        drawn.append((d["box"], "detection", f"{d['label']} {d['confidence']:.2f}"))
    closest = evidence.get("closest_person")
    if closest and closest["person_idx"] is not None:
        drawn.append((truth["persons"][closest["person_idx"]]["box"], "truth", f"GT person {closest['person_idx']}"))
        if closest["matched_to"]:
            drawn.append((dets[closest["matched_to"]]["box"], "other", closest["matched_to"]))
    for h in evidence.get("triggers") or evidence.get("candidates") or []:
        if h["hazard_idx"] is not None:
            drawn.append((truth["hazards"][h["hazard_idx"]]["box"], "annotated_hazard",
                          f"GT {h['annotated_class']} ({h.get('nearer') or 'no pair'})"))
        if h["detection"]:
            drawn.append((dets[h["detection"]]["box"], "hazard", h["detection"]))
    return drawn


def render(number, error, record, path):
    image = Image.open(path).convert("RGB")
    drawn = boxes_for(error, record)
    x1 = min(b[0] for b, _, _ in drawn)
    y1 = min(b[1] for b, _, _ in drawn)
    x2 = max(b[2] for b, _, _ in drawn)
    y2 = max(b[3] for b, _, _ in drawn)
    margin = 0.15 * max(x2 - x1, y2 - y1, 300)
    crop = (max(0, int(x1 - margin)), max(0, int(y1 - margin)),
            min(image.width, int(x2 + margin)), min(image.height, int(y2 + margin)))
    scale = WIDTH / (crop[2] - crop[0])
    view = image.crop(crop).resize((WIDTH, int((crop[3] - crop[1]) * scale)))
    draw = ImageDraw.Draw(view)
    label_font = font(15)
    for box, key, caption in drawn:
        b = [(box[0] - crop[0]) * scale, (box[1] - crop[1]) * scale, (box[2] - crop[0]) * scale, (box[3] - crop[1]) * scale]
        draw.rectangle(b, outline=COLORS[key], width=4 if key in ("truth", "detection") else 2)
        y = b[3] + 2 if key in ("annotated_hazard", "truth") else b[1] - 18
        draw.text((b[0] + 3, y), caption, fill=COLORS[key], font=label_font, stroke_width=2, stroke_fill=(0, 0, 0))

    idx = "-" if error["person_idx"] is None else error["person_idx"]
    lines = [f"#{number}  {error['type']}  {error['image']}  GT person {idx} / {error['person_label'] or 'not detected'}",
             f"root cause: {error['root_cause']}" + (f"   contributing: {', '.join(error['contributing_factors'])}"
                                                     if error["contributing_factors"] else "")
             + ("   [needs review]" if error["requires_manual_review"] else "")]
    lines += textwrap.wrap(error["explanation"], 120)
    lines.append("green: annotated person   red: detection   blue: hazard detection   cyan: annotated hazard   "
                 "orange: detection matched instead")
    caption_font = font(16)
    sheet = Image.new("RGB", (WIDTH, view.height + 22 * len(lines) + 16), (20, 20, 20))
    sheet.paste(view, (0, 0))
    text = ImageDraw.Draw(sheet)
    for i, line in enumerate(lines):
        text.text((10, view.height + 8 + 22 * i), line, fill=(235, 235, 235), font=caption_font)
    return sheet


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("attribution", nargs="?", default=ROOT / "eval" / "results" / "baseline_error_attribution.json",
                        type=Path)
    parser.add_argument("--out", default=ROOT / "eval" / "review", type=Path)
    parser.add_argument("--coco-dir", help="coco128 folder (default: Ultralytics' datasets_dir/coco128)")
    args = parser.parse_args()

    from ultralytics.utils import SETTINGS
    coco_dir = Path(args.coco_dir) if args.coco_dir else Path(SETTINGS["datasets_dir"]) / "coco128"
    attribution = json.loads(args.attribution.read_text(encoding="utf-8"))
    results = ROOT / attribution["results_file"]
    records = {r["image"]: r for r in map(json.loads, results.read_text(encoding="utf-8").splitlines()) if r}
    args.out.mkdir(parents=True, exist_ok=True)
    for number, error in enumerate(attribution["errors"], 1):
        record = records[error["image"]]
        path = image_path({"source": record["source"], "file": record["image"]}, coco_dir)
        name = f"{number:02d}_{error['type']}_{Path(error['image']).stem}_{error['person_label'] or 'missed'}.png"
        render(number, error, record, path).save(args.out / name)
        print(f"{args.out / name}")


if __name__ == "__main__":
    main()
