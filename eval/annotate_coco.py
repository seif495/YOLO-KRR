"""Annotate the Phase 4 COCO images per eval/ANNOTATION_GUIDELINES.md v1.2, from judgments made on the images.

    python eval/annotate_coco.py sheets --split dev|test [--start N] [--count N] [--out DIR] [--datasets-dir DIR]
    python eval/annotate_coco.py build --split dev|test [--partial] [--datasets-dir DIR]

Images and boxes come from <datasets-dir>/coco_val2017 (instances_val2017.json) and coco_train2017
(instances_train2017_selected.json, written by coco_subset.py draw-train), as each selection record says.

Boxes are COCO's human-drawn ones; the detector is never run here. People and hazards (the classes the
rules make hazards) are numbered left to right, P0.. and H0... A candidate pair is a person and a hazard
whose boxes overlap or lie within 50 px (guidelines step 3).

sheets draws each image of the split with its numbered boxes into --out (default eval/review/annotate)
and lists the candidate pairs to judge. It shows which pairs overlap but not which base is lower, so
that depth order is judged on the image, not taken from the system's own cue.

build reads the judgments in eval/annotations_<split>_judgments.json, keyed by file name:
  scene         crossing|beside_parked|crowded|small_distant|safe, the first that fits (people crossing or
                waiting to cross the road; people next to a parked or stopped vehicle; 8 or more people; all small
                or far; anything else)
  lighting, weather    image metadata (guidelines step 5)
  nearer        {"P0-H1": "person|hazard|unclear"} for every candidate pair: where the boxes overlap,
                the one that hides the other is nearer; otherwise, the one standing closer to the camera
  traffic_area  {"H1": "yes|no|unclear"}: is the hazard in the traffic area (Q3)
  person_area   {"P0": "road|off_road|unclear"}: is the person clearly on a pavement or other path
                separated from the road
  barrier       ["P0-H1"]: pairs with a clear barrier between them (Q4)
  distant       ["P0-H1"]: pairs whose boxes overlap only in the picture, the vehicle being far behind the
                person ("significant distance but unclear if safe": null, guidelines section 1)
  roles         {"P3": ["rider"|"occupant", "H2" or null]} or {"P3": ["depiction", null]} (a statue, poster or
                reflection COCO boxed as a person): not a pedestrian, so both labels are false
  not_vehicle   ["H0"]: hazards COCO boxed that are no real vehicle or animal (a toy, a model, a picture or a
                reflection); pairs with them count for neither label
  motion        {"H1": "moving|stopped|parked|unclear"} where determinable
  confidence    {"P0": "medium|low"} (default high; low whenever a label is null)
  notes         {"P0": "...", "image": "..."}
  annotator     who judged the image (default ANNOTATOR); reviewed_by, who re-checked it, if anyone
traffic_area and person_area are needed for every overlapping pair whose nearer is person or unclear,
except for riders and occupants.
build then applies the decision tree:
  dangerous  true if some overlapping pair has the person nearer, the hazard in the traffic area, the
             person not off the road, no barrier and the vehicle not distant; else null if such a pair
             is unclear on any of these or distant; else false
  hidden     true if a vehicle (subclass(c, vehicle) in the rules, as the hidden rule requires) nearer
             than the person covers >= 20% of the person's box; null for 10-20%, or >= 10% with the
             depth order unclear; else false
The image's category is clear_danger if someone is dangerous, else hidden if someone is hidden, else
ambiguous if a label is null, else the scene. build writes eval/annotations_<split>.json, refusing if
any judgment is missing or refers to nothing.
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from analyze_errors import box_gap, boxes_intersect, hazard_classes  # noqa: E402
from coco_subset import SELECTION, TRAIN_SELECTED, covered, image_path, xyxy  # noqa: E402
from yolo_sneps.scene import atom  # noqa: E402
from yolo_sneps.snepslog import load_rules  # noqa: E402

PAIR_GAP = 50
ANNOTATOR = "claude (on the author's behalf)"
SCENES = ("crossing", "beside_parked", "crowded", "small_distant", "safe")
VEHICLES = {m.group(1) for m in map(re.compile(r"subclass\(\s*(\w+)\s*,\s*vehicle\s*\)").fullmatch,
                                    load_rules(ROOT / "kb" / "danger.snepslog")) if m}


COCO_JSON = {"val2017": "coco_val2017/instances_val2017.json",
             "train2017": f"coco_train2017/{TRAIN_SELECTED}"}


def default_datasets_dir():
    from ultralytics.utils import SETTINGS
    return Path(SETTINGS["datasets_dir"])


def scenes(split, datasets_dir):
    """[(selection record, persons, hazards, candidate pairs)] for the split, in selection order."""
    hazards = hazard_classes(ROOT / "kb" / "danger.snepslog")
    records = [r for r in json.loads(SELECTION.read_text(encoding="utf-8"))["images"] if r["split"] == split]
    anns, names = {}, {}
    for coco_split in sorted({r["coco_split"] for r in records}):
        coco = json.loads((datasets_dir / COCO_JSON[coco_split]).read_text(encoding="utf-8"))
        names = {c["id"]: c["name"] for c in coco["categories"]}
        wanted = {r["id"] for r in records if r["coco_split"] == coco_split}
        for a in coco["annotations"]:
            if a["image_id"] in wanted:
                anns.setdefault((coco_split, a["image_id"]), []).append(a)
    result = []
    for r in records:
        objects = [(xyxy(a["bbox"]), names[a["category_id"]]) for a in anns[r["coco_split"], r["id"]]]
        persons = sorted((b for b, c in objects if c == "person"), key=lambda b: (b[0], b[1]))
        found = sorted(((b, c) for b, c in objects if atom(c) in hazards), key=lambda bc: (bc[0][0], bc[0][1]))
        pairs = [(i, j, boxes_intersect(p, h)) for i, p in enumerate(persons) for j, (h, _) in enumerate(found)
                 if boxes_intersect(p, h) or box_gap(p, h) <= PAIR_GAP]
        result.append((r, persons, found, pairs))
    return result


def sheet(path, persons, hazards, scale):
    image = Image.open(path).convert("RGB")
    image = image.resize((int(image.width * scale), int(image.height * scale)))
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("arial.ttf", 15)
    for j, (box, cls) in enumerate(hazards):
        b = [v * scale for v in box]
        draw.rectangle(b, outline=(0, 200, 255), width=2)
        draw.text((b[0] + 2, b[3] - 17), f"H{j} {cls}", fill=(0, 200, 255), font=font, stroke_width=2,
                  stroke_fill=(0, 0, 0))
    for i, box in enumerate(persons):
        b = [v * scale for v in box]
        draw.rectangle(b, outline=(60, 240, 60), width=2)
        draw.text((b[0] + 1, b[1] - 16), f"P{i}", fill=(60, 240, 60), font=font, stroke_width=2, stroke_fill=(0, 0, 0))
    return image


def label(persons, hazards, pairs, judged):
    """The image's persons, hazards and pairs per the decision tree, or raise ValueError naming what is missing."""
    nearer, traffic, area = judged.get("nearer", {}), judged.get("traffic_area", {}), judged.get("person_area", {})
    barrier, roles = set(judged.get("barrier", [])), judged.get("roles", {})
    distant, not_vehicle = set(judged.get("distant", [])), set(judged.get("not_vehicle", []))
    confidence, notes = judged.get("confidence", {}), judged.get("notes", {})
    keys = {f"P{i}-H{j}" for i, j, _ in pairs}
    known = {f"P{i}" for i in range(len(persons))} | {f"H{j}" for j in range(len(hazards))}
    problems = [f"no nearer for {k}" for k in sorted(keys - set(nearer))]
    problems += [f"nearer for {k}, which is no candidate pair" for k in sorted(set(nearer) - keys)]
    problems += [f"{k} in barrier or distant is no candidate pair" for k in sorted((barrier | distant) - keys)]
    problems += [f"{k} refers to nothing" for k in [*traffic, *area, *roles, *confidence, *not_vehicle,
                                                     *(roles[p][1] for p in roles if roles[p][1])] if k not in known]
    problems += [f"{p}: role {roles[p][0]!r} is not rider, occupant or depiction" for p in roles
                 if roles[p][0] not in ("rider", "occupant", "depiction")]
    out_persons = []
    for i, box in enumerate(persons):
        danger, hide = [], []
        for _, j, overlap in (p for p in pairs if p[0] == i):
            key, h = f"P{i}-H{j}", f"H{j}"
            if not overlap or f"P{i}" in roles or h in not_vehicle or key not in nearer:
                continue
            near, cover = nearer[key], covered(box, hazards[j][0])
            if near in ("person", "unclear"):
                if h not in traffic or f"P{i}" not in area:
                    problems.append(f"{key}: needs traffic_area[{h}] and person_area[P{i}]")
                    continue
                facts = (near, traffic[h], area[f"P{i}"], key in barrier)
                danger.append(False if facts[1] == "no" or facts[2] == "off_road" or facts[3]
                              else None if "unclear" in facts[:3] or key in distant else True)
            if atom(hazards[j][1]) not in VEHICLES:
                continue
            if near == "hazard":
                hide.append(True if cover >= 0.2 else None if cover >= 0.1 else False)
            elif near == "unclear" and cover >= 0.1:
                hide.append(None)
        dangerous = True if True in danger else None if None in danger else False
        hidden = True if True in hide else None if None in hide else False
        person = {"box": [round(v, 1) for v in box], "dangerous": dangerous, "hidden": hidden,
                  "confidence_gt": "low" if None in (dangerous, hidden) else confidence.get(f"P{i}", "high")}
        if f"P{i}" in roles:
            role, vehicle = roles[f"P{i}"]
            person.update(role=role, vehicle=int(vehicle[1:]) if vehicle else None)
        if f"P{i}" in notes:
            person["notes"] = notes[f"P{i}"]
        out_persons.append(person)
    if problems:
        raise ValueError("; ".join(problems))
    motion = judged.get("motion", {})
    out_hazards = [{"class": cls, "box": [round(v, 1) for v in box], "motion_state": motion.get(f"H{j}", "unclear"),
                    **({"not_vehicle": True} if f"H{j}" in not_vehicle else {})}
                   for j, (box, cls) in enumerate(hazards)]
    out_pairs = [{"person": i, "hazard": j, "nearer": nearer[f"P{i}-H{j}"]} for i, j, _ in pairs]
    return out_persons, out_hazards, out_pairs


def build(split, datasets_dir, partial=False):
    judgments = json.loads((ROOT / "eval" / f"annotations_{split}_judgments.json").read_text(encoding="utf-8"))
    excluded = [{k: e[k] for k in ("file", "reason", "note")}
                for e in json.loads(SELECTION.read_text(encoding="utf-8"))["excluded"] if e.get("split") == split]
    images, problems = [], []
    selected = set()
    for r, persons, hazards, pairs in scenes(split, datasets_dir):
        selected.add(r["file"])
        judged = judgments.get(r["file"])
        if judged is None:
            if not partial:
                problems.append(f"{r['file']}: not judged")
            continue
        try:
            out_persons, out_hazards, out_pairs = label(persons, hazards, pairs, judged)
        except ValueError as e:
            problems.append(f"{r['file']}: {e}")
            continue
        labels = {(p["dangerous"], p["hidden"]) for p in out_persons}
        category = ("clear_danger" if any(d is True for d, _ in labels) else
                    "hidden" if any(h is True for _, h in labels) else
                    "ambiguous" if any(None in pair for pair in labels) else judged["scene"])
        if judged["scene"] not in SCENES:
            problems.append(f"{r['file']}: scene {judged['scene']!r} is not one of {SCENES}")
        images.append({
            "source": f"coco_{r['coco_split']}", "file": r["file"], "split": split, "coco_id": r["id"],
            "coco_split": r["coco_split"], "stratum": r["stratum"], "draw": r.get("draw", "main"),
            "category": category, "scene": judged["scene"], "lighting": judged["lighting"], "weather": judged["weather"],
            "persons": out_persons, "hazards": out_hazards, "pairs": out_pairs,
            "annotation_metadata": {"annotator": judged.get("annotator", ANNOTATOR), "guidelines": "v1.2",
                                    **({"reviewed_by": judged["reviewed_by"]} if "reviewed_by" in judged else {}),
                                    "ambiguous": any(p["confidence_gt"] == "low" for p in out_persons),
                                    "notes": judged.get("notes", {}).get("image", "")}})
    problems += [f"{f}: judged but not selected for {split}" for f in sorted(set(judgments) - selected)]
    if problems:
        sys.exit("Not written:\n  " + "\n  ".join(problems))
    out = ROOT / "eval" / f"annotations_{split}.json"
    if not partial:
        out.write_text(json.dumps({"guidelines": "eval/ANNOTATION_GUIDELINES.md v1.2", "split": split,
                                   "excluded": excluded, "images": images}, indent=1) + "\n", encoding="utf-8")
    people = [p for im in images for p in im["persons"]]
    count = Counter((p["dangerous"], p["hidden"]) for p in people)
    share = lambda key, value: sum(p[key] is value for p in people) / len(people)  # noqa: E731
    print(f"{out.name}{' (partial, not written)' if partial else ''}: {len(images)} images, {len(people)} people, "
          f"{len(excluded)} excluded")
    print(f"  dangerous {share('dangerous', True):.0%}, hidden {share('hidden', True):.0%}, "
          f"null danger {share('dangerous', None):.0%}, null hidden {share('hidden', None):.0%}")
    print("  categories:", dict(Counter(im["category"] for im in images).most_common()))
    print("  (dangerous, hidden):", dict(count))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["sheets", "build"])
    parser.add_argument("--split", choices=["dev", "test"], required=True)
    parser.add_argument("--datasets-dir", type=Path, help="default: Ultralytics' datasets_dir")
    parser.add_argument("--partial", action="store_true", help="build: check the judged images only, write nothing")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--out", type=Path, default=ROOT / "eval" / "review" / "annotate")
    args = parser.parse_args()
    datasets_dir = args.datasets_dir or default_datasets_dir()

    if args.command == "build":
        return build(args.split, datasets_dir, args.partial)
    args.out.mkdir(parents=True, exist_ok=True)
    chosen = scenes(args.split, datasets_dir)[args.start:args.start + args.count]
    for n, (r, persons, hazards, pairs) in enumerate(chosen, args.start):
        scale = 960 / max(r["width"], r["height"]) if max(r["width"], r["height"]) < 960 else 1.0
        name = f"{args.split}_{n:03d}_{Path(r['file']).stem}.png"
        sheet(image_path(r, datasets_dir), persons, hazards, scale).save(args.out / name)
        listed = ", ".join(f"P{i}-H{j}{' overlap' if o else ''}" for i, j, o in pairs) or "none"
        print(f"[{n}] {r['file']} ({r['stratum']}) -> {name}")
        print(f"    hazards: {', '.join(f'H{j} {c}' for j, (_, c) in enumerate(hazards))}")
        print(f"    pairs: {listed}")


if __name__ == "__main__":
    main()
