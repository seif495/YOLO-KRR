"""Select the Phase 4 dev and test images from COCO val2017 and train2017, and fetch them.

    python eval/coco_subset.py select --coco-json PATH [--seed 2026]
    python eval/coco_subset.py fetch [--datasets-dir DIR]
    python eval/coco_subset.py duplicates [--bits N] [--datasets-dir DIR]
    python eval/coco_subset.py exclude FILE --reason REASON --note TEXT [--datasets-dir DIR]
    python eval/coco_subset.py supplement --stratum front [--datasets-dir DIR]
    python eval/coco_subset.py draw-train --coco-json PATH [--seed 2026] [--datasets-dir DIR]

select draws the images from COCO val2017's human-drawn boxes; nothing here runs the detector. An
image is eligible if it has 1 to 12 people, at least one motor vehicle or train (car, motorcycle, bus,
truck, train) and no crowd annotation (a crowd region leaves people unboxed). Each eligible image
falls in one stratum:
  front   a person's box overlaps a hazard's and the person's base is lower: every person who can be
          dangerous under ANNOTATION_GUIDELINES.md v1.2 is in one of these images
  behind  otherwise, a hazard covers at least 20% of a person's box and the person's base is higher:
          the candidates for hidden
  apart   the rest
A person overlapping a bicycle or motorcycle with their base in its bottom 15% is taken for its
rider and does not make an image front. Each stratum is shuffled with the seed; its first images fill
the dev and test sets in the fixed numbers below and the rest, in order, are the reserve. An image may
be excluded only for a reason in EXCLUSION_REASONS, and is then replaced by the next reserve image of
its stratum and COCO split, in the same set. Images captured at the same second are kept in the same
set, but COCO's capture times do not identify scenes (hundreds of unrelated selected images fall within
an hour of each other), so near-duplicates are found by content instead: duplicates lists the selected
pairs whose difference hashes differ in at most NEAR_DUPLICATE bits, and exclude replaces an image,
skipping reserve images that would be near-duplicates themselves.

supplement moves a stratum's whole reserve into the sets, in draw order, assigning SUPPLEMENT_PATTERN in
turn (dev, dev, test, ...), so the 2:1 split holds; images marked "draw": "supplement". It skips images
within NEAR_DUPLICATE bits of one already selected (recorded under "excluded"). After supplementing
front, every eligible val2017 front image is in a set: front is a census, behind and apart are random
samples of the sizes in "eligible".

draw-train adds test images from COCO train2017, because val2017's whole front stratum holds only 3
test images with a dangerous person. The rule was fixed before any train2017 image was seen: the same
eligibility and strata; only the front stratum; images of the baseline (eval/annotations.json, whose
coco128 images come from train2017) left out; shuffled with the seed; the first TRAIN_DRAW images go to
the test set (marked "draw": "train2017"), skipping near-duplicates of images already selected; the
next TRAIN_RESERVE are the reserve for exclusions. It also writes the drawn and reserve images'
annotations to <datasets-dir>/coco_train2017/instances_train2017_selected.json, so later steps need not
load the 470 MB file. These images are a random sample of train2017's front stratum, reported as their
own stratum.

Writes eval/coco_selection.json; every record names its COCO split ("coco_split"). fetch downloads the
selected images (over http: COCO's https certificate does not match its host) into
<datasets-dir>/coco_<split>/images, default datasets-dir Ultralytics' datasets_dir, and records or
checks each file's SHA-256 in the selection file.
"""
import argparse
import hashlib
import json
import random
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from analyze_errors import boxes_intersect, hazard_classes  # noqa: E402
from yolo_sneps.scene import atom  # noqa: E402

SELECTION = ROOT / "eval" / "coco_selection.json"
ANNOTATIONS_ZIP = "annotations_trainval2017.zip (md5 f4bbac642086de4f52a3fdda2de5fa2c)"
MOTOR = {"car", "motorcycle", "bus", "truck", "train"}
TWO_WHEELERS = {"bicycle", "motorcycle"}
MAX_PEOPLE = 12
# Of 64 difference-hash bits. The one real duplicate (excluded by hand) is 11 bits from its twin, but so is an
# unrelated train2017 image, so pairs from NEAR_DUPLICATE + 1 to 16 bits are checked by eye (duplicates --bits 16).
NEAR_DUPLICATE = 10
SUPPLEMENT_PATTERN = ("dev", "dev", "test")
COUNTS = {"dev": {"front": 50, "behind": 24, "apart": 26}, "test": {"front": 25, "behind": 12, "apart": 13}}
TRAIN_DRAW = 200
TRAIN_RESERVE = 50
TRAIN_SELECTED = "instances_train2017_selected.json"
EXCLUSION_REASONS = {
    "unreadable": "the image cannot be opened",
    "unboxed_person": "a visible person within ~50 px of a hazard has no COCO box",
    "near_duplicate": "the same scene as an image already selected",
}


def xyxy(bbox):
    x, y, w, h = bbox
    return [x, y, x + w, y + h]


def covered(person, hazard):
    """Share of the person's box inside the hazard's."""
    w = max(0.0, min(person[2], hazard[2]) - max(person[0], hazard[0]))
    h = max(0.0, min(person[3], hazard[3]) - max(person[1], hazard[1]))
    area = (person[2] - person[0]) * (person[3] - person[1])
    return w * h / area if area > 0 else 0.0


def probable_rider(person, hazard, cls):
    return (cls in TWO_WHEELERS and boxes_intersect(person, hazard)
            and person[3] <= hazard[3] and person[3] >= hazard[3] - 0.15 * (hazard[3] - hazard[1]))


def stratum(persons, hazards):
    """front, behind or apart, from (box) persons and (box, class) hazards."""
    pairs = [(p, h, c) for p in persons for h, c in hazards if boxes_intersect(p, h)]
    if any(p[3] > h[3] and not probable_rider(p, h, c) for p, h, c in pairs):
        return "front"
    if any(p[3] < h[3] and covered(p, h) >= 0.2 for p, h, _ in pairs):
        return "behind"
    return "apart"


def eligible_images(coco, hazards):
    """{image id: (image info, stratum)} for every eligible image."""
    names = {c["id"]: c["name"] for c in coco["categories"]}
    by_image = defaultdict(list)
    for a in coco["annotations"]:
        by_image[a["image_id"]].append(a)
    result = {}
    for info in coco["images"]:
        anns = by_image[info["id"]]
        if any(a["iscrowd"] for a in anns):
            continue
        persons = [xyxy(a["bbox"]) for a in anns if names[a["category_id"]] == "person"]
        objects = [(xyxy(a["bbox"]), names[a["category_id"]]) for a in anns]
        if not 1 <= len(persons) <= MAX_PEOPLE or not any(c in MOTOR for _, c in objects):
            continue
        result[info["id"]] = (info, stratum(persons, [(b, c) for b, c in objects if atom(c) in hazards]))
    return result


def record_for(info, name, licenses, coco_split):
    return {"id": info["id"], "file": info["file_name"], "coco_split": coco_split, "stratum": name,
            "width": info["width"], "height": info["height"], "date_captured": info["date_captured"],
            "coco_url": info["coco_url"], "flickr_url": info["flickr_url"],
            "license": licenses[info["license"]]["name"], "license_url": licenses[info["license"]]["url"]}


def strata_sizes(images):
    return {s: sum(1 for _, t in images.values() if t == s) for s in ("front", "behind", "apart")}


def select(coco, hazards, seed):
    images = eligible_images(coco, hazards)
    licenses = {lic["id"]: lic for lic in coco["licenses"]}
    rng = random.Random(seed)
    chosen, reserve, split_of_time = [], [], {}
    for name in ("front", "behind", "apart"):
        ids = sorted(i for i, (_, s) in images.items() if s == name)
        rng.shuffle(ids)
        need = {split: COUNTS[split][name] for split in COUNTS}
        for i in ids:
            info = images[i][0]
            split = split_of_time.get(info["date_captured"]) or next((s for s in need if need[s]), None)
            record = record_for(info, name, licenses, "val2017")
            if split and need[split]:
                need[split] -= 1
                split_of_time[info["date_captured"]] = split
                chosen.append({**record, "split": split})
            else:
                reserve.append(record)
    return {"source": f"COCO val2017, annotations/instances_val2017.json from {ANNOTATIONS_ZIP}",
            "seed": seed, "eligible": strata_sizes(images), "counts": COUNTS, "max_people": MAX_PEOPLE,
            "exclusion_reasons": EXCLUSION_REASONS, "images": chosen, "reserve": reserve, "excluded": []}


def image_path(record, datasets_dir):
    """Where an image of the selection is kept: <datasets_dir>/coco_<split>/images/<file>."""
    return datasets_dir / f"coco_{record.get('coco_split', 'val2017')}" / "images" / record["file"]


def dhash(path):
    """64-bit difference hash: which of each pair of neighbouring pixels is brighter, on a 9x8 thumbnail."""
    pixels = list(Image.open(path).convert("L").resize((9, 8), Image.LANCZOS).getdata())
    return sum(1 << i for i in range(64) if pixels[i // 8 * 9 + i % 8] > pixels[i // 8 * 9 + i % 8 + 1])


def near_duplicates(selection, datasets_dir, bits=NEAR_DUPLICATE):
    """(distance, file, file) for selected pairs within `bits` bits, closest first."""
    hashes = {r["file"]: dhash(image_path(r, datasets_dir)) for r in selection["images"]}
    files = list(hashes)
    distances = ((bin(hashes[a] ^ hashes[b]).count("1"), a, b) for i, a in enumerate(files) for b in files[i + 1:])
    return sorted(d for d in distances if d[0] <= bits)


def download(record, datasets_dir):
    path = image_path(record, datasets_dir)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(record["coco_url"].replace("https://", "http://"), timeout=60) as response:
            path.write_bytes(response.read())
    return path


def nearest(h, kept):
    """(bits, file) of the kept hash closest to h."""
    return min((bin(h ^ k).count("1"), f) for f, k in kept.items())


def exclude(selection, file, reason, note, datasets_dir):
    """Move `file` to the excluded list and select the next usable reserve image of its stratum in its place."""
    if reason not in EXCLUSION_REASONS:
        sys.exit(f"reason must be one of {sorted(EXCLUSION_REASONS)}")
    record = next((r for r in selection["images"] if r["file"] == file), None)
    if record is None:
        sys.exit(f"{file} is not a selected image")
    selection["images"].remove(record)
    selection["excluded"].append({**record, "reason": reason, "note": note})
    kept = {r["file"]: dhash(image_path(r, datasets_dir)) for r in selection["images"]}
    for candidate in [r for r in selection["reserve"]
                      if r["stratum"] == record["stratum"] and r["coco_split"] == record["coco_split"]]:
        selection["reserve"].remove(candidate)
        bits, twin = nearest(dhash(download(candidate, datasets_dir)), kept)
        if bits > NEAR_DUPLICATE:
            selection["images"].append({**candidate, "split": record["split"],
                                        **({"draw": record["draw"]} if "draw" in record else {})})
            print(f"{file} excluded ({reason}); {candidate['file']} takes its place in {record['split']}")
            return
        selection["excluded"].append({**candidate, "reason": "near_duplicate",
                                      "note": f"skipped as a replacement: {bits} bits from {twin}"})
    sys.exit(f"no reserve image left in stratum {record['stratum']} of {record['coco_split']}")


def supplement(selection, stratum, datasets_dir):
    """Move the stratum's val2017 reserve into the sets, in draw order, splits by SUPPLEMENT_PATTERN."""
    kept = {r["file"]: dhash(image_path(r, datasets_dir)) for r in selection["images"]}
    added = 0
    for candidate in [r for r in selection["reserve"] if r["stratum"] == stratum and r["coco_split"] == "val2017"]:
        selection["reserve"].remove(candidate)
        h = dhash(download(candidate, datasets_dir))
        bits, twin = nearest(h, kept)
        if bits <= NEAR_DUPLICATE:
            selection["excluded"].append({**candidate, "reason": "near_duplicate",
                                          "note": f"skipped by supplement: {bits} bits from {twin}"})
            continue
        kept[candidate["file"]] = h
        split = SUPPLEMENT_PATTERN[added % len(SUPPLEMENT_PATTERN)]
        selection["images"].append({**candidate, "split": split, "draw": "supplement"})
        added += 1
    print(f"{added} {stratum} images added")


def draw_train(selection, coco, hazards, seed, datasets_dir):
    """Add TRAIN_DRAW front images of train2017 to the test set (see the module docstring)."""
    images = eligible_images(coco, hazards)
    licenses = {lic["id"]: lic for lic in coco["licenses"]}
    baseline = {im["file"] for im in json.loads((ROOT / "eval" / "annotations.json").read_text(encoding="utf-8"))["images"]
                if im["source"] == "coco128"}
    ids = sorted(i for i, (info, s) in images.items() if s == "front" and info["file_name"] not in baseline)
    random.Random(seed).shuffle(ids)
    kept = {r["file"]: dhash(image_path(r, datasets_dir)) for r in selection["images"]}
    drawn, reserve = [], []
    for i in ids:
        record = record_for(images[i][0], "front", licenses, "train2017")
        if len(drawn) == TRAIN_DRAW:
            if len(reserve) == TRAIN_RESERVE:
                break
            reserve.append(record)
            continue
        h = dhash(download(record, datasets_dir))
        bits, twin = nearest(h, kept)
        if bits <= NEAR_DUPLICATE:
            selection["excluded"].append({**record, "reason": "near_duplicate",
                                          "note": f"skipped by draw-train: {bits} bits from {twin}"})
            continue
        kept[record["file"]] = h
        drawn.append({**record, "split": "test", "draw": "train2017"})
    selection["images"] += drawn
    selection["reserve"] += reserve
    pool = strata_sizes(images)
    selection["train2017"] = {"source": f"COCO train2017, annotations/instances_train2017.json from {ANNOTATIONS_ZIP}",
                              "seed": seed, "eligible": pool, "baseline_left_out": len(baseline & {
                                  info["file_name"] for info, s in images.values() if s == "front"}),
                              "drawn": TRAIN_DRAW, "reserve": TRAIN_RESERVE}
    wanted = {r["id"] for r in drawn + reserve}
    subset = {"images": [im for im in coco["images"] if im["id"] in wanted],
              "annotations": [a for a in coco["annotations"] if a["image_id"] in wanted],
              "categories": coco["categories"], "licenses": coco["licenses"]}
    (datasets_dir / "coco_train2017" / TRAIN_SELECTED).write_text(json.dumps(subset), encoding="utf-8")
    print(f"train2017 eligible: {pool}; {len(drawn)} front images added to test, {len(reserve)} in reserve")


def fetch(selection, datasets_dir):
    for record in selection["images"]:
        path = download(record, datasets_dir)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if record.setdefault("sha256", digest) != digest:
            sys.exit(f"{path}: SHA-256 {digest} does not match the selection's {record['sha256']}")
    print(f"{len(selection['images'])} images under {datasets_dir}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("select")
    s.add_argument("--coco-json", required=True, type=Path)
    s.add_argument("--seed", type=int, default=2026)
    for name in ("fetch", "duplicates", "exclude", "supplement", "draw-train"):
        command = sub.add_parser(name)
        command.add_argument("--datasets-dir", type=Path)
        if name == "exclude":
            command.add_argument("file")
            command.add_argument("--reason", required=True)
            command.add_argument("--note", required=True)
        if name == "supplement":
            command.add_argument("--stratum", required=True, choices=["front", "behind", "apart"])
        if name == "duplicates":
            command.add_argument("--bits", type=int, default=NEAR_DUPLICATE, help="list pairs within this many bits")
        if name == "draw-train":
            command.add_argument("--coco-json", required=True, type=Path, help="instances_train2017.json")
            command.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    if args.command == "select":
        coco = json.loads(args.coco_json.read_text(encoding="utf-8"))
        selection = select(coco, hazard_classes(ROOT / "kb" / "danger.snepslog"), args.seed)
        print("eligible:", selection["eligible"])
    else:
        from ultralytics.utils import SETTINGS
        selection = json.loads(SELECTION.read_text(encoding="utf-8"))
        datasets_dir = args.datasets_dir or Path(SETTINGS["datasets_dir"])
        if args.command == "duplicates":
            pairs = near_duplicates(selection, datasets_dir, args.bits)
            split = {r["file"]: r["split"] for r in selection["images"]}
            for distance, a, b in pairs:
                print(f"{distance:2d} bits  {a} ({split[a]})  {b} ({split[b]})")
            print(f"{len(pairs)} pairs within {args.bits} bits")
            return
        if args.command == "exclude":
            exclude(selection, args.file, args.reason, args.note, datasets_dir)
        if args.command == "supplement":
            supplement(selection, args.stratum, datasets_dir)
        if args.command == "draw-train":
            coco = json.loads(args.coco_json.read_text(encoding="utf-8"))
            draw_train(selection, coco, hazard_classes(ROOT / "kb" / "danger.snepslog"), args.seed, datasets_dir)
        fetch(selection, datasets_dir)
    SELECTION.write_text(json.dumps(selection, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
