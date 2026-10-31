"""Quality checks on the Phase 4 annotation files (eval/ANNOTATION_GUIDELINES.md, "Quality Control").

    python eval/check_annotations.py [--images-dir DIR]

Checks eval/annotations_dev.json and eval/annotations_test.json:
  schema    every image and person has the fields guidelines v1.2 require, with allowed values, and
            every pair refers to an existing person and hazard
  splits    no image is in both sets or in the baseline (eval/annotations.json), and no dev/test pair
            of images is a near-duplicate (coco_subset.NEAR_DUPLICATE bits of difference hash)
  rates     the shares of dangerous, hidden and null labels against the guidelines' expected ranges
  strata    the counts per sampling stratum (coco_subset.py), with the weight that turns them into
            estimates for all eligible images: front is a census, behind and apart are samples
Prints the per-set statistics and every problem, and exits 1 if a schema or split check fails. Rates
outside the expected ranges are reported as flags, not failures: the guidelines treat them as findings.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from coco_subset import NEAR_DUPLICATE, dhash, image_path  # noqa: E402

SETS = ("dev", "test")
STRATA = (("val2017", "front"), ("val2017", "behind"), ("val2017", "apart"), ("train2017", "front"))
CATEGORIES = {"clear_danger", "beside_parked", "hidden", "crossing", "small_distant", "crowded", "ambiguous", "safe"}
LIGHTING = {"day", "night", "dawn_dusk"}
WEATHER = {"clear", "rain", "fog", "snow", "unclear"}
NEARER = {"person", "hazard", "unclear"}
CONFIDENCE = {"high", "medium", "low"}
# (low, high) expected and (low, high) flag-if-outside, from the guidelines' "Expected Distributions"
EXPECTED = {"dangerous": ((0.20, 0.40), (0.10, 0.50)), "hidden": ((0.10, 0.20), (0.05, 0.30)),
            "null": ((0.05, 0.15), (0.0, 0.25))}


def schema_problems(name, data):
    problems = []
    for im in data["images"]:
        where = f"{name}/{im.get('file')}"
        for key, allowed in (("category", CATEGORIES), ("lighting", LIGHTING), ("weather", WEATHER)):
            if im.get(key) not in allowed:
                problems.append(f"{where}: {key} {im.get(key)!r} not in {sorted(allowed)}")
        for i, p in enumerate(im["persons"]):
            if len(p.get("box", [])) != 4 or not p["box"][0] < p["box"][2] or not p["box"][1] < p["box"][3]:
                problems.append(f"{where} P{i}: bad box {p.get('box')}")
            for key in ("dangerous", "hidden"):
                if p.get(key, "missing") not in (True, False, None):
                    problems.append(f"{where} P{i}: {key} missing or not true/false/null")
            if p.get("confidence_gt") not in CONFIDENCE:
                problems.append(f"{where} P{i}: confidence_gt {p.get('confidence_gt')!r}")
            if None in (p.get("dangerous"), p.get("hidden")) and p.get("confidence_gt") != "low":
                problems.append(f"{where} P{i}: a null label needs confidence_gt low")
        for pair in im["pairs"]:
            if not (0 <= pair["person"] < len(im["persons"]) and 0 <= pair["hazard"] < len(im["hazards"])):
                problems.append(f"{where}: pair {pair} refers to nothing")
            if pair["nearer"] not in NEARER:
                problems.append(f"{where}: pair {pair} nearer not in {sorted(NEARER)}")
    return problems


def split_problems(sets, baseline, datasets_dir):
    problems = []
    files = {name: {im["file"] for im in data["images"]} for name, data in sets.items()}
    for name, names in files.items():
        if len(names) != len(sets[name]["images"]):
            problems.append(f"{name}: an image appears twice")
        problems += [f"{f}: in {name} and in the baseline" for f in sorted(names & baseline)]
    problems += [f"{f}: in both dev and test" for f in sorted(files["dev"] & files["test"])]
    if datasets_dir:
        hashes = {name: {im["file"]: dhash(image_path(im, datasets_dir)) for im in data["images"]}
                  for name, data in sets.items()}
        problems += [f"{a} (dev) and {b} (test) are near-duplicates ({d} bits)"
                     for a, ha in hashes["dev"].items() for b, hb in hashes["test"].items()
                     if (d := bin(ha ^ hb).count("1")) <= NEAR_DUPLICATE]
    return problems


def rates(data):
    people = [p for im in data["images"] for p in im["persons"]]
    share = {"dangerous": sum(p["dangerous"] is True for p in people) / len(people),
             "hidden": sum(p["hidden"] is True for p in people) / len(people),
             "null": sum(None in (p["dangerous"], p["hidden"]) for p in people) / len(people)}
    flags = [f"{key} {value:.0%} is outside the flag range {lo:.0%}-{hi:.0%}"
             for key, value in share.items() for lo, hi in [EXPECTED[key][1]] if not lo <= value <= hi]
    flags += [f"{key} {value:.0%} is outside the expected {lo:.0%}-{hi:.0%}"
              for key, value in share.items() for lo, hi in [EXPECTED[key][0]]
              if not lo <= value <= hi and not any(f.startswith(key) for f in flags)]
    return people, share, flags


def strata(images, eligible):
    """Per stratum: images, people, dangerous people, images with one, hidden, null, and the design weight.

    The weight is eligible images / images of that stratum in this set. Strata are per COCO split
    (val2017 front, behind, apart; train2017 front): summing a count over the val2017 strata with these
    weights estimates it for all eligible val2017 images, and train2017 front is a random sample of its
    own stratum.
    """
    rows = {}
    for split, stratum in STRATA:
        ims = [im for im in images if im.get("coco_split", "val2017") == split and im["stratum"] == stratum]
        if not ims and split != "val2017":
            continue
        name = stratum if split == "val2017" else f"{stratum} ({split[:5]})"
        people = [p for im in ims for p in im["persons"]]
        rows[name] = {"images": len(ims), "people": len(people),
                      "dangerous": sum(p["dangerous"] is True for p in people),
                      "images_dangerous": sum(any(p["dangerous"] is True for p in im["persons"]) for im in ims),
                      "hidden": sum(p["hidden"] is True for p in people),
                      "null": sum(None in (p["dangerous"], p["hidden"]) for p in people),
                      "eligible": eligible[split][stratum], "weight": eligible[split][stratum] / len(ims) if ims else 0.0}
    return rows


def print_strata(images, eligible):
    print(f"  {'stratum':<14}{'images':>7}{'of':>6}{'weight':>8}{'people':>8}{'danger':>8}{'(imgs)':>8}{'hidden':>8}{'null':>6}")
    for name, r in strata(images, eligible).items():
        print(f"  {name:<14}{r['images']:>7}{r['eligible']:>6}{r['weight']:>8.2f}{r['people']:>8}{r['dangerous']:>8}"
              f"{r['images_dangerous']:>8}{r['hidden']:>8}{r['null']:>6}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--datasets-dir", type=Path, help="holds coco_<split>/images, for the near-duplicate "
                                                          "check (default: Ultralytics' datasets_dir if present)")
    args = parser.parse_args()
    images_dir = args.datasets_dir
    if images_dir is None:
        from ultralytics.utils import SETTINGS
        default = Path(SETTINGS["datasets_dir"])
        images_dir = default if (default / "coco_val2017" / "images").exists() else None

    sets = {name: json.loads((ROOT / "eval" / f"annotations_{name}.json").read_text(encoding="utf-8")) for name in SETS}
    baseline = {im["file"] for im in json.loads((ROOT / "eval" / "annotations.json").read_text(encoding="utf-8"))["images"]}
    selection = json.loads((ROOT / "eval" / "coco_selection.json").read_text(encoding="utf-8"))
    eligible = {"val2017": selection["eligible"], "train2017": selection.get("train2017", {}).get("eligible", {})}
    failures = []
    for name, data in sets.items():
        people, share, flags = rates(data)
        images = data["images"]
        print(f"{name}: {len(images)} images, {len(people)} people, {len(data['excluded'])} excluded")
        print(f"  dangerous {sum(p['dangerous'] is True for p in people)} ({share['dangerous']:.0%}), "
              f"hidden {sum(p['hidden'] is True for p in people)} ({share['hidden']:.0%}), "
              f"a null label {sum(None in (p['dangerous'], p['hidden']) for p in people)} ({share['null']:.0%}), "
              f"riders/occupants {sum('role' in p for p in people)}")
        print(f"  images with a dangerous person: {sum(any(p['dangerous'] is True for p in im['persons']) for im in images)}")
        print("  categories:", dict(Counter(im["category"] for im in images).most_common()))
        print("  lighting:", dict(Counter(im["lighting"] for im in images).most_common()))
        print_strata(images, eligible)
        for flag in flags:
            print(f"  FLAG: {flag}")
        failures += schema_problems(name, data)
    failures += split_problems(sets, baseline, images_dir)
    if images_dir is None:
        print("near-duplicate check skipped: no images directory")
    for problem in failures:
        print(f"FAIL: {problem}")
    print(f"\n{'FAILED' if failures else 'PASSED'}: schema and split checks")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
