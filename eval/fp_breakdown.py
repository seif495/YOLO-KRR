"""Why each false positive of a run is annotated safe, from the annotator's recorded judgments.

    python eval/fp_breakdown.py <name> [<name> ...] [--annotations eval/annotations_dev.json]

Reads eval/results/<name>_error_attribution.json (from analyze_errors.py) and tags every FP with
each reason the judgments give (one FP can carry several):
  person off the road           the annotator judged the person off the road (person_area)
  vehicle outside traffic area  a hazard the rule fired on is judged not in a traffic area, or unclear
  rider/occupant/depiction      the person has a role, so is not a pedestrian
  unmatched detection           the flagged box matches no annotated person
FPs with none of these are listed by name.
"""
import argparse
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def reasons(error, judgments, persons):
    if error["root_cause"] == "unmatched_detection":
        return {"unmatched detection"}
    i = error["person_idx"]
    tags = set()
    if judgments.get("person_area", {}).get(f"P{i}") == "off_road":
        tags.add("person off the road")
    if persons[i].get("role"):
        tags.add("rider/occupant/depiction")
    for trigger in error["evidence"].get("triggers", []):
        h = trigger.get("hazard_idx")
        if h is not None and judgments.get("traffic_area", {}).get(f"H{h}") not in ("yes", None):
            tags.add("vehicle outside traffic area")
    return tags


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="+")
    parser.add_argument("--annotations", default="eval/annotations_dev.json")
    args = parser.parse_args()
    annotations = ROOT / args.annotations
    judgments = json.loads(annotations.with_name(annotations.stem + "_judgments.json").read_text(encoding="utf-8"))
    images = {im["file"]: im for im in json.loads(annotations.read_text(encoding="utf-8"))["images"]}
    for name in args.names:
        errors = json.loads((ROOT / "eval/results" / f"{name}_error_attribution.json").read_text(encoding="utf-8"))["errors"]
        fps = [e for e in errors if e["type"] == "FP"]
        counts, untagged = collections.Counter(), []
        for e in fps:
            tags = reasons(e, judgments[e["image"]], images[e["image"]]["persons"])
            counts.update(tags)
            if not tags:
                untagged.append(f"{e['image']} {e['person_label']}")
        print(f"{name}: {len(fps)} FP")
        for tag, n in counts.most_common():
            print(f"  {n:4d}  {tag}")
        print(f"  {len(untagged):4d}  none of these: {', '.join(untagged) or '-'}")


if __name__ == "__main__":
    main()
