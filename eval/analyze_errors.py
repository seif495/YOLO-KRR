"""Analyze errors in evaluation results and attribute them to categories.

Usage:
    python eval/analyze_errors.py eval/results/typed-yolo11n-seg-640.json

Reads evaluation results and ground truth annotations, then classifies each
false positive and false negative according to the error taxonomy in ERROR_TAXONOMY.md.

Outputs:
  - Summary statistics (error category distribution)
  - Per-image error details
  - Recommendations based on error patterns
"""
import argparse
import json
import sys
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from yolo_sneps.scene import iou  # noqa: E402

ERROR_CATEGORIES = {
    "1a_missing_person": "Missing Person Detection (CV)",
    "1b_missing_vehicle": "Missing Vehicle Detection (CV)",
    "1c_wrong_class": "Wrong Classification (CV)",
    "1d_poor_localization": "Poor Localization (CV)",
    "2a_depth_order": "Incorrect Depth Order (Geometric)",
    "2b_overlap": "Overlap Misdetection (Geometric)",
    "2c_spatial": "Spatial Relation Error (Geometric)",
    "3a_missing_fact": "Missing Fact (KR)",
    "3b_atom_form": "Wrong Atom Form (KR)",
    "3c_threshold": "Confidence Threshold (KR)",
    "4a_wrong_inference": "Correct Facts, Wrong Inference (Rule)",
    "4b_rule_broad": "Rule Too Broad (Rule)",
    "4c_rule_narrow": "Rule Too Narrow (Rule)",
    "4d_chained": "Chained Inference Failure (Rule)",
    "5a_conf_low": "Dangerous but Low Confidence (Policy)",
    "5b_conf_high": "Not Dangerous but Confident (Policy)",
    "6a_disagreement": "Annotator Disagreement (Ambiguous)",
    "6b_uncertain": "Inherently Uncertain (Ambiguous)",
    "unknown": "Could Not Classify"
}

CATEGORY_GROUPS = {
    "Perception (CV + Geometric)": ["1a", "1b", "1c", "1d", "2a", "2b", "2c"],
    "Knowledge Representation": ["3a", "3b", "3c"],
    "Reasoning (Rules)": ["4a", "4b", "4c", "4d"],
    "Policy": ["5a", "5b"],
    "Ambiguity": ["6a", "6b"]
}


def load_annotations(path):
    """Load ground truth annotations."""
    with open(path) as f:
        return {item["file"]: item for item in json.load(f)["images"]}


def load_results(path):
    """Load evaluation results (JSONL format)."""
    results = []
    with open(path) as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))
    return {"images": results}


def match_detection(truth_box, detections, threshold=0.5):
    """Find detection matching ground truth box, or None."""
    for d in detections:
        # Handle both dict and object formats
        box = d.box if hasattr(d, 'box') else d["box"]
        if iou(truth_box, box) >= threshold:
            return d
    return None


def match_person_to_detection(person_box, detections):
    """Match ground truth person to detected object."""
    return match_detection(person_box, detections)


def has_fact(facts, predicate, *args):
    """Check if a fact with predicate and arguments exists."""
    fact_str = f"{predicate}({', '.join(args)})"
    # Handle both list-of-lists and list-of-strings
    for f in facts:
        if isinstance(f, list):
            # Format: ['predicate', 'arg1', 'arg2']
            if f[0] == predicate and len(f) == len(args) + 1:
                if all(f[i+1] == arg for i, arg in enumerate(args)):
                    return True
        elif isinstance(f, str):
            if fact_str in f:
                return True
    return False


def get_hazard_label(hazard_box, detections):
    """Get detection label for a hazard box."""
    matched = match_detection(hazard_box, detections)
    if matched:
        return matched.label if hasattr(matched, 'label') else matched["label"]
    return None


def attribute_false_positive(image_name, person_idx, gt_image, detections, facts, dangerous_flags):
    """Classify why a safe person was flagged as dangerous.
    
    Returns (category_code, explanation)
    """
    person = gt_image["persons"][person_idx]
    person_box = person["box"]
    
    # Find which detection was flagged
    detected = match_person_to_detection(person_box, detections)
    if not detected:
        return "unknown", "Person flagged but no matching detection found (shouldn't happen)"
    
    # Handle both dict and object formats
    person_label = detected.label if hasattr(detected, 'label') else detected["label"]
    
    # Check if this person is annotated as being near any vehicle
    relevant_pairs = [p for p in gt_image.get("pairs", []) if p["person"] == person_idx]
    
    if not relevant_pairs:
        return "4b_rule_broad", f"Person {person_label} flagged but no annotated vehicle proximity"
    
    # Check each pair
    for pair in relevant_pairs:
        hazard = gt_image["hazards"][pair["hazard"]]
        hazard_label = get_hazard_label(hazard["box"], detections)
        
        if not hazard_label:
            # Hazard not detected - but rule still fired?
            return "unknown", f"Hazard not detected but {person_label} still flagged"
        
        # Check if infrontof fact exists
        infrontof_fact = has_fact(facts, "infrontof", person_label, hazard_label)
        
        if infrontof_fact:
            # Fact exists, person in front of vehicle
            gt_nearer = pair.get("nearer", "unclear")
            
            if gt_nearer == "person":
                # Ground truth confirms person is nearer, but annotator says not dangerous
                # This means the rule is too broad (fires on parked cars, etc.)
                return "4b_rule_broad", (
                    f"{person_label} correctly detected in front of {hazard_label}, "
                    f"but scenario is safe (likely parked/stopped vehicle)"
                )
            elif gt_nearer == "hazard":
                # Person is behind vehicle according to ground truth
                # Our depth cue got it wrong
                return "2a_depth_order", (
                    f"Depth order reversed: system thinks {person_label} is in front of "
                    f"{hazard_label}, but actually behind"
                )
            else:  # unclear
                # Annotator wasn't sure about depth order
                return "6b_uncertain", f"Ambiguous depth order for {person_label} and {hazard_label}"
        
        # Check if person is behind vehicle (hidden case)
        behind_fact = has_fact(facts, "infrontof", hazard_label, person_label)
        if behind_fact:
            # Person is behind vehicle, should be hidden, not dangerous
            # But dangerous was flagged - why?
            return "4a_wrong_inference", (
                f"{person_label} is behind {hazard_label} (should be hidden, not dangerous)"
            )
    
    # Fell through - rule fired but we can't identify why
    return "4b_rule_broad", f"Rule fired on {person_label} but exact cause unclear (likely parked vehicle)"


def attribute_false_negative(image_name, person_idx, gt_image, detections, facts, dangerous_flags):
    """Classify why a dangerous person was NOT flagged.
    
    Returns (category_code, explanation)
    """
    person = gt_image["persons"][person_idx]
    person_box = person["box"]
    
    # First check: was person detected?
    detected = match_person_to_detection(person_box, detections)
    if not detected:
        return "1a_missing_person", f"Person at {person_box} not detected by YOLO"
    
    # Handle both dict and object formats
    person_label = detected.label if hasattr(detected, 'label') else detected["label"]
    detected_conf = detected.conf if hasattr(detected, 'conf') else detected["conf"]
    
    # Check confidence
    if detected_conf < 0.25:  # Assuming default threshold
        return "3c_threshold", f"{person_label} detected but confidence {detected_conf:.2f} below threshold"
    
    # Person detected - check for relevant vehicles
    relevant_pairs = [p for p in gt_image.get("pairs", []) if p["person"] == person_idx]
    
    if not relevant_pairs:
        return "unknown", f"{person_label} marked dangerous but no vehicle pairs annotated"
    
    for pair in relevant_pairs:
        hazard = gt_image["hazards"][pair["hazard"]]
        hazard_label = get_hazard_label(hazard["box"], detections)
        
        if not hazard_label:
            # Vehicle not detected
            return "1b_missing_vehicle", (
                f"{person_label} detected but threatening {hazard['class']} not detected"
            )
        
        # Both person and vehicle detected - check spatial relations
        gt_nearer = pair.get("nearer", "unclear")
        
        if gt_nearer == "person":
            # Person should be in front of vehicle
            infrontof_fact = has_fact(facts, "infrontof", person_label, hazard_label)
            
            if not infrontof_fact:
                # Fact missing - why?
                # Check if bounding boxes actually overlap
                if iou(person_box, hazard["box"]) < 0.1:
                    return "1d_poor_localization", (
                        f"{person_label} and {hazard_label} don't overlap enough; "
                        "boxes may be misplaced"
                    )
                else:
                    return "2a_depth_order", (
                        f"Depth cue failed: {person_label} is in front of {hazard_label} "
                        "but system thinks otherwise"
                    )
            else:
                # Fact exists, rule should have fired but didn't
                return "4c_rule_narrow", (
                    f"infrontof({person_label}, {hazard_label}) asserted but rule didn't fire"
                )
        
        elif gt_nearer == "hazard":
            # Person behind vehicle - shouldn't be dangerous
            return "unknown", "Ground truth error: person marked dangerous but is behind vehicle"
        
        else:  # unclear
            return "6b_uncertain", f"Ambiguous case: unclear if {person_label} is in front of {hazard_label}"
    
    return "unknown", f"Could not determine why {person_label} was not flagged"


def analyze_image(image_name, gt_image, results):
    """Analyze errors for a single image."""
    # Find corresponding result
    image_result = next((r for r in results.get("images", []) if r.get("image") == image_name), None)
    if not image_result:
        return []
    
    # Extract from detailed format
    detections = [
        type('Detection', (), {
            'label': d['label'],
            'cls': d['class'],
            'box': tuple(d['box']),
            'conf': d['confidence']
        })() for d in image_result.get("detections", [])
    ]
    facts = image_result.get("facts", [])
    dangerous_flags = set(image_result.get("predictions", {}).get("dangerous", []))
    
    errors = []
    
    # Check each ground truth person
    for person_idx, person in enumerate(gt_image["persons"]):
        gt_dangerous = person.get("dangerous", False)
        
        # Match to detected person
        detected = match_person_to_detection(person["box"], detections)
        person_label = detected.label if (detected and hasattr(detected, 'label')) else (detected["label"] if detected else None)
        
        is_flagged = person_label in dangerous_flags if person_label else False
        
        if gt_dangerous and not is_flagged:
            # False negative
            category, explanation = attribute_false_negative(
                image_name, person_idx, gt_image, detections, facts, dangerous_flags
            )
            errors.append({
                "type": "FN",
                "image": image_name,
                "person_idx": person_idx,
                "person_label": person_label,
                "category": category,
                "explanation": explanation
            })
        
        elif not gt_dangerous and is_flagged:
            # False positive
            category, explanation = attribute_false_positive(
                image_name, person_idx, gt_image, detections, facts, dangerous_flags
            )
            errors.append({
                "type": "FP",
                "image": image_name,
                "person_idx": person_idx,
                "person_label": person_label,
                "category": category,
                "explanation": explanation
            })
    
    return errors


def print_summary(errors):
    """Print error summary statistics."""
    fp_errors = [e for e in errors if e["type"] == "FP"]
    fn_errors = [e for e in errors if e["type"] == "FN"]
    
    print("\n" + "="*80)
    print("ERROR ATTRIBUTION SUMMARY")
    print("="*80)
    print(f"\nTotal Errors: {len(errors)}")
    print(f"  False Positives: {len(fp_errors)}")
    print(f"  False Negatives: {len(fn_errors)}")
    
    # Count by category
    fp_categories = Counter(e["category"] for e in fp_errors)
    fn_categories = Counter(e["category"] for e in fn_errors)
    
    print("\n" + "-"*80)
    print("FALSE POSITIVE ATTRIBUTION")
    print("-"*80)
    for cat_code, count in fp_categories.most_common():
        cat_name = ERROR_CATEGORIES.get(cat_code, cat_code)
        pct = 100 * count / len(fp_errors) if fp_errors else 0
        print(f"  {cat_code}: {count:2d} ({pct:5.1f}%) - {cat_name}")
    
    print("\n" + "-"*80)
    print("FALSE NEGATIVE ATTRIBUTION")
    print("-"*80)
    for cat_code, count in fn_categories.most_common():
        cat_name = ERROR_CATEGORIES.get(cat_code, cat_code)
        pct = 100 * count / len(fn_errors) if fn_errors else 0
        print(f"  {cat_code}: {count:2d} ({pct:5.1f}%) - {cat_name}")
    
    # Group by high-level categories
    print("\n" + "-"*80)
    print("ERROR DISTRIBUTION BY PIPELINE STAGE")
    print("-"*80)
    
    all_categories = Counter(e["category"] for e in errors)
    
    for group_name, prefixes in CATEGORY_GROUPS.items():
        count = sum(all_categories[cat] for cat in all_categories if any(cat.startswith(p) for p in prefixes))
        pct = 100 * count / len(errors) if errors else 0
        print(f"  {group_name}: {count:2d} ({pct:5.1f}%)")
    
    print("\n" + "="*80)


def print_details(errors, limit=10):
    """Print detailed error examples."""
    print("\n" + "="*80)
    print(f"DETAILED ERROR EXAMPLES (showing first {limit})")
    print("="*80)
    
    for i, error in enumerate(errors[:limit]):
        print(f"\n{i+1}. {error['type']}: {error['image']}")
        print(f"   Person: {error['person_label'] or 'not detected'} (index {error['person_idx']})")
        print(f"   Category: {error['category']} - {ERROR_CATEGORIES.get(error['category'], 'unknown')}")
        print(f"   Explanation: {error['explanation']}")


def print_recommendations(errors):
    """Provide recommendations based on error distribution."""
    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)
    
    all_categories = Counter(e["category"] for e in errors)
    
    # Count by group
    perception_count = sum(all_categories[cat] for cat in all_categories 
                          if any(cat.startswith(p) for p in CATEGORY_GROUPS["Perception (CV + Geometric)"]))
    kr_count = sum(all_categories[cat] for cat in all_categories 
                  if any(cat.startswith(p) for p in CATEGORY_GROUPS["Knowledge Representation"]))
    reasoning_count = sum(all_categories[cat] for cat in all_categories 
                         if any(cat.startswith(p) for p in CATEGORY_GROUPS["Reasoning (Rules)"]))
    
    total = len(errors)
    
    if total == 0:
        print("\nNo errors to analyze!")
        return
    
    perception_pct = 100 * perception_count / total
    reasoning_pct = 100 * reasoning_count / total
    kr_pct = 100 * kr_count / total
    
    print(f"\nError Distribution:")
    print(f"  Perception (CV + Geometric): {perception_pct:.1f}%")
    print(f"  Knowledge Representation: {kr_pct:.1f}%")
    print(f"  Reasoning (Rules): {reasoning_pct:.1f}%")
    
    print("\nPriority Improvements:")
    
    if reasoning_pct > 50:
        print("  1. HIGH: Rules need refinement (>50% of errors)")
        print("     - Most common: Rule Too Broad (person next to parked car)")
        print("     - Action: Add motion/parking state detection, or context rules")
    
    if perception_pct > 30:
        print(f"  2. MEDIUM: Perception errors ({perception_pct:.1f}%)")
        print("     - Action: Consider larger YOLO model or lower confidence threshold")
    
    if kr_pct > 10:
        print(f"  3. MEDIUM: Knowledge representation issues ({kr_pct:.1f}%)")
        print("     - Action: Review fact generation and KB schema")
    
    # Specific actionable items
    if all_categories.get("4b_rule_broad", 0) > 3:
        print("\n  SPECIFIC: Rule Too Broad dominates false positives")
        print("    - Root cause: Cannot distinguish parked from moving vehicles")
        print("    - Solutions:")
        print("      a) Add temporal information (video frames)")
        print("      b) Add parking lot/curb detection")
        print("      c) Require additional context (onroad + moving)")
    
    if all_categories.get("1a_missing_person", 0) > 2:
        print("\n  SPECIFIC: Missing person detections cause false negatives")
        print("    - Action: Use larger YOLO model (yolo11s or yolo11m)")
        print("    - Action: Lower confidence threshold (current: 0.25)")
    
    if all_categories.get("2a_depth_order", 0) > 2:
        print("\n  SPECIFIC: Depth order estimation errors")
        print("    - Action: Improve infrontof heuristic")
        print("    - Action: Use depth estimation network")


def main():
    parser = argparse.ArgumentParser(description=__doc__, 
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", help="Path to evaluation results JSON")
    parser.add_argument("--annotations", default="eval/annotations.json", 
                       help="Path to ground truth annotations")
    parser.add_argument("--details", type=int, default=10, 
                       help="Number of detailed examples to show")
    parser.add_argument("--output", help="Save full error report to JSON file")
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading annotations from {args.annotations}...")
    annotations = load_annotations(args.annotations)
    
    print(f"Loading results from {args.results}...")
    results = load_results(args.results)
    
    # Analyze each image
    print(f"\nAnalyzing {len(annotations)} images...")
    all_errors = []
    
    for image_name in annotations:
        errors = analyze_image(image_name, annotations[image_name], results)
        all_errors.extend(errors)
    
    # Print results
    print_summary(all_errors)
    print_details(all_errors, limit=args.details)
    print_recommendations(all_errors)
    
    # Save if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "results_file": args.results,
                "annotations_file": args.annotations,
                "total_errors": len(all_errors),
                "errors": all_errors,
                "summary": {
                    "by_type": {
                        "FP": len([e for e in all_errors if e["type"] == "FP"]),
                        "FN": len([e for e in all_errors if e["type"] == "FN"])
                    },
                    "by_category": dict(Counter(e["category"] for e in all_errors))
                }
            }, f, indent=2)
        print(f"\nFull error report saved to {args.output}")


if __name__ == "__main__":
    main()
