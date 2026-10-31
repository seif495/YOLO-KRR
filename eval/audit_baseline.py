"""
Comprehensive audit script for Phase 2 baseline evaluation.

Performs:
1. Regression equivalence verification
2. Annotation consistency checks
3. Error attribution validation
4. Schema conformance verification
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

def load_json(path: Path) -> dict:
    """Load JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_jsonl(path: Path) -> list:
    """Load JSONL file."""
    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records

def verify_regression_equivalence(original_path: Path, instrumented_path: Path, detailed_path: Path) -> Dict:
    """
    Verify that instrumented evaluation produces identical results to original.
    Returns detailed comparison report.
    """
    print("=" * 80)
    print("1. REGRESSION EQUIVALENCE VERIFICATION")
    print("=" * 80)
    
    original = load_json(original_path)
    instrumented = load_json(instrumented_path)
    detailed = load_jsonl(detailed_path)
    
    results = {
        "passed": True,
        "summary_metrics_match": True,
        "per_image_predictions_match": True,
        "mismatches": []
    }
    
    # Compare summary metrics
    print("\n--- Summary Metrics Comparison ---")
    metrics_to_check = [
        'danger_tp_fp_fn', 'danger_precision', 'danger_recall', 'danger_f1',
        'alert_tp_fp_fn', 'alert_precision', 'alert_recall', 'alert_f1',
        'hidden_flagged', 'images_with_sneps_errors'
    ]
    
    for metric in metrics_to_check:
        orig_val = original['summary'].get(metric)
        inst_val = instrumented['summary'].get(metric)
        match = orig_val == inst_val
        status = "✅" if match else "❌"
        print(f"{status} {metric:30s}: {orig_val} vs {inst_val}")
        if not match:
            results["summary_metrics_match"] = False
            results["passed"] = False
            results["mismatches"].append({
                "type": "summary_metric",
                "metric": metric,
                "original": orig_val,
                "instrumented": inst_val
            })
    
    # Compare per-image predictions
    print("\n--- Per-Image Predictions Comparison ---")
    original_by_image = {img['image']: img for img in original['images']}
    instrumented_by_image = {img['image']: img for img in instrumented['images']}
    detailed_by_image = {rec['image']: rec for rec in detailed}
    
    mismatches_found = 0
    images_checked = 0
    
    for image_name in original_by_image:
        images_checked += 1
        orig = original_by_image[image_name]
        inst = instrumented_by_image.get(image_name)
        det = detailed_by_image.get(image_name)
        
        if not inst:
            print(f"❌ {image_name}: Missing in instrumented results")
            results["per_image_predictions_match"] = False
            results["passed"] = False
            mismatches_found += 1
            continue
        
        # Compare flagged lists
        orig_flagged = set(orig.get('flagged', []))
        inst_flagged = set(inst.get('flagged', []))
        
        if orig_flagged != inst_flagged:
            print(f"❌ {image_name}: Dangerous predictions differ")
            print(f"   Original: {sorted(orig_flagged)}")
            print(f"   Instrumented: {sorted(inst_flagged)}")
            results["per_image_predictions_match"] = False
            results["passed"] = False
            mismatches_found += 1
            results["mismatches"].append({
                "type": "dangerous_prediction",
                "image": image_name,
                "original": sorted(orig_flagged),
                "instrumented": sorted(inst_flagged)
            })
        
        # Compare alert lists
        orig_alert = set(orig.get('alert', []))
        inst_alert = set(inst.get('alert', []))
        
        if orig_alert != inst_alert:
            print(f"❌ {image_name}: Alert predictions differ")
            print(f"   Original: {sorted(orig_alert)}")
            print(f"   Instrumented: {sorted(inst_alert)}")
            results["per_image_predictions_match"] = False
            results["passed"] = False
            mismatches_found += 1
            results["mismatches"].append({
                "type": "alert_prediction",
                "image": image_name,
                "original": sorted(orig_alert),
                "instrumented": sorted(inst_alert)
            })
        
        # Compare hidden lists
        orig_hidden = set(orig.get('hidden', []))
        inst_hidden = set(inst.get('hidden', []))
        
        if orig_hidden != inst_hidden:
            print(f"❌ {image_name}: Hidden predictions differ")
            print(f"   Original: {sorted(orig_hidden)}")
            print(f"   Instrumented: {sorted(inst_hidden)}")
            results["per_image_predictions_match"] = False
            results["passed"] = False
            mismatches_found += 1
            results["mismatches"].append({
                "type": "hidden_prediction",
                "image": image_name,
                "original": sorted(orig_hidden),
                "instrumented": sorted(inst_hidden)
            })
        
        # Verify detailed record has matching predictions
        if det:
            det_dangerous = set(det['predictions'].get('dangerous', []))
            det_alert = set(det['predictions'].get('alert', []))
            det_hidden = set(det['predictions'].get('hidden', []))
            
            if det_dangerous != inst_flagged:
                print(f"❌ {image_name}: Detailed dangerous doesn't match summary")
                results["per_image_predictions_match"] = False
                results["passed"] = False
                mismatches_found += 1
    
    if mismatches_found == 0:
        print(f"✅ All {images_checked} images have matching predictions")
    else:
        print(f"\n❌ Found {mismatches_found} mismatches across {images_checked} images")
    
    print("\n--- Regression Test Result ---")
    if results["passed"]:
        print("✅ PASSED: Instrumented evaluator produces identical results")
    else:
        print("❌ FAILED: Instrumented evaluator produces different results")
    
    return results

def audit_annotation_consistency(annotations_path: Path) -> Dict:
    """
    Audit annotation file for structural inconsistencies.
    """
    print("\n" + "=" * 80)
    print("2. ANNOTATION CONSISTENCY AUDIT")
    print("=" * 80)
    
    annotations = load_json(annotations_path)
    
    issues = {
        "dangerous_without_pairs": [],
        "invalid_person_indices": [],
        "invalid_hazard_indices": [],
        "duplicate_pairs": [],
        "missing_nearer_labels": [],
        "ambiguous_nearer": [],
        "total_issues": 0
    }
    
    for img_data in annotations['images']:
        image = img_data['file']
        persons = img_data['persons']
        hazards = img_data['hazards']
        pairs = img_data['pairs']
        
        num_persons = len(persons)
        num_hazards = len(hazards)
        
        # Find dangerous persons
        dangerous_indices = {i for i, p in enumerate(persons) if p.get('dangerous', False)}
        
        # Find persons referenced in pairs
        persons_in_pairs = {p['person'] for p in pairs}
        
        # Check: dangerous persons without pairs
        dangerous_without_pairs = dangerous_indices - persons_in_pairs
        if dangerous_without_pairs:
            issues["dangerous_without_pairs"].append({
                "image": image,
                "person_indices": sorted(dangerous_without_pairs),
                "boxes": [persons[i]['box'] for i in dangerous_without_pairs]
            })
            issues["total_issues"] += len(dangerous_without_pairs)
        
        # Check: invalid indices in pairs
        seen_pairs = set()
        for pair in pairs:
            person_idx = pair['person']
            hazard_idx = pair['hazard']
            
            if person_idx >= num_persons:
                issues["invalid_person_indices"].append({
                    "image": image,
                    "pair": pair,
                    "max_valid_index": num_persons - 1
                })
                issues["total_issues"] += 1
            
            if hazard_idx >= num_hazards:
                issues["invalid_hazard_indices"].append({
                    "image": image,
                    "pair": pair,
                    "max_valid_index": num_hazards - 1
                })
                issues["total_issues"] += 1
            
            # Check: duplicate pairs
            pair_key = (person_idx, hazard_idx)
            if pair_key in seen_pairs:
                issues["duplicate_pairs"].append({
                    "image": image,
                    "person": person_idx,
                    "hazard": hazard_idx
                })
                issues["total_issues"] += 1
            seen_pairs.add(pair_key)
            
            # Check: missing nearer label
            nearer = pair.get('nearer')
            if not nearer:
                issues["missing_nearer_labels"].append({
                    "image": image,
                    "pair": pair
                })
                issues["total_issues"] += 1
            elif nearer not in ['person', 'hazard', 'unclear']:
                issues["ambiguous_nearer"].append({
                    "image": image,
                    "pair": pair,
                    "nearer": nearer
                })
                issues["total_issues"] += 1
    
    # Print report
    print("\n--- Dangerous Persons Without Pairs ---")
    if issues["dangerous_without_pairs"]:
        for issue in issues["dangerous_without_pairs"]:
            print(f"❌ {issue['image']}")
            print(f"   Persons {issue['person_indices']} marked dangerous but have no hazard pairs")
            print(f"   Boxes: {issue['boxes']}")
    else:
        print("✅ All dangerous persons have at least one hazard pair")
    
    print("\n--- Invalid Person Indices ---")
    if issues["invalid_person_indices"]:
        for issue in issues["invalid_person_indices"]:
            print(f"❌ {issue['image']}: Person index {issue['pair']['person']} exceeds max {issue['max_valid_index']}")
    else:
        print("✅ All person indices are valid")
    
    print("\n--- Invalid Hazard Indices ---")
    if issues["invalid_hazard_indices"]:
        for issue in issues["invalid_hazard_indices"]:
            print(f"❌ {issue['image']}: Hazard index {issue['pair']['hazard']} exceeds max {issue['max_valid_index']}")
    else:
        print("✅ All hazard indices are valid")
    
    print("\n--- Duplicate Pairs ---")
    if issues["duplicate_pairs"]:
        for issue in issues["duplicate_pairs"]:
            print(f"❌ {issue['image']}: Duplicate pair (person {issue['person']}, hazard {issue['hazard']})")
    else:
        print("✅ No duplicate pairs found")
    
    print("\n--- Missing/Invalid Nearer Labels ---")
    if issues["missing_nearer_labels"]:
        for issue in issues["missing_nearer_labels"]:
            print(f"❌ {issue['image']}: Pair {issue['pair']} missing 'nearer' field")
    else:
        print("✅ All pairs have 'nearer' field")
    
    if issues["ambiguous_nearer"]:
        for issue in issues["ambiguous_nearer"]:
            print(f"⚠️  {issue['image']}: Pair {issue['pair']} has invalid nearer value: {issue['nearer']}")
    
    print("\n--- Annotation Consistency Summary ---")
    print(f"Total issues found: {issues['total_issues']}")
    print(f"  - Dangerous persons without pairs: {len(issues['dangerous_without_pairs'])}")
    print(f"  - Invalid person indices: {len(issues['invalid_person_indices'])}")
    print(f"  - Invalid hazard indices: {len(issues['invalid_hazard_indices'])}")
    print(f"  - Duplicate pairs: {len(issues['duplicate_pairs'])}")
    print(f"  - Missing nearer labels: {len(issues['missing_nearer_labels'])}")
    print(f"  - Ambiguous nearer values: {len(issues['ambiguous_nearer'])}")
    
    return issues

def validate_error_attributions(detailed_path: Path, attribution_path: Path, annotations_path: Path) -> Dict:
    """
    Validate the 10 error attributions against detailed evidence.
    """
    print("\n" + "=" * 80)
    print("3. ERROR ATTRIBUTION VALIDATION")
    print("=" * 80)
    
    detailed = load_jsonl(detailed_path)
    attributions = load_json(attribution_path)
    annotations = load_json(annotations_path)
    
    detailed_by_image = {rec['image']: rec for rec in detailed}
    annotations_by_image = {img['file']: img for img in annotations['images']}
    
    validations = []
    
    print(f"\nValidating {len(attributions['errors'])} error attributions...\n")
    
    for error in attributions['errors']:
        image = error['image']
        person_idx = error['person_idx']
        person_label = error['person_label']
        error_type = error['type']
        category = error['category']
        explanation = error['explanation']
        
        det = detailed_by_image.get(image)
        ann = annotations_by_image.get(image)
        
        validation = {
            "image": image,
            "person_idx": person_idx,
            "person_label": person_label,
            "error_type": error_type,
            "category": category,
            "explanation": explanation,
            "ground_truth": None,
            "system_prediction": None,
            "person_detected": None,
            "facts": [],
            "reasoning": [],
            "attribution_status": "unknown"
        }
        
        if not det or not ann:
            validation["attribution_status"] = "missing_data"
            validations.append(validation)
            continue
        
        # Extract ground truth
        if person_idx < len(ann['persons']):
            gt_person = ann['persons'][person_idx]
            validation["ground_truth"] = {
                "dangerous": gt_person.get('dangerous', False),
                "box": gt_person['box']
            }
            
            # Find pairs for this person
            person_pairs = [p for p in ann['pairs'] if p['person'] == person_idx]
            validation["ground_truth"]["pairs"] = person_pairs
        
        # Extract system prediction
        dangerous_list = det['predictions'].get('dangerous', [])
        alert_list = det['predictions'].get('alert', [])
        hidden_list = det['predictions'].get('hidden', [])
        
        validation["system_prediction"] = {
            "dangerous": person_label in dangerous_list,
            "alert": person_label in alert_list,
            "hidden": person_label in hidden_list
        }
        
        # Check person detection
        matched_persons = det.get('matched_persons', [])
        for mp in matched_persons:
            if mp['person_idx'] == person_idx:
                validation["person_detected"] = {
                    "detected": mp['detected'],
                    "label": mp.get('matched_detection_label'),
                    "confidence": mp.get('matched_detection_conf'),
                    "iou": mp.get('match_iou')
                }
                break
        
        # Extract relevant facts
        facts = det.get('facts', [])
        relevant_facts = [f for f in facts if person_label in str(f)]
        validation["facts"] = relevant_facts
        
        # Extract reasoning (limited - just check if person mentioned in statements)
        statements = det.get('statements', [])
        relevant_statements = [s for s in statements if person_label in s]
        validation["reasoning"] = relevant_statements[:5]  # Limit to first 5
        
        # Determine attribution status
        if error_type == "FP":
            # False positive: system said dangerous, ground truth says not dangerous
            if validation["ground_truth"] and validation["system_prediction"]:
                gt_dangerous = validation["ground_truth"]["dangerous"]
                sys_dangerous = validation["system_prediction"]["dangerous"]
                
                if not gt_dangerous and sys_dangerous:
                    # Correct FP identification
                    if category == "4b_rule_broad":
                        # Check if depth cue worked (person in front of hazard)
                        if any('infrontof' in str(f) and person_label in str(f) for f in relevant_facts):
                            validation["attribution_status"] = "confirmed"
                        else:
                            validation["attribution_status"] = "provisional"
                    else:
                        validation["attribution_status"] = "provisional"
                else:
                    validation["attribution_status"] = "incorrect_classification"
        
        elif error_type == "FN":
            # False negative: system missed a dangerous person
            if validation["ground_truth"] and validation["system_prediction"]:
                gt_dangerous = validation["ground_truth"]["dangerous"]
                sys_dangerous = validation["system_prediction"]["dangerous"]
                
                if gt_dangerous and not sys_dangerous:
                    # Correct FN identification
                    if category == "unknown":
                        # Check if annotation is complete
                        gt_pairs = validation["ground_truth"].get("pairs", [])
                        if len(gt_pairs) == 0:
                            validation["attribution_status"] = "confirmed"
                            validation["explanation_updated"] = "Annotation incomplete: no hazard pairs for dangerous person"
                        else:
                            validation["attribution_status"] = "requires_visual_inspection"
                    else:
                        validation["attribution_status"] = "provisional"
                else:
                    validation["attribution_status"] = "incorrect_classification"
        
        validations.append(validation)
    
    # Print validation results
    for v in validations:
        print(f"\n{'=' * 70}")
        print(f"Image: {v['image']}")
        print(f"Person: {v['person_label']} (index {v['person_idx']})")
        print(f"Error Type: {v['error_type']}")
        print(f"Category: {v['category']}")
        print(f"Attribution Status: {v['attribution_status']}")
        
        if v['ground_truth']:
            print(f"\nGround Truth:")
            print(f"  Dangerous: {v['ground_truth']['dangerous']}")
            print(f"  Pairs: {v['ground_truth'].get('pairs', [])}")
        
        if v['system_prediction']:
            print(f"\nSystem Prediction:")
            print(f"  Dangerous: {v['system_prediction']['dangerous']}")
            print(f"  Alert: {v['system_prediction']['alert']}")
            print(f"  Hidden: {v['system_prediction']['hidden']}")
        
        if v['person_detected']:
            print(f"\nPerson Detection:")
            print(f"  Detected: {v['person_detected']['detected']}")
            print(f"  Confidence: {v['person_detected'].get('confidence', 'N/A')}")
            print(f"  IoU: {v['person_detected'].get('iou', 'N/A')}")
        
        if v['facts']:
            print(f"\nRelevant Facts ({len(v['facts'])}):")
            for fact in v['facts'][:3]:
                print(f"  {fact}")
        
        print(f"\nExplanation: {v['explanation']}")
        if 'explanation_updated' in v:
            print(f"Updated: {v['explanation_updated']}")
    
    # Summary
    print("\n" + "=" * 80)
    print("ERROR ATTRIBUTION SUMMARY")
    print("=" * 80)
    
    by_status = defaultdict(int)
    for v in validations:
        by_status[v['attribution_status']] += 1
    
    print(f"\nAttribution Status Distribution:")
    for status, count in sorted(by_status.items()):
        print(f"  {status:30s}: {count:2d}")
    
    return {
        "validations": validations,
        "summary": dict(by_status)
    }

def verify_schema_conformance(detailed_path: Path, config_path: Path) -> Dict:
    """
    Verify that output files conform to documented schema.
    """
    print("\n" + "=" * 80)
    print("4. SCHEMA CONFORMANCE VERIFICATION")
    print("=" * 80)
    
    detailed = load_jsonl(detailed_path)
    config = load_json(config_path)
    
    schema_issues = []
    
    # Check config schema
    print("\n--- Configuration File Schema ---")
    required_config_fields = [
        'model', 'imgsz', 'conf', 'backend', 'annotations_file',
        'environment', 'timestamp', 'rules_path', 'rules_count'
    ]
    
    for field in required_config_fields:
        if field in config:
            print(f"✅ {field}: {config[field]}")
        else:
            print(f"❌ Missing field: {field}")
            schema_issues.append({"file": "config", "field": field, "issue": "missing"})
    
    # Check detailed record schema
    print("\n--- Detailed Record Schema (sample from first record) ---")
    if detailed:
        first_record = detailed[0]
        required_fields = [
            'image', 'source', 'image_height', 'ground_truth', 'detections',
            'facts', 'statements', 'matched_persons', 'pair_evaluations',
            'timing', 'sneps_raw_output', 'predictions', 'sneps_errors', 'evaluation'
        ]
        
        for field in required_fields:
            if field in first_record:
                if field in ['predictions', 'evaluation', 'timing']:
                    print(f"✅ {field}: {first_record[field]}")
                else:
                    value_preview = str(first_record[field])
                    if len(value_preview) > 60:
                        value_preview = value_preview[:60] + "..."
                    print(f"✅ {field}: {value_preview}")
            else:
                print(f"❌ Missing field: {field}")
                schema_issues.append({"file": "detailed", "field": field, "issue": "missing", "record": first_record['image']})
        
        # Check predictions subfields
        print("\n--- Predictions Subfields ---")
        if 'predictions' in first_record:
            pred = first_record['predictions']
            for subfield in ['dangerous', 'alert', 'hidden']:
                if subfield in pred:
                    print(f"✅ predictions.{subfield}: {pred[subfield]}")
                else:
                    print(f"❌ Missing: predictions.{subfield}")
                    schema_issues.append({"file": "detailed", "field": f"predictions.{subfield}", "issue": "missing"})
    
    print("\n--- Schema Conformance Summary ---")
    if schema_issues:
        print(f"❌ Found {len(schema_issues)} schema conformance issues")
        for issue in schema_issues:
            print(f"  {issue}")
    else:
        print("✅ All required fields present and populated")
    
    return {"issues": schema_issues}

def main():
    base_dir = Path(__file__).parent
    results_dir = base_dir / 'results'
    
    # File paths
    original_json = results_dir / 'typed-yolo11n-seg-640.json'
    instrumented_json = results_dir / 'baseline_instrumented.json'
    detailed_jsonl = results_dir / 'baseline_instrumented_detailed.jsonl'
    config_json = results_dir / 'baseline_instrumented_config.json'
    attribution_json = results_dir / 'baseline_error_attribution.json'
    annotations_json = base_dir / 'annotations.json'
    
    # Run audits
    audit_results = {}
    
    try:
        audit_results['regression'] = verify_regression_equivalence(
            original_json, instrumented_json, detailed_jsonl
        )
    except Exception as e:
        print(f"\n❌ Regression verification failed: {e}")
        audit_results['regression'] = {"passed": False, "error": str(e)}
    
    try:
        audit_results['annotations'] = audit_annotation_consistency(annotations_json)
    except Exception as e:
        print(f"\n❌ Annotation audit failed: {e}")
        audit_results['annotations'] = {"error": str(e)}
    
    try:
        audit_results['attributions'] = validate_error_attributions(
            detailed_jsonl, attribution_json, annotations_json
        )
    except Exception as e:
        print(f"\n❌ Attribution validation failed: {e}")
        audit_results['attributions'] = {"error": str(e)}
    
    try:
        audit_results['schema'] = verify_schema_conformance(detailed_jsonl, config_json)
    except Exception as e:
        print(f"\n❌ Schema verification failed: {e}")
        audit_results['schema'] = {"error": str(e)}
    
    # Save full audit report
    output_path = results_dir / 'baseline_audit_report.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(audit_results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("AUDIT COMPLETE")
    print("=" * 80)
    print(f"\nFull report saved to: {output_path}")
    
    # Overall assessment
    print("\n--- Overall Assessment ---")
    regression_passed = audit_results.get('regression', {}).get('passed', False)
    annotation_issues = audit_results.get('annotations', {}).get('total_issues', 0)
    schema_issues = len(audit_results.get('schema', {}).get('issues', []))
    
    print(f"Regression Test: {'✅ PASSED' if regression_passed else '❌ FAILED'}")
    print(f"Annotation Issues: {annotation_issues}")
    print(f"Schema Issues: {schema_issues}")
    
    if regression_passed and annotation_issues < 10 and schema_issues == 0:
        print("\n✅ RECOMMENDATION: Baseline is sufficiently reliable to proceed with Phase 3")
        print("   Action items:")
        print("   1. Fix {annotation_issues} annotation issues identified")
        print("   2. Re-run error attribution after annotation fixes")
        print("   3. Proceed with dataset expansion")
        return 0
    else:
        print("\n⚠️  RECOMMENDATION: Address issues before proceeding")
        if not regression_passed:
            print("   - CRITICAL: Regression test failed")
        if annotation_issues >= 10:
            print(f"   - HIGH: {annotation_issues} annotation issues need review")
        if schema_issues > 0:
            print(f"   - MEDIUM: {schema_issues} schema issues need resolution")
        return 1

if __name__ == '__main__':
    sys.exit(main())
