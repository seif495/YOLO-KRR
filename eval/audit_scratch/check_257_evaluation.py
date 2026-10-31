import json

with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "000000000257.jpg":
            print(f"Image: {rec['image']}")
            eval_data = rec['evaluation']
            print(f"Evaluation: {json.dumps(eval_data, indent=2)}")
            break
