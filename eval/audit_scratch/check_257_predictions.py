import json

with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "000000000257.jpg":
            print(f"Image: {rec['image']}")
            preds = rec['predictions']
            print(f"Predictions ({type(preds)}): {json.dumps(preds, indent=2)}")
            break
