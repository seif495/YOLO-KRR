import json

with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "000000000257.jpg":
            print(f"Image: {rec['image']}")
            print(f"Summary: TP={rec['summary']['tp']}, FP={rec['summary']['fp']}, FN={rec['summary']['fn']}")
            print(f"Alert: TP={rec['summary']['alert']['tp']}, FP={rec['summary']['alert']['fp']}, FN={rec['summary']['alert']['fn']}")
            break
