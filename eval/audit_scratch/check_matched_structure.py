import json

with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        matched = rec.get("matched_persons", [])
        if matched:
            print(f"Image: {rec['image']}")
            print(f"Matched persons ({type(matched)}): {len(matched)} matches")
            if matched:
                print("First match:")
                print(json.dumps(matched[0], indent=2))
            break
