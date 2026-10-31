import json

with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "000000000257.jpg":
            print(f"Image: {rec['image']}")
            for det in rec["detections"]:
                if det["class"] == "person":
                    kb_facts = det.get("kb_facts", [])
                    infrontof = [f for f in kb_facts if len(f)==3 and f[0]=="infrontof"]
                    print(f"  {det['label']}: {len(kb_facts)} facts, {len(infrontof)} infrontof")
            break
