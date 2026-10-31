import json

with open("eval/results/v1_frozen/baseline_instrumented_detailed.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        if rec["image"] == "000000000257.jpg":
            print(f"Image: {rec['image']}")
            facts = rec.get('facts', [])
            print(f"Image-level facts: {len(facts)}")
            
            # Filter infrontof facts
            infrontof = [f for f in facts if 'infrontof' in str(f).lower()]
            print(f"infrontof facts: {len(infrontof)}")
            for f in infrontof[:10]:
                print(f"  {f}")
            
            # Check for person_2, person_4, person_9, person_10
            for person_label in ["person_2", "person_4", "person_9", "person_10"]:
                person_facts = [f for f in facts if person_label in str(f)]
                print(f"\n{person_label}: {len(person_facts)} facts")
                for pf in person_facts[:3]:
                    print(f"  {pf}")
            break
