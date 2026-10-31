import json

data = json.load(open('eval/results/baseline_error_attribution_v2.json'))
person3 = [e for e in data['errors'] if e.get('image') == 'women_in_front_of_parked_van.jpg' and e.get('person_label') == 'person_3'][0]
print(json.dumps(person3, indent=2))
