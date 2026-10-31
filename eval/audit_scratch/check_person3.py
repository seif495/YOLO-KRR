import json

data = json.load(open('eval/results/baseline_error_attribution_v2.json'))
print(f"Total errors: {len(data['errors'])}")
print(f"\nImages with errors:")
images = set(e['image'] for e in data['errors'])
for img in sorted(images):
    print(f"  {img}")

print(f"\nVan image errors:")
van_errors = [e for e in data['errors'] if 'van' in e['image'].lower()]
for e in van_errors:
    print(f"  {e['image']}: {e.get('person_label', 'N/A')} ({e['type']}, {e['category']})")

print(f"\nAll error categories:")
for e in data['errors']:
    print(f"  {e['image']}: {e.get('person_label', 'N/A')} ({e['type']}, {e['category']})")
