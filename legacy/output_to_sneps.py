import re

with open("yolo_output.txt", "r", encoding="utf-8") as file:
    text = file.read()

pattern = re.compile(
    r"\n\s*(.+?)\s+(\d+)\s+(\d+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)"
)

sneps_assertions = []

for match in pattern.finditer(text):
    class_name = match.group(1).strip().replace(" ", "_")
    images = match.group(2)
    instances = match.group(3)
    precision = match.group(4)
    recall = match.group(5)
    map50 = match.group(6)
    map5095 = match.group(7)

    sneps_assertions.append(f"(assert (class {class_name}))")
    sneps_assertions.append(f"(assert (images {class_name} {images}))")
    sneps_assertions.append(f"(assert (instances {class_name} {instances}))")
    sneps_assertions.append(f"(assert (precision {class_name} {precision}))")
    sneps_assertions.append(f"(assert (recall {class_name} {recall}))")
    sneps_assertions.append(f"(assert (map50 {class_name} {map50}))")
    sneps_assertions.append(f"(assert (map5095 {class_name} {map5095}))")
    sneps_assertions.append("")  # add newline for readability

with open("sneps_output.txt", "w", encoding="utf-8") as out_file:
    out_file.write("\n".join(sneps_assertions))

print("SNePS assertions saved to sneps_output.txt")
