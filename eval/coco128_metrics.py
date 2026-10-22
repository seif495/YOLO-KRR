"""Per-class box and mask metrics of the segmentation model on coco128.

    python eval/coco128_metrics.py [--model yolo11n-seg.pt] [--imgsz 640]

Caution: coco128 is the first 128 images of COCO train2017, the data the pretrained weights were
trained on, and its train and val splits are the same images. These numbers therefore overstate
accuracy on new images; eval/evaluate.py measures the project on its own test set.
Writes eval/results/coco128-<model>-<imgsz>.txt. (Replaces main.py, whose table repeated the
overall metrics in every class row.)
"""
import argparse
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default=str(ROOT / "yolo11n-seg.pt"))
    parser.add_argument("--imgsz", type=int, default=640)
    args = parser.parse_args()

    from ultralytics import YOLO
    from ultralytics.utils import SETTINGS

    model = YOLO(args.model)
    with tempfile.TemporaryDirectory() as tmp:  # keep validation plots out of the project
        metrics = model.val(data="coco128-seg.yaml", imgsz=args.imgsz, plots=False, verbose=False, project=tmp)

    # Images and instances per class, counted from the label files (the metrics object does not carry them).
    labels = Path(SETTINGS["datasets_dir"]) / "coco128-seg" / "labels" / "train2017"
    instances, images, total_images = Counter(), Counter(), 0
    for f in labels.glob("*.txt"):
        if not (labels.parent.parent / "images" / "train2017" / f"{f.stem}.jpg").exists():
            continue  # a few label files in coco128 have no image; validation skips them too
        total_images += 1
        classes = [int(line.split()[0]) for line in f.read_text().splitlines() if line.strip()]
        instances.update(classes)
        images.update(set(classes))

    lines = [f"Model {Path(args.model).name}, imgsz {args.imgsz}, data coco128-seg (training data of the weights)", "",
             f"{'Class':<15}{'Images':>7}{'Inst.':>7}  {'Box P':>7}{'Box R':>7}{'mAP50':>7}{'50-95':>7}"
             f"  {'Mask P':>7}{'Mask R':>7}{'mAP50':>7}{'50-95':>7}"]
    for i, c in enumerate(metrics.box.ap_class_index):
        box, mask = metrics.box.class_result(i), metrics.seg.class_result(i)
        lines.append(f"{model.names[c]:<15}{images[c]:>7}{instances[c]:>7}  "
                     + "".join(f"{v:>7.3f}" for v in box) + "  " + "".join(f"{v:>7.3f}" for v in mask))
    lines += ["", f"{'all':<15}{total_images:>7}{sum(instances.values()):>7}  "
              + "".join(f"{v:>7.3f}" for v in metrics.box.mean_results()) + "  "
              + "".join(f"{v:>7.3f}" for v in metrics.seg.mean_results())]
    out = ROOT / "eval" / "results"
    out.mkdir(exist_ok=True)
    path = out / f"coco128-{Path(args.model).stem}-{args.imgsz}.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:3] + lines[-1:]))
    print(f"written to {path}")


if __name__ == "__main__":
    main()
