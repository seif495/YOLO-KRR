# YOLO Segmentation & SNePSLOG Integration

## Overview

This project is the vision half of a YOLO + SNePS system. It detects objects with YOLO, works out where they are relative to each other in the picture, and asserts those facts into a SNePS knowledge base. Rules then decide which people are in a dangerous position, such as a pedestrian in front of a car.

The SNePS side comes from [SNePSpaCy](https://github.com/numberw8835/SNePSpaCy). It translates English into SNePSLOG and talks to SNePS through its `sneps_wrapper/sneps_api.py`. This project does not send English to SNePSpaCy's translator. Its sentences mostly do not survive translation: "left of"/"right of" and the second object are lost, and class information never appears. Instead, it emits **typed SNePSLOG** directly and uses SNePSpaCy only to run SNePS:

```
isa(person_1, person).            one fact per detected object
infrontof(person_1, car_1).       spatial relations between objects
ask(dangerous(?x)).               rules in kb/danger.snepslog answer this
```

## Components

- **`yolo_sneps/`**: the YOLO → SNePS bridge (`python -m yolo_sneps`).
  - `scene.py`: YOLO boxes → detections with SNePSLOG-safe labels (`stop sign` → `stop_sign_1`).
    - Applies a confidence threshold.
    - Drops duplicate boxes: any box overlapping a more confident one with IoU ≥ 0.85, or a same-class box lying ≥ 95% inside a more confident one with IoU ≥ 0.6.
    - Numbers each class's objects left to right.
  - `relations.py`: `leftof`, `above`, `overlaps` and `infrontof` between detections. Directions come from the geometry, never from detection order.
  - `snepslog.py`: SNePSLOG statements, checks on them, the rules file, and parsing of SNePS answers.
  - `backends.py`: how SNePS is run.
    - `snepspacy` uses SNePSpaCy's wrapper (Linux/WSL).
    - `allegro` runs the Windows SNePS 2.7 build headless.
- **`kb/danger.snepslog`**: class hierarchy and danger rules in SNePSLOG.
- **`legacy/`**: earlier scripts and the original Prolog-syntax `danger_kb.lisp`, kept for reference. None of them is used by the bridge; `legacy/README.md` says what each one did and why it was replaced.

## Requirements

- **Python:** 3.12. The versions in `requirements.txt` are the ones the project was developed with.
- **Model weights:** not in the repository. On the first run, Ultralytics downloads `yolo11n-seg.pt` (about 6 MB, AGPL-3.0) into the current directory, so that run needs internet access. `--model PATH` uses weights you already have.
- **SNePS 2.7**, one of:
  - **Windows:** the SNePS 2.7 Windows build from the [SNePS Research Group](https://cse.buffalo.edu/sneps/), i.e. the folder containing `Sneps-2.7.exe`. Its REPL is a GUI console, so the bridge runs it headless. Nothing in that folder needs editing.
  - **Linux/WSL:** a [SNePSpaCy](https://github.com/numberw8835/SNePSpaCy) checkout, which bundles a 32-bit Linux SNePS build.
    - On 64-bit Ubuntu/WSL this needs `sudo apt install libc6-i386`.
    - Clone it with git inside the Linux/WSL filesystem (e.g. `~/SNePSpaCy`). Run from a Windows drive (`/mnt/c/...`), SNePS stops with `couldn't find exe location`, and Git for Windows would also convert `Sneps-2.7.0.sh` to CRLF line endings, which breaks it.

Install the Python dependencies:
```
pip install -r requirements.txt
```

## Usage

Run these from the repository root, the folder that contains `yolo_sneps/`:

```
# Windows: headless SNePS
python -m yolo_sneps img_3.png img_2.png --backend allegro --sneps-dir "C:\path\to\Sneps-2.7.0-Windows"

# Linux/WSL: SNePS through SNePSpaCy
python -m yolo_sneps img_3.png img_2.png --backend snepspacy --snepspacy-dir ~/SNePSpaCy

# No SNePS: only write the SNePSLOG transcripts
python -m yolo_sneps img_3.png
```

For each image, the bridge writes two files to `outputs/` (or `--out`). `<name>` is the image file name without its extension, and a number is appended when two inputs share a name.
- `<name>.snepslog`: the full SNePSLOG transcript (rules, facts and query). Replay it in a SNePSLOG session with `demo "outputs/img_3.snepslog"`. The path must be in quotes, and the transcript starts with `clearkb`, so it replaces whatever is in the knowledge base.
- `<name>.json`: the detections, the facts and `dangerous`, the objects SNePS found dangerous.
  - `dangerous` is `null` when no backend ran, or when SNePS reported an error or timed out: a rejected statement or a timeout can hide an answer. The console then says `UNKNOWN`, any partial answer is under `partial_answers`, and the exit status is 1.

Options:

| Option | Meaning |
|---|---|
| `--sneps-dir` / `--snepspacy-dir` | Where SNePS or SNePSpaCy is. Can also be set as `SNEPS_DIR` / `SNEPSPACY_DIR`. |
| `--model` | YOLO weights; default `yolo11n-seg.pt`. |
| `--conf` | Minimum detection confidence; default 0.25. |
| `--imgsz` | Inference size; default 640. Larger finds smaller, farther objects. |
| `--focus` | Classes whose pairs with *other* objects get relation facts; default `person`. |
| `--all-pairs` | Relation facts for every pair. SNePS slows down sharply as the knowledge base grows, so this can be slow on busy scenes. |
| `--rules` | Rules file; default `kb/danger.snepslog`. |
| `--timeout` | SNePS seconds per image; default 300. With `snepspacy` it applies to each SNePS call. |
| `--out` | Output folder; default `outputs`. |

Run the tests:
```
python -m unittest discover -s tests
```

To include the end-to-end tests against the Windows SNePS build, set `SNEPS_DIR` first:
```
PowerShell:  $env:SNEPS_DIR = "C:\path\to\Sneps-2.7.0-Windows"; python -m unittest discover -s tests
cmd:         set SNEPS_DIR=C:\path\to\Sneps-2.7.0-Windows
             python -m unittest discover -s tests
Git Bash:    SNEPS_DIR="C:\path\to\Sneps-2.7.0-Windows" python -m unittest discover -s tests
```

On Linux/WSL, `SNEPSPACY_DIR=~/SNePSpaCy python -m unittest discover -s tests` runs the end-to-end test through SNePSpaCy instead.

## What the relations mean, and their limits

Relations describe the picture, not the world:
- **`above`** in a road scene usually means "farther away".
- **`infrontof(a, b)`** means the boxes overlap and `a`'s base is lower in the image. For two objects standing on the same ground, that object is nearer the camera. No depth fact is emitted when the two bases are within 2% of the image height.
  - "Nearer the camera than an overlapping vehicle" is not "in the vehicle's path". People on a pavement beside a parked bus are flagged too (all four in `bus.jpg`).
  - The cue does not hold for things off the ground, such as a sign on a pole or a person on a bus.
- **Single still images:** there is no motion, speed or tracking.
- **Classes:** YOLO's COCO classes have no road, crosswalk or sidewalk.
- **Detection confidence** is used only as a threshold.
- **Duplicates:** a duplicate box that the rules above don't catch makes one person count twice.
- **Detection range:** the default nano model at 640 px misses small or distant pedestrians, so `"dangerous": []` does not mean a scene is safe.

## License

This project is licensed under the MIT License.

---

For questions or contributions, please open an issue or pull request.
