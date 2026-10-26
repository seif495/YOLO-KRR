# Legacy scripts

Earlier experiments, kept for reference and for the history of the thesis. Nothing in `yolo_sneps/` uses them, and they keep the bugs listed below. Run them from the repository root (e.g. `python legacy/seg_without_depth.py`), since they open images by relative path.

| File | What it did | Why it is not used |
|---|---|---|
| `segmentation.py` | The first end-to-end attempt: YOLO segmentation, pairwise relations, facts sent to SNePS, then `(find dangerous)`. | It starts plain SBCL, which never loads SNePS, so nothing is asserted or inferred; its "inferred" output is Lisp error text. `(find dangerous)` is not a valid query. The occlusion window takes the vertical union instead of the intersection, and masks are stretched from the letterboxed resolution. |
| `seg_without_depth.py` | Prints English relation sentences ("person_1 is completely to the left of car_1"). | Box containment is used as a depth cue, so one pair can be both "in front of" and "behind". Relations are emitted in one direction only, in detection order. |
| `segmentation_test.py`, `seg_test_results.py` | Mask-overlap occlusion experiment (`OcclusionResolver`). | Overlap is symmetric, so it asserts both "A in front of B" and "B in front of A". |
| `new_segmentation.py`, `no_train.py`, `old_main.py` | Detection and segmentation demos on `bus.jpg`; `old_main.py` also fine-tunes on coco128. | Demos only. The 3-epoch fine-tune on coco128 made the model worse, and nothing uses its weights. |
| `output_to_sneps.py` | Turns the validation table into `(assert ...)` forms. | It reads a file nothing writes (`yolo_output.txt`), emits forms SNePS does not accept, and encodes model metrics rather than scene facts. |
| `danger_kb.lisp` | The original danger rules. | Prolog syntax, which SNePS cannot load. `kb/danger.snepslog` replaces it. |
| `sneps_wrapper/sneps_api.py` | An early copy of SNePSpaCy's wrapper, ported to wexpect for Windows. | It does not work: the Windows SNePS REPL is a GUI console, so `init()` times out, and its error handlers fail because wexpect has no `exceptions` module. The bridge uses SNePSpaCy's own wrapper instead. |

The images these scripts expect (img_3.png, zidane.jpg, ...) were removed from the repository because their licenses are unknown. Use your own images, or the Ultralytics samples at https://ultralytics.com/images/zidane.jpg and https://ultralytics.com/images/bus.jpg.
