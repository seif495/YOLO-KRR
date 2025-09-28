# YOLO Segmentation & SNEPSLOG Integration

## Overview

This project provides an end-to-end pipeline for object detection and segmentation using YOLO, with spatial relationship analysis and translation into SNEPSLOG format for knowledge representation.

## Components

- **`seg_without_depth.py`**  
  Handles object detection and segmentation using YOLO.  
  - Loads a YOLO segmentation model.
  - Processes images to detect objects and generate segmentation masks.
  - Analyzes spatial relationships (e.g., left, right, above, below, in front of, behind) between detected objects.
  - Visualizes results with overlays and labels.

- **`sneps_api.py`**  
  Translates YOLO detection results and spatial relationships into SNEPSLOG statements.  
  - Converts object and relationship data into SNEPSLOG syntax for use in knowledge-based systems.

## Requirements

- Python 3.8+
- [Ultralytics YOLO](https://github.com/ultralytics/ultralytics)
- OpenCV (`cv2`)
- NumPy
- Matplotlib

Install dependencies:
```
pip install ultralytics opencv-python numpy matplotlib
```

## Usage

1. **Object Detection & Segmentation**  
   Run `seg_without_depth.py` to process an image and visualize detected objects and their spatial relationships.

2. **SNEPSLOG Translation**  
   Use `sneps_api.py` to convert YOLO results into SNEPSLOG format for further reasoning or integration with SNePS.

## Example

- Input: Image file (e.g., `zidane.jpg`)
- Output:  
  - Visualization of detected objects and their relationships.
  - SNEPSLOG statements representing the scene.

## License

This project is licensed under the MIT License.

---

For questions or contributions, please open an issue or pull request.
