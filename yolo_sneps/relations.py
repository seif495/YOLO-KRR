"""Image-plane spatial relations between detections.

Relations are viewer-centred: they say where boxes sit in the picture, not in the world.
Each direction comes from the geometry, never from the order YOLO reported the objects in.

    leftof(a, b)     a's box ends before b's box begins, horizontally.
    above(a, b)      a's box ends before b's box begins, vertically. In a road scene this
                     usually means "farther away", not "higher up".
    overlaps(a, b)   the boxes intersect. Emitted once per pair, smaller label first.
    near(a, b)       the boxes do not intersect, their bottom edges are at a similar height (within
                     0.75 x the taller box) and the horizontal gap is at most one box height:
                     the two stand close together at about the same distance from the camera.
                     Emitted once per pair, smaller label first.
    infrontof(a, b)  the boxes intersect and a's bottom edge is clearly lower in the image.
                     This is the ground-contact cue: of two objects standing on the same
                     ground, the one whose base appears lower is closer to the camera. It does
                     not hold for objects off the ground (a sign on a pole, a person on a bus),
                     and no depth fact is emitted when the two bases are within
                     `depth_margin` (a fraction of the image height) of each other.
"""


def relations(detections, image_height, depth_margin=0.02, pair_filter=None):
    """Return (predicate, subject, object) facts for every pair accepted by `pair_filter`."""
    margin = image_height * depth_margin
    facts = []
    for i, a in enumerate(detections):
        for b in detections[i + 1:]:
            if pair_filter is None or pair_filter(a, b):
                facts.extend(_pair_relations(a, b, margin))
    return facts


def focus_pairs(classes):
    """Pair filter keeping only pairs of one object in `classes` and one object outside it.

    Facts grow with the square of the number of objects and SNePS inference slows down
    sharply with KB size, so by default only pairs the rules can use (a person and something
    else) are asserted; person-person pairs are left out.
    """
    classes = set(classes)
    return lambda a, b: (a.cls in classes) != (b.cls in classes)


def _pair_relations(a, b, margin):
    ax1, ay1, ax2, ay2 = a.box
    bx1, by1, bx2, by2 = b.box
    facts = []
    if ax2 < bx1:
        facts.append(("leftof", a.label, b.label))
    elif bx2 < ax1:
        facts.append(("leftof", b.label, a.label))
    if ay2 < by1:
        facts.append(("above", a.label, b.label))
    elif by2 < ay1:
        facts.append(("above", b.label, a.label))
    first, second = sorted((a.label, b.label))
    if ax1 < bx2 and bx1 < ax2 and ay1 < by2 and by1 < ay2:
        facts.append(("overlaps", first, second))
        if ay2 - by2 > margin:
            facts.append(("infrontof", a.label, b.label))
        elif by2 - ay2 > margin:
            facts.append(("infrontof", b.label, a.label))
    else:
        height = max(ay2 - ay1, by2 - by1)
        gap = max(0.0, bx1 - ax2, ax1 - bx2)
        if abs(ay2 - by2) <= 0.75 * height and gap <= height:
            facts.append(("near", first, second))
    return facts
