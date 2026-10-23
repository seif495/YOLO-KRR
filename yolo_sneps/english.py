"""The English route: describe a scene in English and let SNePSpaCy translate it to SNePSLOG.

Each detection and relation becomes a sentence ("car_1 is a car.", "person_1 is in front of
car_1."), which SNePSpaCy's semantic parser turns into its event-style SNePSLOG: a state constant
whose subject is given by reference(), with the class as an attribute of that state:

    car_1 is a car.  =>  state(s1), reference(s1, car_1), attribute(s1, c1), car(c1)

kb/danger_english.snepslog holds the danger rules written against that shape. Only the relations
the rules use are described. Needs a SNePSpaCy checkout and spaCy with en_core_web_trf.
"""
import sys
import warnings
from pathlib import Path

SENTENCES = {"infrontof": "{} is in front of {}.", "near": "{} is near {}."}


def sentences(detections, facts, confident=0.5):
    """English sentences for the detections' classes and confidence, and for the relations above."""
    lines = [f"{d.label} is a {d.cls.replace('_', ' ')}." for d in detections]
    lines += [f"{d.label} is visible." for d in detections if d.conf >= confident]
    lines += [SENTENCES[p].format(x, y) for p, x, y in facts if p in SENTENCES]
    return lines


class Translator:
    def __init__(self, snepspacy_dir):
        root = str(Path(snepspacy_dir).resolve())
        if root not in sys.path:
            sys.path.append(root)  # appended, so YOLO-KRR's own modules win any name clash
        from semantic_parser.core import snepslog
        from nlp_utils.spaCy_helpers import TranscriptionWarning
        self.engine = snepslog()
        self.warning = TranscriptionWarning

    def statements(self, lines):
        """SNePSLOG statements for the sentences, and (sentence, message) for parts left untranslated."""
        statements, errors = [], []
        for line in lines:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", self.warning)
                translation = self.engine.transcribe(line)
            errors += [(line, str(w.message)) for w in caught if issubclass(w.category, self.warning)]
            # A scene sentence translates to a conjunction of ground atoms; assert them one by one.
            statements += [part.strip() for part in translation.split(" and ")]
        return statements, errors
