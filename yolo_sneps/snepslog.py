"""SNePSLOG text for a scene, and parsing of SNePS answers."""
import re
from pathlib import Path

_WFF_PREFIX = re.compile(r"wff\d+!:\s*", re.IGNORECASE)


def scene_statements(detections, facts):
    """SNePSLOG statements for a scene, without the trailing '.' (sneps_api.inform adds it)."""
    statements = [f"isa({d.label}, {d.cls})" for d in detections]
    statements += [f"{p}({x}, {y})" for p, x, y in facts]
    return statements


def check_statement(statement):
    """Why `statement` must not be sent to SNePS, or None if it is fine.

    An unbalanced statement makes the SNePSLOG reader swallow everything after it, and SNePS
    misreads non-ASCII text, so these are caught before anything is sent.
    """
    if not statement.strip():
        return "empty statement"
    if not statement.isascii() or '"' in statement:
        return "contains non-ASCII characters or a double quote"
    depth = {"(": 0, "{": 0}
    for ch in statement:
        if ch in "({":
            depth[ch] += 1
        elif ch in ")}":
            depth["(" if ch == ")" else "{"] -= 1
            if min(depth.values()) < 0:
                return "unbalanced brackets"
    if any(depth.values()):
        return "unbalanced brackets"
    return None


def load_rules(path):
    """Statements from a .snepslog file: one per line, ';' starts a comment, trailing '.' removed.

    Raises ValueError naming the line of any statement check_statement rejects.
    """
    statements = []
    lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    for number, line in enumerate(lines, 1):
        line = line.split(";", 1)[0].strip()
        if not line:
            continue
        statement = line[:-1].rstrip() if line.endswith(".") else line
        problem = check_statement(statement)
        if problem:
            raise ValueError(f"{path}, line {number}: {problem}: {line}")
        statements.append(statement)
    return statements


def parse_answers(lines, predicate="dangerous"):
    """Lower-cased arguments of `predicate(arg)` answers, in natural order (person_2 before person_10).

    Accepts output from either SNePS build: the Windows image prints 'WFF15!:  DANGEROUS(PERSON_1)',
    and SNePSpaCy's ask() only strips a lower-case 'wffN!:' prefix.
    """
    pattern = re.compile(rf"{re.escape(predicate)}\((\w+)\)", re.IGNORECASE)
    found = set()
    for line in lines:
        match = pattern.fullmatch(_WFF_PREFIX.sub("", line.strip()))
        if match:
            found.add(match.group(1).lower())
    return sorted(found, key=_natural_key)


def _natural_key(label):
    stem, _, number = label.rpartition("_")
    return (stem, int(number)) if number.isdigit() else (label, 0)
