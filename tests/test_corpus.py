"""Check the real rules against the annotated examples in ``tests/corpus``.

Each example file marks its interesting lines with a comment:

    # expect: SL101        dangerous, and SecureLint reports it
    # missed: SL101        dangerous, but SecureLint does not report it yet
    # false-alarm: SL101   safe, but SecureLint reports it anyway

The last two are written down on purpose. They keep the numbers honest,
and when a rule improves, a test here fails until the comment is updated.
"""

import re
from collections import Counter
from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.rules import ALL_RULES

CORPUS = Path(__file__).parent / "corpus"
CORPUS_FILES = sorted(CORPUS.glob("*.py"))

_ANNOTATION = re.compile(r"#\s*(expect|missed|false-alarm):\s*(SL\d+(?:\s*,\s*SL\d+)*)")

# For each rule: detected, missed, false alarms. The same numbers are in
# tests/corpus/README.md and in the main README; keep the three in step.
TOTALS = {
    "SL101": (7, 1, 1),
    "SL102": (10, 3, 2),
    "SL103": (12, 2, 1),
    "SL104": (11, 5, 2),
    "SL105": (10, 2, 2),
}

Case = tuple[int, str]
"""A line number and a rule id."""


def read_annotations(path: Path) -> dict[str, list[Case]]:
    """Return the annotated cases of one file, grouped by kind."""
    cases: dict[str, list[Case]] = {"expect": [], "missed": [], "false-alarm": []}
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        for kind, rule_ids in _ANNOTATION.findall(line):
            for rule_id in rule_ids.split(","):
                cases[kind].append((number, rule_id.strip()))
    return cases


def test_the_corpus_is_found() -> None:
    assert len(CORPUS_FILES) >= 5


@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda path: path.name)
def test_file_is_reported_exactly_as_annotated(path: Path) -> None:
    cases = read_annotations(path)

    result = scan(path, ALL_RULES)

    assert result.failures == ()
    reported = sorted((finding.line, finding.rule_id) for finding in result.findings)
    # A "missed" line is in neither list, so it must not be reported.
    assert reported == sorted(cases["expect"] + cases["false-alarm"])


def test_totals_match_the_published_numbers() -> None:
    counts = {kind: Counter[str]() for kind in ("expect", "missed", "false-alarm")}
    for path in CORPUS_FILES:
        for kind, cases in read_annotations(path).items():
            counts[kind].update(rule_id for _, rule_id in cases)

    rule_ids = sorted(set().union(*counts.values()))
    totals = {
        rule_id: (
            counts["expect"][rule_id],
            counts["missed"][rule_id],
            counts["false-alarm"][rule_id],
        )
        for rule_id in rule_ids
    }

    assert totals == TOTALS
