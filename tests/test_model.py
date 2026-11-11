"""Tests for the shared data model."""

import dataclasses
from typing import Any

import pytest

from securelint.model import Confidence, Finding, Severity


def make_finding(**overrides: Any) -> Finding:
    """Build a valid finding, replacing only the fields a test cares about."""
    fields: dict[str, Any] = {
        "rule_id": "SL101",
        "message": "Use of eval() on untrusted input.",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "path": "app/views.py",
        "line": 12,
        "column": 5,
    }
    fields.update(overrides)
    return Finding(**fields)


def test_finding_stores_its_fields() -> None:
    finding = make_finding()

    assert finding.rule_id == "SL101"
    assert finding.message == "Use of eval() on untrusted input."
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.path == "app/views.py"
    assert finding.line == 12
    assert finding.column == 5


def test_finding_cannot_be_modified() -> None:
    finding = make_finding()

    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.severity = Severity.LOW  # type: ignore[misc]


def test_equal_findings_compare_equal_and_hash_alike() -> None:
    # Later stages remove duplicates by putting findings in a set.
    assert make_finding() == make_finding()
    assert len({make_finding(), make_finding()}) == 1
    assert make_finding() != make_finding(line=13)


def test_severity_levels_are_ordered() -> None:
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert max(Severity.MEDIUM, Severity.CRITICAL, Severity.LOW) is Severity.CRITICAL


def test_confidence_levels_are_ordered() -> None:
    assert Confidence.LOW < Confidence.MEDIUM < Confidence.HIGH


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("rule_id", "", "rule_id must not be empty"),
        ("message", "", "message must not be empty"),
        ("path", "", "path must not be empty"),
        ("path", "app\\views.py", "path must use forward slashes"),
        ("line", 0, "line must be 1 or greater"),
        ("line", -3, "line must be 1 or greater"),
        ("column", 0, "column must be 1 or greater"),
    ],
)
def test_invalid_finding_is_rejected(
    field: str, value: object, expected_error: str
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        make_finding(**{field: value})


def test_first_line_and_first_column_are_valid() -> None:
    finding = make_finding(line=1, column=1)

    assert (finding.line, finding.column) == (1, 1)
