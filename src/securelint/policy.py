"""Decide which findings stop a change and which are only warnings.

Without a policy every finding blocks: one uncertain guess stops a team
as much as a certain SQL injection, and teams answer that by turning the
tool off. A policy says where the line is::

    [tool.securelint.policy]
    block-severity = "high"
    block-confidence = "medium"

A finding then blocks only when it is at least that severe *and* the rule
is at least that sure. Every other finding is still reported, as a
warning, and does not fail the scan.

The policy only sorts findings that the scan produced. It runs after the
rules, the silencing comments and the baseline, and it never removes a
finding from the report.
"""

from dataclasses import dataclass, replace

from securelint.engine import ScanResult
from securelint.model import Confidence, Finding, Severity


@dataclass(frozen=True, slots=True)
class Policy:
    """Where the line between "blocks" and "warning" is.

    The defaults are the lowest levels, so by default everything blocks:
    a project only becomes more lenient by asking for it.
    """

    block_severity: Severity = Severity.LOW
    """A finding less severe than this is a warning."""

    block_confidence: Confidence = Confidence.LOW
    """A finding the rule is less sure of than this is a warning."""

    def blocks(self, finding: Finding) -> bool:
        """Return True if ``finding`` must be fixed before the change passes."""
        return (
            finding.severity >= self.block_severity
            and finding.confidence >= self.block_confidence
        )


def apply_policy(result: ScanResult, policy: Policy) -> ScanResult:
    """Move the findings that do not block out of ``result.findings``.

    They are kept in ``result.warnings``, so reports still show them.
    """
    return replace(
        result,
        findings=tuple(f for f in result.findings if policy.blocks(f)),
        warnings=tuple(f for f in result.findings if not policy.blocks(f)),
    )
