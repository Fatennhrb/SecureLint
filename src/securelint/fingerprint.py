"""Give each finding an identity that survives edits elsewhere in the file.

A finding is reported at a line number, but a line number is a poor
identity: add one line at the top of a file and every finding below it
"moves", though nothing about it changed.

The fingerprint is built from what does not move:

* the rule,
* the file's path,
* the text of the reported line, without the spaces around it,
* and, when that exact line appears several times in the file, which of
  them this is (first, second...).

So adding or removing code elsewhere, or changing the indentation, keeps
the fingerprint. Editing the reported line itself changes it, which is
right: it is different code, and worth looking at again.
"""

import hashlib
from collections import Counter
from collections.abc import Sequence
from dataclasses import replace

from securelint.model import Finding

FINGERPRINT_LENGTH = 16
"""Characters kept from the hash. 16 hexadecimal characters are 64 bits:
far more than needed to keep the findings of one project apart, and short
enough to read and to store."""


_BYTE_ORDER_MARK = b"\xef\xbb\xbf"


def add_fingerprints(findings: Sequence[Finding], source: bytes) -> list[Finding]:
    """Return the findings of one file, in the same order, with fingerprints.

    ``source`` is the content of the file the findings are in.
    """
    # Some editors start a file with an invisible mark (a UTF-8 byte order
    # mark). It is not part of the first line's code, so it is removed:
    # otherwise a finding on line 1 would change identity as soon as a line
    # was added above it.
    lines = source.removeprefix(_BYTE_ORDER_MARK).splitlines()
    # The file is used as bytes, exactly as it is on disk, so its encoding
    # never has to be guessed.
    texts = [
        lines[finding.line - 1].strip() if finding.line <= len(lines) else b""
        for finding in findings
    ]

    # Identical lines are numbered from the top of the file, whatever
    # order the findings arrived in.
    in_file_order = sorted(
        range(len(findings)),
        key=lambda index: (findings[index].line, findings[index].column),
    )
    seen: Counter[tuple[str, bytes]] = Counter()
    fingerprints = [""] * len(findings)
    for index in in_file_order:
        finding = findings[index]
        key = (finding.rule_id, texts[index])
        fingerprints[index] = _hash(finding, texts[index], seen[key])
        seen[key] += 1

    return [
        replace(finding, fingerprint=fingerprint)
        for finding, fingerprint in zip(findings, fingerprints, strict=True)
    ]


def _hash(finding: Finding, text: bytes, occurrence: int) -> str:
    # The parts are separated by a byte that cannot appear in a rule id, a
    # path or a line of code, so two different findings can never be glued
    # into the same input.
    parts = [
        finding.rule_id.encode(),
        finding.path.encode(),
        text,
        str(occurrence).encode(),
    ]
    digest = hashlib.sha256(b"\0".join(parts)).hexdigest()
    return digest[:FINGERPRINT_LENGTH]
