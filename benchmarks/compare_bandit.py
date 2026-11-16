"""Compare SecureLint and Bandit on the annotated corpus.

Usage::

    pip install "bandit==1.9.4"
    python benchmarks/compare_bandit.py            # the summary table
    python benchmarks/compare_bandit.py --details  # every line they disagree on

The corpus in ``tests/corpus`` marks every dangerous line with
``# expect:`` or ``# missed:`` and a SecureLint rule id; a line without a
comment is safe. Both tools are scored against those comments the same way:

* found: a dangerous line the tool reports, for the same kind of problem,
* missed: a dangerous line it does not report,
* false alarm: a line it reports that is not dangerous for that kind.

Lines are compared by statement: a call written over several lines counts
once, whichever of its lines a tool names (Bandit often names the line of
the string or of ``shell=True``, SecureLint the first line of the call).

Bandit marks each finding with a confidence. A second total keeps only its
medium and high confidence findings, as a team that filters out the low
ones would see it.

Only the five kinds of problems both tools look for are compared. Bandit
checks that make another claim (an import of ``pickle``, a subprocess call
without a shell) are listed apart and not counted against it.

The corpus was written while building SecureLint's rules, so it favours
SecureLint: read the numbers as a check on the same examples, not as a
verdict on which tool is better.
"""

import argparse
import ast
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from securelint.engine import scan
from securelint.rules import ALL_RULES

CORPUS = Path(__file__).parent.parent / "tests" / "corpus"

KINDS = {
    "SL101": "Code execution (eval, exec)",
    "SL102": "Shell command injection",
    "SL103": "Unsafe deserialization",
    "SL104": "Hard-coded secret",
    "SL105": "SQL injection",
}

# Each Bandit check, mapped to the kind of problem it reports.
BANDIT_KINDS = {
    "B102": "SL101",  # exec_used
    "B307": "SL101",  # eval
    "B602": "SL102",  # subprocess with shell=True
    "B604": "SL102",  # any other call with shell=True
    "B605": "SL102",  # os.system and other calls through a shell
    "B301": "SL103",  # pickle and similar loaders
    "B302": "SL103",  # marshal
    "B506": "SL103",  # yaml.load
    "B105": "SL104",  # hard-coded password string
    "B106": "SL104",  # hard-coded password as an argument
    "B107": "SL104",  # hard-coded password as a default value
    "B608": "SL105",  # SQL built from strings
}

_ANNOTATION = re.compile(r"#\s*(expect|missed):\s*(SL\d+(?:\s*,\s*SL\d+)*)")

Case = tuple[str, int, str]
"""A file name, a line number and a kind of problem (a SecureLint rule id)."""


def statement_starts(path: Path) -> dict[int, int]:
    """Map each line of a file to the first line of its innermost statement."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    spans = sorted(
        (
            (node.end_lineno or node.lineno) - node.lineno,
            node.lineno,
            node.end_lineno or node.lineno,
        )
        for node in ast.walk(tree)
        if isinstance(node, ast.stmt)
    )
    starts: dict[int, int] = {}
    # Smallest statements first: a line keeps the innermost one.
    for _, first, last in spans:
        for line in range(first, last + 1):
            starts.setdefault(line, first)
    return starts


def by_statement(corpus: Path, cases: Iterable[Case]) -> set[Case]:
    """Move every case to the first line of its statement."""
    starts = {path.name: statement_starts(path) for path in corpus.glob("*.py")}
    return {(name, starts[name].get(line, line), kind) for name, line, kind in cases}


def dangerous_lines(corpus: Path) -> set[Case]:
    """Return the lines the corpus marks as dangerous, with their kind."""
    cases = set()
    for path in sorted(corpus.glob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            for _, rule_ids in _ANNOTATION.findall(line):
                for rule_id in rule_ids.split(","):
                    cases.add((path.name, number, rule_id.strip()))
    return cases


def securelint_cases(corpus: Path) -> set[Case]:
    """Return what SecureLint reports on the corpus."""
    result = scan(corpus, ALL_RULES)
    return {
        (Path(finding.path).name, finding.line, finding.rule_id)
        for finding in result.findings
    }


def bandit_cases(
    corpus: Path, *, confident_only: bool = False
) -> tuple[set[Case], Counter[str]]:
    """Return what Bandit reports, and how often its other checks fired.

    With ``confident_only``, findings Bandit itself marks as low confidence
    are left out.
    """
    try:
        completed = subprocess.run(  # noqa: S603 (Python itself, fixed arguments)
            [sys.executable, "-m", "bandit", "-r", str(corpus), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        report = json.loads(completed.stdout)
    except (OSError, ValueError) as error:
        raise SystemExit(f"cannot run Bandit: {error}") from None
    if "results" not in report:
        raise SystemExit("cannot run Bandit: is it installed? pip install bandit")

    cases: set[Case] = set()
    others: Counter[str] = Counter()
    for item in report["results"]:
        if confident_only and item["issue_confidence"] == "LOW":
            continue
        kind = BANDIT_KINDS.get(item["test_id"])
        if kind is None:
            others[f"{item['test_id']} {item['test_name']}"] += 1
        else:
            cases.add((Path(item["filename"]).name, item["line_number"], kind))
    return cases, others


def score(found: set[Case], dangerous: set[Case], kind: str) -> tuple[int, int, int]:
    """Return found, missed and false alarms for one kind of problem."""
    reported = {case for case in found if case[2] == kind}
    expected = {case for case in dangerous if case[2] == kind}
    return (
        len(reported & expected),
        len(expected - reported),
        len(reported - expected),
    )


def table(securelint: set[Case], bandit: set[Case], dangerous: set[Case]) -> list[str]:
    """Return the comparison as a Markdown table."""
    rows = [
        "| Kind of problem | Dangerous lines "
        "| SecureLint found | missed | false alarms "
        "| Bandit found | missed | false alarms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    totals = [0] * 7
    for kind, name in KINDS.items():
        ours = score(securelint, dangerous, kind)
        theirs = score(bandit, dangerous, kind)
        size = sum(1 for case in dangerous if case[2] == kind)
        numbers = [size, *ours, *theirs]
        totals = [total + number for total, number in zip(totals, numbers, strict=True)]
        rows.append(f"| {name} ({kind}) | " + " | ".join(map(str, numbers)) + " |")
    rows.append("| **Total** | " + " | ".join(f"**{n}**" for n in totals) + " |")
    return rows


def disagreements(
    securelint: set[Case], bandit: set[Case], dangerous: set[Case]
) -> Iterable[str]:
    """Describe every line where the two tools give different answers."""
    for case in sorted(securelint ^ bandit):
        name, line, kind = case
        who = "only SecureLint" if case in securelint else "only Bandit"
        truth = "dangerous" if case in dangerous else "safe"
        yield f"{name}:{line}  {kind}  {who} reports it; the line is {truth}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare SecureLint and Bandit.")
    parser.add_argument(
        "--details", action="store_true", help="list every line they disagree on"
    )
    args = parser.parse_args(argv)

    dangerous = by_statement(CORPUS, dangerous_lines(CORPUS))
    securelint = by_statement(CORPUS, securelint_cases(CORPUS))
    raw_bandit, others = bandit_cases(CORPUS)
    bandit = by_statement(CORPUS, raw_bandit)
    confident = by_statement(CORPUS, bandit_cases(CORPUS, confident_only=True)[0])

    print("\n".join(table(securelint, bandit, dangerous)))
    found, missed, false_alarms = (
        sum(numbers)
        for numbers in zip(
            *(score(confident, dangerous, kind) for kind in KINDS), strict=True
        )
    )
    print(
        f"\nBandit with medium and high confidence only: found {found}, "
        f"missed {missed}, false alarms {false_alarms}."
    )
    print("\nBandit findings not compared (they make another claim):")
    for check, count in sorted(others.items()):
        print(f"  {check}: {count}")
    if args.details:
        print("\nLines where the two tools disagree:")
        for line in disagreements(securelint, bandit, dangerous):
            print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
