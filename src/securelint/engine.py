"""Run detection rules over a project.

The engine connects the other parts: it finds the files, parses each one,
and shows every node of the syntax tree to the rules that asked for it.
"""

import ast
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from securelint.context import FileContext, collect_imports
from securelint.discovery import discover
from securelint.model import Finding
from securelint.parsing import ParsedFile, ParseFailure, parse


class Rule(ABC):
    """Base class for one detection rule.

    A rule says which kinds of syntax-tree node it wants to see, and the
    engine calls ``check`` once for each such node.
    """

    node_types: ClassVar[tuple[type[ast.AST], ...]]
    """The node classes this rule inspects, e.g. ``(ast.Call,)``."""

    @abstractmethod
    def check(self, node: ast.AST, context: FileContext) -> Iterable[Finding]:
        """Return the findings for one node (usually none or one).

        ``context`` describes the file the node is in: its path, and how to
        turn a name used in the file into the real name behind it.
        """


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one scan produced."""

    findings: tuple[Finding, ...]
    """Sorted by path, line, column, then rule."""

    failures: tuple[ParseFailure, ...]
    """Files that could not be scanned. They are reported, never hidden:
    a file nobody looked at must not count as a clean file."""

    files_scanned: int
    """Number of files that were parsed and checked."""


def scan(target: Path, rules: Sequence[Rule]) -> ScanResult:
    """Scan the file or directory ``target`` with ``rules``.

    Raises ``FileNotFoundError`` if ``target`` does not exist.
    """
    # Built once per scan: for each node class, the rules that want it.
    rules_by_node_type: dict[type[ast.AST], list[Rule]] = {}
    for rule in rules:
        for node_type in rule.node_types:
            rules_by_node_type.setdefault(node_type, []).append(rule)

    findings: list[Finding] = []
    failures: list[ParseFailure] = []
    files_scanned = 0
    for source_file in discover(target):
        result = parse(source_file)
        if isinstance(result, ParseFailure):
            failures.append(result)
            continue
        files_scanned += 1
        findings.extend(_check_file(result, rules_by_node_type))

    findings.sort(key=_sort_key)
    return ScanResult(
        findings=tuple(findings),
        failures=tuple(failures),
        files_scanned=files_scanned,
    )


def _check_file(
    parsed_file: ParsedFile, rules_by_node_type: dict[type[ast.AST], list[Rule]]
) -> list[Finding]:
    """Walk one syntax tree a single time, whatever the number of rules.

    Each rule walking the tree by itself would make the scan slower with
    every rule added. Here the tree is walked once and each node is handed
    to the rules interested in its type.
    """
    # The nodes are kept in a list because they are needed twice: first to
    # learn the file's imports, then to run the rules. An import can be
    # written below the code that uses it (inside a function, for example),
    # so the imports must all be known before the first rule runs.
    nodes = list(ast.walk(parsed_file.tree))
    context = FileContext(
        path=parsed_file.source_file.relative_path,
        imports=collect_imports(nodes),
    )
    findings: list[Finding] = []
    for node in nodes:
        for rule in rules_by_node_type.get(type(node), ()):
            findings.extend(rule.check(node, context))
    return findings


def _sort_key(finding: Finding) -> tuple[str, int, int, str]:
    return (finding.path, finding.line, finding.column, finding.rule_id)
