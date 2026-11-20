"""Run detection rules over a project.

The engine connects the other parts: it finds the files, parses each one,
and shows every node of the syntax tree to the rules that asked for it.
"""

import ast
from abc import ABC, abstractmethod
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from securelint.context import FileContext, collect_imports, module_parts
from securelint.dataflow import analyse
from securelint.discovery import SourceFile, discover
from securelint.fingerprint import add_fingerprints
from securelint.model import Finding
from securelint.parsing import ParsedFile, ParseFailure, parse
from securelint.suppressions import Silenced, apply_comments


class Rule(ABC):
    """Base class for one detection rule.

    A rule says which kinds of syntax-tree node it wants to see, and the
    engine calls ``check`` once for each such node.
    """

    rule_id: ClassVar[str]
    """The rule's short name, e.g. ``"SL101"``, used in reports and settings."""

    title: ClassVar[str] = ""
    """A few words saying what the rule reports, for reports that list the
    rules (SARIF). Empty for a rule that has none."""

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

    silenced: tuple[Silenced, ...] = ()
    """Findings hidden by a comment in the code. They are kept apart, not
    thrown away, so every report can show what was hidden and why."""

    known: tuple[Finding, ...] = ()
    """Findings listed in the project's baseline file: problems that were
    already there when the project accepted them (see ``securelint.baseline``).
    A scan itself leaves this empty."""

    warnings: tuple[Finding, ...] = ()
    """Findings that the project's policy reports without blocking (see
    ``securelint.policy``). A scan itself leaves this empty."""

    base: str = ""
    """Where the scanned directory is, counted from the top of the project,
    e.g. ``"src"``; empty when it is the top itself, or when the top is not
    known. Paths in findings are relative to the scanned directory, so a
    report that needs paths from the top of the project (SARIF) puts this
    in front of them."""

    outside_change: tuple[Finding, ...] = ()
    """Findings on lines that the change being checked did not touch (see
    ``securelint.changes``). A scan itself leaves this empty."""

    explanations: tuple[tuple[Finding, str], ...] = ()
    """Explanations written by an AI for some of the findings and warnings
    (see ``securelint.explain``). They are shown next to the finding and
    change nothing else. A scan itself leaves this empty."""


def scan(
    target: Path,
    rules: Sequence[Rule],
    exclude: Collection[Path] = (),
    root: Path | None = None,
) -> ScanResult:
    """Scan the file or directory ``target`` with ``rules``.

    ``exclude`` holds full paths of files and directories to leave out.

    ``root`` is the top directory of the project, as a full path. It only
    affects fingerprints: they are built from each file's path under
    ``root``, so they do not depend on which part of the project is scanned.

    Raises ``FileNotFoundError`` if ``target`` does not exist.
    """
    # Built once per scan: for each node class, the rules that want it.
    rules_by_node_type: dict[type[ast.AST], list[Rule]] = {}
    for rule in rules:
        for node_type in rule.node_types:
            rules_by_node_type.setdefault(node_type, []).append(rule)

    running = {rule.rule_id for rule in rules}

    findings: list[Finding] = []
    silenced: list[Silenced] = []
    failures: list[ParseFailure] = []

    # First every file is read, so that a call to a function defined in
    # another file can be followed whatever order the files come in.
    project: dict[str, tuple[ast.expr, FileContext] | None] = {}
    prepared: list[tuple[ParsedFile, list[ast.AST], FileContext]] = []
    for source_file in discover(target, exclude):
        result = parse(source_file)
        if isinstance(result, ParseFailure):
            failures.append(result)
            continue
        prepared.append(_prepare_file(result, project))

    for result, nodes, context in prepared:
        source_file = result.source_file
        kept, hidden = apply_comments(
            _check_file(nodes, context, rules_by_node_type),
            result.source,
            source_file.relative_path,
            running,
        )
        if kept or hidden:
            # Kept and silenced findings are numbered together, so silencing
            # one of two identical lines does not change the other's identity.
            marked = add_fingerprints(
                [*kept, *(item.finding for item in hidden)],
                result.source,
                _path_in_project(source_file, root),
            )
            kept = marked[: len(kept)]
            hidden = [
                Silenced(finding, item.reason)
                for finding, item in zip(marked[len(kept) :], hidden, strict=True)
            ]
        findings.extend(kept)
        silenced.extend(hidden)

    findings.sort(key=_sort_key)
    silenced.sort(key=lambda item: _sort_key(item.finding))
    return ScanResult(
        findings=tuple(findings),
        failures=tuple(failures),
        files_scanned=len(prepared),
        silenced=tuple(silenced),
        base=_base(target, root),
    )


def _base(target: Path, root: Path | None) -> str:
    """Return the scanned directory's path from the top of the project."""
    if root is None:
        return ""
    directory = target.resolve()
    if not directory.is_dir():
        directory = directory.parent
    if not directory.is_relative_to(root):
        return ""
    base = directory.relative_to(root).as_posix()
    return "" if base == "." else base


def _prepare_file(
    parsed_file: ParsedFile,
    project: dict[str, tuple[ast.expr, FileContext] | None],
) -> tuple[ParsedFile, list[ast.AST], FileContext]:
    """Walk one syntax tree a single time, and learn what the rules need.

    The nodes are kept in a list because they are needed twice: first to
    learn the file's imports, then to run the rules. An import can be
    written below the code that uses it (inside a function, for example),
    so the imports must all be known before the first rule runs.

    The functions the file defines at the top are added to ``project``,
    under every name another file could import them by.
    """
    path = parsed_file.source_file.relative_path
    nodes, values, other = analyse(parsed_file.tree)
    context = FileContext(
        path=path,
        imports=collect_imports(nodes),
        values=values,
        pieces=other.pieces,
        returns=other.returns,
        project=project,
    )
    # "app/queries.py" can be imported as app.queries or, when the scan
    # starts above the package (a "src" folder), as queries.
    parts = module_parts(path)
    for name, returned in other.exported.items():
        for start in range(len(parts)):
            full_name = ".".join([*parts[start:], name])
            # Two files that could both be meant: follow neither.
            project[full_name] = None if full_name in project else (returned, context)
    return parsed_file, nodes, context


def _check_file(
    nodes: list[ast.AST],
    context: FileContext,
    rules_by_node_type: dict[type[ast.AST], list[Rule]],
) -> list[Finding]:
    """Hand each node of a file to the rules interested in its type.

    Each rule walking the tree by itself would make the scan slower with
    every rule added. Here the tree is walked once and each node is handed
    to the rules interested in its type.
    """
    findings: list[Finding] = []
    for node in nodes:
        for rule in rules_by_node_type.get(type(node), ()):
            findings.extend(rule.check(node, context))
    return findings


def _path_in_project(source_file: SourceFile, root: Path | None) -> str:
    """Return a file's path counted from the top of the project.

    Falls back to the path shown in reports when the project's top is not
    known, or the file is not under it.
    """
    if root is not None:
        full_path = source_file.path.resolve()
        if full_path.is_relative_to(root):
            return full_path.relative_to(root).as_posix()
    return source_file.relative_path


def _sort_key(finding: Finding) -> tuple[str, int, int, str]:
    return (finding.path, finding.line, finding.column, finding.rule_id)
