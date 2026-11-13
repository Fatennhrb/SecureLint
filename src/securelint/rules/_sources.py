"""Find where a value comes from, when that place is known to be a user.

The rules report a dangerous call whenever its argument is not fixed. That
is a careful guess: the value might come from a user, or from the
program's own settings. This module removes the guess in the clearest
cases, by recognising the places where outside data enters a program::

    name = request.args["name"]      # a web request
    answer = input("Your name: ")    # typed at the keyboard
    path = sys.argv[1]               # the command line

When a value from one of these places reaches a dangerous call, the rule
can say so, and report with high confidence.
"""

import ast
from dataclasses import dataclass

from securelint.context import MAX_HOPS, FileContext
from securelint.model import Confidence

# Functions whose result is typed in by a user.
_SOURCE_CALLS = {"input": "input()"}

# Objects that hold what a user sent.
_SOURCE_OBJECTS = {"sys.argv": "sys.argv", "sys.stdin": "sys.stdin"}

# The parts of a web request that hold what the visitor sent. The names
# cover Flask (args, form...), Django (GET, POST...) and similar libraries.
_REQUEST_PARTS = frozenset(
    {
        "args", "form", "values", "cookies", "headers", "json", "data", "files",
        "get_json", "get_data", "GET", "POST", "COOKIES", "FILES", "body",
        "query_params",
    }
)  # fmt: skip

# Functions that turn any text into a harmless value, so what goes in no
# longer matters: int("1; DROP TABLE users") fails instead of passing on.
_CLEANERS = frozenset({"int", "float", "bool", "len", "shlex.quote"})


@dataclass(frozen=True, slots=True)
class Source:
    """A place where outside data enters the program."""

    description: str
    """How the place is written in the code, e.g. ``request.args``."""

    line: int
    """The line it is on."""


def find_source(node: ast.expr, context: FileContext) -> Source | None:
    """Return where the value of an expression comes from, if a user controls it.

    The expression is searched piece by piece, and variables are followed
    to the value they were given. Returns ``None`` when no known entry
    point is found, which does not mean the value is safe: only that
    SecureLint cannot tell.
    """
    seen: set[int] = set()
    waiting: list[tuple[ast.AST, int]] = [(node, 0)]
    while waiting:
        current, hops = waiting.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))

        if isinstance(current, ast.Name):
            value = context.value_of(current)
            if value is not None:
                if hops < MAX_HOPS:
                    waiting.append((value, hops + 1))
                continue

        description = _describe(current, context)
        if description is not None:
            return Source(description, getattr(current, "lineno", 1))
        is_cleaner = (
            isinstance(current, ast.Call)
            and context.qualified_name(current.func) in _CLEANERS
        )
        if is_cleaner:
            continue
        waiting.extend((child, hops) for child in ast.iter_child_nodes(current))
    return None


def with_source(
    message: str, confidence: Confidence, source: Source | None
) -> tuple[str, Confidence]:
    """Return a finding's message and confidence, adjusted for a known source.

    Without a source both are returned unchanged. With one, the message
    says where the value comes from and the confidence becomes high.
    """
    if source is None:
        return message, confidence
    note = f" Here the value comes from {source.description} on line {source.line}."
    return message + note, Confidence.HIGH


def _describe(node: ast.AST, context: FileContext) -> str | None:
    """Return a short name for ``node`` if it is an entry point for outside data."""
    if isinstance(node, ast.Call):
        name = context.qualified_name(node.func)
        return _SOURCE_CALLS.get(name) if name is not None else None
    # A name alone is an entry point after "from sys import argv".
    if isinstance(node, ast.Attribute | ast.Name):
        name = context.qualified_name(node)
        if name is None:
            return None
        if name in _SOURCE_OBJECTS:
            return _SOURCE_OBJECTS[name]
        # "request.args", also when Flask's request was imported:
        # "flask.request.args".
        owner, _, part = name.rpartition(".")
        if owner in {"request", "flask.request"} and part in _REQUEST_PARTS:
            return f"request.{part}"
    return None
