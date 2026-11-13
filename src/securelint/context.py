"""What a rule knows about the file it is checking.

The main job here is following imports. Code can reach the same function
under many names::

    import subprocess as sp          # sp.run(...)
    from os import system            # system(...)
    from os import system as sh      # sh(...)

A rule that compared the written name with ``"os.system"`` would miss all
of these. ``FileContext.qualified_name`` turns each one back into the real
name, so every rule compares against a single spelling.
"""

import ast
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FileContext:
    """Information about one file, given to every rule that checks it."""

    path: str
    """The file's relative path, to put in each ``Finding``."""

    imports: Mapping[str, str]
    """Each imported name in the file, mapped to what it really refers to,
    e.g. ``{"sp": "subprocess", "system": "os.system"}``."""

    values: Mapping[ast.Name, ast.expr] = field(default_factory=dict)
    """For each place a variable is read, the expression it was given, when
    there is exactly one (see ``securelint.dataflow``)."""

    def value_of(self, node: ast.expr) -> ast.expr | None:
        """Return the expression a variable was given, if that is certain.

        For ``query`` in ``cursor.execute(query)`` this is the right-hand
        side of ``query = ...``. Returns ``None`` for anything that is not
        a variable, and for a variable with no single known value.
        """
        if isinstance(node, ast.Name):
            return self.values.get(node)
        return None

    def qualified_name(self, node: ast.expr) -> str | None:
        """Return the real, full name of what an expression refers to.

        With ``import subprocess as sp``, the expression ``sp.run`` gives
        ``"subprocess.run"``. A name the file does not import is returned
        as written, which is right for built-ins such as ``eval``.

        Returns ``None`` when the expression is not a plain chain of names,
        for example ``get_module().run``.
        """
        name = dotted_name(node)
        if name is None:
            return None
        first, dot, rest = name.partition(".")
        target = self.imports.get(first)
        if target is None:
            return name
        return f"{target}{dot}{rest}"


def dotted_name(node: ast.expr) -> str | None:
    """Return a chain of names as written, e.g. ``"os.path.join"``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def collect_imports(nodes: Iterable[ast.AST]) -> dict[str, str]:
    """Build the ``imports`` mapping from the nodes of one file.

    Imports are collected from the whole file, including those inside a
    function. A name is treated as meaning the same thing everywhere in the
    file; the rare file that gives one name two meanings is not handled.
    """
    imports: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    # import os.path as p   ->  p means os.path
                    imports[alias.asname] = alias.name
                else:
                    # import os.path        ->  only the name "os" is created
                    top_level = alias.name.partition(".")[0]
                    imports[top_level] = top_level
        elif isinstance(node, ast.ImportFrom):
            # "from . import x" has level 1 and no module. The leading dots
            # are kept, so a project's own module never looks like a
            # standard one: "from .tools import system" is not os.system.
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                if alias.name == "*":
                    # The imported names are not written in this file.
                    continue
                separator = "" if module.endswith(".") else "."
                imports[alias.asname or alias.name] = f"{module}{separator}{alias.name}"
    return imports
