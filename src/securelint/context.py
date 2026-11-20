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

MAX_HOPS = 10
"""How many variables are followed one after the other (``a = b``, then
``b = c``...). The limit stops two variables that point at each other from
being followed for ever."""


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

    pieces: Mapping[ast.Name, tuple[ast.expr, ...]] = field(default_factory=dict)
    """For a variable given its value only with ``=`` and ``+=``, more than
    once, the right-hand side of each (see ``securelint.dataflow``)."""

    returns: Mapping[ast.Name, ast.expr] = field(default_factory=dict)
    """For the name of a function being called, what its one ``return``
    gives back (see ``securelint.dataflow``)."""

    project: "Mapping[str, tuple[ast.expr, FileContext] | None]" = field(
        default_factory=dict
    )
    """What the functions of every scanned file return, by full name such
    as ``"app.queries.find_user"``, with the context of the file that
    defines each one. ``None`` marks a name two files could both mean.
    Shared by all files of a scan and filled before any rule runs."""

    def value_of(self, node: ast.expr) -> ast.expr | None:
        """Return the expression a variable was given, if that is certain.

        For ``query`` in ``cursor.execute(query)`` this is the right-hand
        side of ``query = ...``. Returns ``None`` for anything that is not
        a variable, and for a variable with no single known value.
        """
        if isinstance(node, ast.Name):
            return self.values.get(node)
        return None

    def pieces_of(self, node: ast.expr) -> tuple[ast.expr, ...]:
        """Return every piece of text a variable can be made of, if known.

        After ``query = "SELECT ..."`` and ``query += f"... {name}"``, the
        two right-hand sides. Empty for anything else, and for a variable
        that also gets a value some other way.
        """
        if isinstance(node, ast.Name):
            return self.pieces.get(node, ())
        return ()

    def return_of(self, call: ast.Call) -> "tuple[ast.expr, FileContext] | None":
        """Return what a call gives back, when the function is known.

        For ``find_user(name)`` this is the expression of the one
        ``return`` in ``def find_user``, with the context of the file that
        defines it: this file, or another scanned file it was imported from
        (``from app.queries import find_user``, ``from .queries import
        find_user``, ``import queries`` then ``queries.find_user``).
        """
        if isinstance(call.func, ast.Name):
            returned = self.returns.get(call.func)
            if returned is not None:
                return returned, self
        # Only an imported name can lead to another file.
        written = dotted_name(call.func)
        if written is None or written.partition(".")[0] not in self.imports:
            return None
        name = self.qualified_name(call.func)
        if name is None:
            return None
        absolute = absolute_name(name, self.path)
        if absolute is None:
            return None
        return self.project.get(absolute)

    def qualified_name(self, node: ast.expr, hops: int = 0) -> str | None:
        """Return the real, full name of what an expression refers to.

        With ``import subprocess as sp``, the expression ``sp.run`` gives
        ``"subprocess.run"``. A name the file does not import is returned
        as written, which is right for built-ins such as ``eval``.

        A function kept in a variable is followed too: after
        ``run = os.system``, the expression ``run`` gives ``"os.system"``.

        Returns ``None`` when the expression is not a plain chain of names,
        for example ``get_module().run``.
        """
        name = dotted_name(node)
        if name is None:
            return None
        first, dot, rest = name.partition(".")

        # The chain starts with a variable given its value once: continue
        # from that value. "sp = subprocess" then "sp.run" is subprocess.run.
        start = node
        while isinstance(start, ast.Attribute):
            start = start.value
        value = self.value_of(start)
        if value is not None and hops < MAX_HOPS:
            real_start = self.qualified_name(value, hops + 1)
            if real_start is not None:
                return f"{real_start}{dot}{rest}"

        target = self.imports.get(first)
        if target is None:
            return name
        return f"{target}{dot}{rest}"


def module_parts(path: str) -> list[str]:
    """Return the module a file is, as its parts.

    ``"app/queries.py"`` is ``["app", "queries"]``; ``"app/__init__.py"``
    is the package itself, ``["app"]``.
    """
    parts = path.removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return parts


def absolute_name(name: str, path: str) -> str | None:
    """Turn a relative import, as kept in ``imports``, into a full name.

    In ``app/views.py``, ``".queries.find_user"`` (from ``from .queries
    import find_user``) is ``"app.queries.find_user"``. A name with no
    leading dot is returned as it is. ``None`` when the dots climb above
    the scanned directory.
    """
    level = len(name) - len(name.lstrip("."))
    if level == 0:
        return name
    package = module_parts(path)
    if not path.endswith("__init__.py"):
        package = package[:-1]
    climb = level - 1
    if climb > len(package):
        return None
    base = package[: len(package) - climb]
    rest = name[level:]
    return ".".join([*base, rest]) if base else rest


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
