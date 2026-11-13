"""Follow a variable back to the value it was given.

A rule that looks at one line cannot judge this code::

    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)

The second line only says ``query``. This module finds, for each place a
variable is read, the expression that was assigned to it, so the rule can
look at that expression instead.

It only answers when the answer is certain: the variable is assigned
exactly once in the function (or class body, or module) where it is read.
A variable assigned twice, changed with ``+=``, filled by a loop or
received as a parameter has no single value, and is left alone. Giving no
answer is always safe; giving a wrong one could hide a real problem.
"""

import ast
from dataclasses import dataclass, field

# Each of these has its own variables.
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

# Statements that give a name a value without an ordinary assignment.
_OTHER_BINDINGS = frozenset(
    {
        ast.Import,
        ast.ImportFrom,
        ast.Global,
        ast.Nonlocal,
        ast.ExceptHandler,
        ast.MatchAs,
        ast.MatchStar,
        ast.MatchMapping,
    }
)


@dataclass(slots=True)
class _Scope:
    """What happens to variables inside one function, class body or module."""

    bindings: dict[str, list[ast.expr | None]] = field(default_factory=dict)
    """For each name, one entry for every place that gives it a value: the
    assigned expression, or ``None`` when the value cannot be known (a
    parameter, a loop variable, an import...)."""

    reads: list[ast.Name] = field(default_factory=list)
    """Every place where a variable is read."""

    def bind(self, name: str, value: ast.expr | None = None) -> None:
        self.bindings.setdefault(name, []).append(value)


def analyse(tree: ast.Module) -> tuple[list[ast.AST], dict[ast.Name, ast.expr]]:
    """Walk a file once; return all its nodes and the values of its variables.

    The first result holds every node except the small markers that say
    whether a name is read or written (``ast.Load``, ``ast.Store``,
    ``ast.Del``), which no rule inspects.

    The second result maps each place a variable is read to the expression
    it was given. Only reads with exactly one certain value are in it.

    Both results come from the same walk because walking the tree is the
    most expensive part of a scan: doing it twice made scans twice as slow.
    """
    nodes: list[ast.AST] = [tree]
    scopes: list[_Scope] = []
    # Names declared "global" or "nonlocal" are changed from another
    # function, so no single scope shows everything that happens to them.
    shared: set[str] = set()

    waiting: list[ast.AST] = [tree]
    while waiting:
        scope_node = waiting.pop()
        scope = _Scope()
        for parameter in _parameters(scope_node):
            scope.bind(parameter)
        _read_scope(scope_node, scope, shared, nodes, waiting)
        scopes.append(scope)

    values: dict[ast.Name, ast.expr] = {}
    for scope in scopes:
        for read in scope.reads:
            if read.id in shared:
                continue
            bound = scope.bindings.get(read.id)
            if bound is not None and len(bound) == 1 and bound[0] is not None:
                values[read] = bound[0]
    return nodes, values


def collect_values(tree: ast.Module) -> dict[ast.Name, ast.expr]:
    """Map each variable read in a file to the expression it was given."""
    return analyse(tree)[1]


def _read_scope(
    scope_node: ast.AST,
    scope: _Scope,
    shared: set[str],
    nodes: list[ast.AST],
    waiting: list[ast.AST],
) -> None:
    """Walk one scope: record its nodes, its bindings and its reads.

    Each node is visited before its children. An inner function or class
    is added to ``waiting``, to be walked later as a scope of its own.
    Comprehensions are walked as part of the scope: their loop variables
    then count as extra bindings, which can only make an answer less
    likely, never wrong.
    """
    # The value of each plain "name = value" target, filled just before
    # the target itself is visited.
    assigned: dict[ast.Name, ast.expr] = {}

    # A list of statements, or one expression for a lambda.
    body = getattr(scope_node, "body", [])
    stack: list[ast.AST] = list(body) if isinstance(body, list) else [body]
    while stack:
        node = stack.pop()
        nodes.append(node)
        kind = type(node)

        if kind is ast.Name:
            assert isinstance(node, ast.Name)  # noqa: S101 (tells mypy the type)
            if type(node.ctx) is ast.Load:
                scope.reads.append(node)
            else:
                # Every other way of storing into a name lands here with no
                # known value: "+=", "for x in", "with ... as x", "a, b =",
                # ":=", "del x".
                scope.bind(node.id, assigned.get(node))
        elif kind is ast.Assign:
            assert isinstance(node, ast.Assign)  # noqa: S101
            # "a = b = value" gives the same value to both.
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target] = node.value
        elif kind is ast.AnnAssign:
            assert isinstance(node, ast.AnnAssign)  # noqa: S101
            if isinstance(node.target, ast.Name) and node.value is not None:
                assigned[node.target] = node.value
        elif kind in _OTHER_BINDINGS:
            _bind_other(node, scope, shared)

        elif kind in _SCOPE_TYPES:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                scope.bind(node.name)
            waiting.append(node)

        fields = _FIELDS_TO_FOLLOW.get(kind)
        if fields is None:
            fields = _FIELDS_TO_FOLLOW[kind] = _fields_to_follow(kind)
        for field_name in fields:
            child = getattr(node, field_name, None)
            if type(child) is list:
                for item in child:
                    if isinstance(item, ast.AST):
                        stack.append(item)
            elif isinstance(child, ast.AST):
                stack.append(child)


_SCOPE_TYPES = frozenset(_SCOPES)

# For each kind of node, the fields that can hold other nodes. Worked out
# once per kind, because this is asked for every node of every file.
_FIELDS_TO_FOLLOW: dict[type[ast.AST], tuple[str, ...]] = {}


def _fields_to_follow(kind: type[ast.AST]) -> tuple[str, ...]:
    skipped = {
        # Says whether a name is read or written. It is already used above
        # through ``node.ctx``, and no rule needs it as a node of its own.
        "ctx",
    }
    if kind in _SCOPE_TYPES:
        # The body of an inner function or class is its own scope.
        # Everything else about it (decorators, default values, base
        # classes) runs in the scope that contains it.
        skipped.add("body")
    return tuple(name for name in kind._fields if name not in skipped)


def _bind_other(node: ast.AST, scope: _Scope, shared: set[str]) -> None:
    """Record a name that gets its value from something other than ``=``."""
    if isinstance(node, ast.Global | ast.Nonlocal):
        shared.update(node.names)
    elif isinstance(node, ast.Import | ast.ImportFrom):
        for alias in node.names:
            scope.bind(alias.asname or alias.name.partition(".")[0])
    elif isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar):
        if node.name is not None:
            scope.bind(node.name)
    elif isinstance(node, ast.MatchMapping) and node.rest is not None:
        scope.bind(node.rest)


def _parameters(scope_node: ast.AST) -> list[str]:
    """Return the parameter names of a function; their values come from callers."""
    if not isinstance(scope_node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
        return []
    arguments = scope_node.args
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return [parameter.arg for parameter in parameters]
