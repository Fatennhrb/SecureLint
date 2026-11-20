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

A variable that the function does not assign at all is looked for the way
Python does it: in the functions around it, then at the top of the file.
So ``TABLE = "users"`` written once at the top of a file is known inside
every function of that file.

Two more answers are kept apart from these certain values, for the rules
that only need to know what text a value can contain:

* The pieces of a name given its value only with ``=`` and ``+=``::

      query = "SELECT * FROM users"
      query += f" WHERE name = '{name}'"

  ``query`` has no single value, but every piece of text it can hold is
  known: the two right-hand sides.

* What a function returns, when it has a single ``return``::

      def find_user(name):
          return f"SELECT * FROM users WHERE name = '{name}'"

      cursor.execute(find_user(name))

  ``find_user`` must be defined once with ``def`` in the same file, with no
  decorator (which could replace it), and must not be a generator.

  Functions defined this way at the top of a file are also listed by name,
  so a call from another file of the project can be followed to them.
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

    parent: "_Scope | None" = None
    """The scope this one is written inside; ``None`` for the module."""

    is_class: bool = False
    """A class body. Its variables are not visible from its methods."""

    pieces: dict[str, list[ast.expr]] = field(default_factory=dict)
    """For each name, the right-hand side of every ``=`` and ``+=`` that
    gives it a value."""

    unpieced: set[str] = field(default_factory=set)
    """Names also given a value some other way (a parameter, a loop, an
    import, ``-=``...), so their pieces are not all known."""

    functions: dict[str, ast.FunctionDef] = field(default_factory=dict)
    """The functions defined here with ``def``, by name."""

    returns: list[ast.Return] = field(default_factory=list)
    """The ``return`` statements of this function itself, not of the
    functions inside it."""

    is_generator: bool = False
    """The function contains ``yield``: calling it does not run its body."""

    def bind(
        self, name: str, value: ast.expr | None = None, piece: ast.expr | None = None
    ) -> None:
        self.bindings.setdefault(name, []).append(value)
        if piece is None:
            self.unpieced.add(name)
        else:
            self.pieces.setdefault(name, []).append(piece)


@dataclass(frozen=True, slots=True)
class OtherValues:
    """What is known about variables and calls that have no single value."""

    pieces: dict[ast.Name, tuple[ast.expr, ...]] = field(default_factory=dict)
    """For a variable given its value only with ``=`` and ``+=``, more than
    once, the right-hand side of each."""

    returns: dict[ast.Name, ast.expr] = field(default_factory=dict)
    """For the name of a function being called, the expression of its one
    ``return``. Its parameters, read inside that expression, have no
    known value."""

    exported: dict[str, ast.expr] = field(default_factory=dict)
    """For each function defined at the top of the file that the same
    rules allow following, by name, the expression of its ``return``.
    Other files that import it can follow it too."""


def analyse(
    tree: ast.Module,
) -> tuple[list[ast.AST], dict[ast.Name, ast.expr], OtherValues]:
    """Walk a file once; return all its nodes and the values of its variables.

    The first result holds every node except the small markers that say
    whether a name is read or written (``ast.Load``, ``ast.Store``,
    ``ast.Del``), which no rule inspects.

    The second result maps each place a variable is read to the expression
    it was given. Only reads with exactly one certain value are in it.

    The third result holds the less certain answers described at the top
    of this module: the pieces of a variable, and what a function returns.

    Both results come from the same walk because walking the tree is the
    most expensive part of a scan: doing it twice made scans twice as slow.
    """
    nodes: list[ast.AST] = [tree]
    scopes: list[_Scope] = []
    # Names declared "global" or "nonlocal" are changed from another
    # function, so no single scope shows everything that happens to them.
    shared: set[str] = set()

    # The scope of each function, to find its "return" statements.
    scope_of: dict[ast.AST, _Scope] = {}

    waiting: list[tuple[ast.AST, _Scope | None]] = [(tree, None)]
    while waiting:
        scope_node, parent = waiting.pop()
        scope = _Scope(parent=parent, is_class=isinstance(scope_node, ast.ClassDef))
        for parameter in _parameters(scope_node):
            scope.bind(parameter)
        _read_scope(scope_node, scope, shared, nodes, waiting)
        scopes.append(scope)
        scope_of[scope_node] = scope

    values: dict[ast.Name, ast.expr] = {}
    other = OtherValues()
    for scope in scopes:
        for read in scope.reads:
            if read.id in shared:
                continue
            owner = _owner(read.id, scope)
            if owner is None:
                continue
            bound = owner.bindings[read.id]
            if len(bound) == 1:
                if bound[0] is not None:
                    values[read] = bound[0]
                    continue
                returned = _single_return(owner.functions.get(read.id), scope_of)
                if returned is not None:
                    other.returns[read] = returned
            elif read.id not in owner.unpieced:
                other.pieces[read] = tuple(owner.pieces[read.id])

    # The first scope read is the file itself.
    module = scopes[0]
    for name, function in module.functions.items():
        if name in shared or len(module.bindings[name]) != 1:
            continue
        returned = _single_return(function, scope_of)
        if returned is not None:
            other.exported[name] = returned
    return nodes, values, other


def _owner(name: str, scope: _Scope) -> _Scope | None:
    """Find the scope that gives a name read in ``scope`` its value.

    The scopes are tried in the order Python uses: the scope itself, then
    each scope around it. The first one that gives the name a value
    decides, even when that value is not certain.
    """
    current: _Scope | None = scope
    while current is not None:
        # A method does not see the variables of its class body; only code
        # written directly in the class body does.
        if (current is scope or not current.is_class) and name in current.bindings:
            return current
        current = current.parent
    return None


def _single_return(
    function: ast.FunctionDef | None, scope_of: dict[ast.AST, _Scope]
) -> ast.expr | None:
    """Return the expression a function returns, if it has exactly one."""
    if function is None or function.decorator_list:
        return None
    scope = scope_of[function]
    if scope.is_generator or len(scope.returns) != 1:
        return None
    return scope.returns[0].value


def collect_values(tree: ast.Module) -> dict[ast.Name, ast.expr]:
    """Map each variable read in a file to the expression it was given."""
    return analyse(tree)[1]


def _read_scope(
    scope_node: ast.AST,
    scope: _Scope,
    shared: set[str],
    nodes: list[ast.AST],
    waiting: list[tuple[ast.AST, _Scope | None]],
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
    # The same for "name += value": not the name's value, only a piece.
    extended: dict[ast.Name, ast.expr] = {}

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
                # ":=", "del x". Of these, only "+=" adds a known piece.
                value = assigned.get(node)
                piece = value if value is not None else extended.get(node)
                scope.bind(node.id, value, piece)
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
        elif kind is ast.AugAssign:
            assert isinstance(node, ast.AugAssign)  # noqa: S101
            if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
                extended[node.target] = node.value
        elif kind is ast.Return:
            assert isinstance(node, ast.Return)  # noqa: S101
            scope.returns.append(node)
        elif kind is ast.Yield or kind is ast.YieldFrom:
            scope.is_generator = True
        elif kind in _OTHER_BINDINGS:
            _bind_other(node, scope, shared)

        elif kind in _SCOPE_TYPES:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                scope.bind(node.name)
            # Not "async def": calling one only creates a coroutine.
            if isinstance(node, ast.FunctionDef):
                scope.functions[node.name] = node
            waiting.append((node, scope))

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
