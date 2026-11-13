"""Tests for following a variable back to the value it was given."""

import ast
from pathlib import Path

import pytest

from securelint.dataflow import analyse, collect_values


def value_of(code: str, name: str) -> str | None:
    """Return the value found for the last place ``name`` is read in ``code``.

    The value is given back as source text, or ``None`` when the variable
    has no single known value there.
    """
    tree = ast.parse(code)
    values = collect_values(tree)
    reads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
    ]
    last = max(reads, key=lambda node: (node.lineno, node.col_offset))
    value = values.get(last)
    return None if value is None else ast.unparse(value)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        # One assignment, in a function, a module or a class body.
        ("def f():\n    x = 'ls'\n    use(x)\n", "'ls'"),
        ("x = 'ls'\nuse(x)\n", "'ls'"),
        ("class A:\n    x = 'ls'\n    y = use(x)\n", "'ls'"),
        ("def f(a):\n    x = 'ping ' + a\n    use(x)\n", "'ping ' + a"),
        ("def f():\n    x: str = 'ls'\n    use(x)\n", "'ls'"),
        ("async def f():\n    x = 'ls'\n    await use(x)\n", "'ls'"),
        # Only the direct value is given; following a chain is the caller's job.
        ("def f():\n    a = 'ls'\n    x = a\n    use(x)\n", "a"),
        # Both names get the same value.
        ("def f():\n    y = x = 'ls'\n    use(x)\n", "'ls'"),
        # The only assignment is below the read: still the only possible value.
        ("def f():\n    for _ in range(2):\n        use(x)\n        x = 'ls'\n", "'ls'"),  # noqa: E501
        # Read inside a comprehension or a nested block of the same function.
        ("def f(items):\n    x = 'ls'\n    return [use(x) for _ in items]\n", "'ls'"),
        ("def f(ok):\n    x = 'ls'\n    if ok:\n        use(x)\n", "'ls'"),
    ],
)  # fmt: skip
def test_variable_with_one_assignment_has_a_value(code: str, expected: str) -> None:
    assert value_of(code, "x") == expected


@pytest.mark.parametrize(
    "code",
    [
        # Never assigned here.
        "use(x)\n",
        "def f(x):\n    use(x)\n",
        "def f(*x):\n    use(x)\n",
        "def f(**x):\n    use(x)\n",
        "def f(*, x):\n    use(x)\n",
        "f = lambda x: use(x)\n",
        # Assigned more than once.
        "def f():\n    x = 'a'\n    x = 'b'\n    use(x)\n",
        "def f(ok):\n    if ok:\n        x = 'a'\n    else:\n        x = 'b'\n    use(x)\n",  # noqa: E501
        "def f(x):\n    x = 'a'\n    use(x)\n",
        "def f():\n    x = 'a'\n    x += b\n    use(x)\n",
        # Given a value in a way that cannot be read from the source.
        "def f(items):\n    for x in items:\n        use(x)\n",
        "def f():\n    with open(p) as x:\n        use(x)\n",
        "def f():\n    x, y = pair()\n    use(x)\n",
        "def f():\n    if (x := read()):\n        use(x)\n",
        "def f():\n    import x\n    use(x)\n",
        "def f():\n    from m import y as x\n    use(x)\n",
        "def f():\n    try:\n        pass\n    except E as x:\n        use(x)\n",
        "def f():\n    def x():\n        pass\n    use(x)\n",
        "def f():\n    class x:\n        pass\n    use(x)\n",
        "def f(v):\n    match v:\n        case [x]:\n            use(x)\n",
        "def f(v):\n    match v:\n        case {**x}:\n            use(x)\n",
        "def f(v):\n    match v:\n        case [*x]:\n            use(x)\n",
        "def f(v):\n    match v:\n        case str() as x:\n            use(x)\n",
        # One assignment plus something else.
        "def f(items):\n    x = 'a'\n    for x in items:\n        pass\n    use(x)\n",
        "def f(items):\n    x = 'a'\n    return [use(x) for x in items]\n",
        "def f():\n    x = 'a'\n    del x\n    use(x)\n",
        "def f(items):\n    x = 'a'\n    [x := i for i in items]\n    use(x)\n",
        # Assigned in another function.
        "def g():\n    x = 'a'\n\ndef f():\n    use(x)\n",
        "def f():\n    def g():\n        x = 'a'\n    use(x)\n",
        # Changed from another function.
        "x = 'a'\n\ndef g():\n    global x\n    x = read()\n\nuse(x)\n",
        "def f():\n    x = 'a'\n    def g():\n        nonlocal x\n        x = read()\n    use(x)\n",  # noqa: E501
        # A default value is computed outside the function.
        "def f(a=x):\n    x = 'a'\n",
    ],
)  # fmt: skip
def test_variable_without_one_certain_value_has_none(code: str) -> None:
    assert value_of(code, "x") is None


def test_a_variable_of_the_module_is_not_followed_into_a_function_yet() -> None:
    # The value is certain here too, but looking outside the function where
    # the variable is read is not done yet.
    code = "x = 'ls'\n\ndef f():\n    use(x)\n"

    assert value_of(code, "x") is None


def test_each_read_gets_its_own_answer() -> None:
    code = "def f():\n    x = 'a'\n    use(x)\n\ndef g(x):\n    use(x)\n"
    tree = ast.parse(code)

    values = collect_values(tree)

    assert [(name.lineno, ast.unparse(value)) for name, value in values.items()] == [
        (3, "'a'")
    ]


def test_deeply_nested_code_does_not_hit_the_recursion_limit() -> None:
    # 2000 nested lists: far deeper than Python lets a function call itself.
    code = "x = 'a'\nuse(x, " + "[" * 150 + "]" * 150 + ")\n"
    blocks = "".join("    " * depth + "if a:\n" for depth in range(60))
    code += (
        "def f():\n"
        + "".join("    " + line + "\n" for line in blocks.splitlines())
        + "    " * 61
        + "y = 1\n"
    )

    assert collect_values(ast.parse(code))


EVERY_KIND_OF_CODE = """
import os
from typing import Any

@decorator(option=1)
class Base(Parent, metaclass=Meta):
    field: int = 0

    @property
    def value(self) -> int:
        return self.field

async def fetch(url: str, *args: Any, retries: int = 3, **options: Any) -> bytes:
    async with session.get(url) as response:
        async for chunk in response:
            yield chunk
    try:
        data = await read()
    except (OSError, ValueError) as error:
        raise RuntimeError("failed") from error
    else:
        pass
    finally:
        close()
    return [x for x in data if x] + [y async for y in stream]

def classify(item, /, flag=False, *, key=lambda v: v.name):
    match item:
        case {"kind": kind, **rest}:
            return kind
        case [first, *others] if first:
            return others
        case Point(x=0) | None:
            return 0
        case _:
            pass
    while (count := next_count()) > 0:
        count -= 1
    squares = {n: n ** 2 for n in range(10)}
    unique = {n for n in squares}
    total = sum(n for n in unique)
    text = f"{total!r:>{width}}"
    del squares[0]
    global counter
    assert total, "empty"
    with open(a) as f, open(b) as g:
        pass
    return total if flag else -total
"""


def full_walk(tree: ast.Module) -> list[ast.AST]:
    """Return what ``ast.walk`` gives, without the read/write markers."""
    return [node for node in ast.walk(tree) if not isinstance(node, ast.expr_context)]


@pytest.mark.parametrize(
    "code",
    [EVERY_KIND_OF_CODE, "", "x = 1\n", "lambda a, b=c: (a, b)\n"],
    ids=["every kind of code", "empty file", "one line", "lambda"],
)
def test_analyse_returns_the_same_nodes_as_a_full_walk(code: str) -> None:
    tree = ast.parse(code)

    nodes, _ = analyse(tree)

    assert len(nodes) == len({id(node) for node in nodes})
    assert {id(node) for node in nodes} == {id(node) for node in full_walk(tree)}


def test_analyse_returns_every_node_of_real_files() -> None:
    # SecureLint's own source and tests: a few thousand nodes of real code.
    project = Path(__file__).parent.parent
    files = sorted(project.glob("src/**/*.py")) + sorted(project.glob("tests/**/*.py"))
    assert len(files) > 20

    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        nodes, _ = analyse(tree)
        assert len(nodes) == len(full_walk(tree)), path.name
