"""Tests for the rules looking through a variable to the value behind it."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.rules import ALL_RULES


def reported(tmp_path: Path, code: str) -> list[tuple[int, str]]:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return [(f.line, f.rule_id) for f in scan(tmp_path, ALL_RULES).findings]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        # A query built on one line and run on another.
        (
            "def find(cursor, name):\n"
            "    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
            "    cursor.execute(query)\n",
            [(3, "SL105")],
        ),
        (
            "def find(cursor, name):\n"
            '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
            "    cursor.execute(query, ())\n",
            [(3, "SL105")],
        ),
        # The fixed part and the value are joined at the call.
        (
            "def find(cursor, user_id):\n"
            '    query = "SELECT * FROM users WHERE id = %s"\n'
            "    cursor.execute(query % user_id)\n",
            [(3, "SL105")],
        ),
        (
            "def find(cursor, column):\n"
            '    base = "SELECT * FROM users ORDER BY "\n'
            "    cursor.execute(base + column)\n",
            [(3, "SL105")],
        ),
        # Through two variables.
        (
            "def find(cursor, name):\n"
            "    where = f\"name = '{name}'\"\n"
            '    query = "SELECT * FROM users WHERE " + where\n'
            "    cursor.execute(query)\n",
            [(4, "SL105")],
        ),
        # A wrapped statement kept in a variable.
        (
            "def find(session, user_id):\n"
            '    statement = text(f"SELECT * FROM users WHERE id = {user_id}")\n'
            "    session.execute(statement)\n",
            [(3, "SL105")],
        ),
        # Still reported as before: the variable holds a changing value.
        (
            "def ping(host):\n"
            '    command = "ping -c 1 " + host\n'
            "    os.system(command)\n",
            [(3, "SL102")],
        ),
        ("def run(source):\n    code = source\n    exec(code)\n", [(3, "SL101")]),
        (
            "def load(request):\n    blob = request.data\n    pickle.loads(blob)\n",
            [(3, "SL103")],
        ),
    ],
)
def test_reports_a_problem_built_through_a_variable(
    tmp_path: Path, code: str, expected: list[tuple[int, str]]
) -> None:
    assert reported(tmp_path, code) == expected


@pytest.mark.parametrize(
    "code",
    [
        # A fixed value kept in a variable is as safe as the value itself.
        'def f(cursor):\n    query = "SELECT * FROM users"\n    cursor.execute(query)\n',  # noqa: E501
        'def f():\n    command = "ls -l"\n    os.system(command)\n',
        'def f():\n    command = "ls -l"\n    subprocess.run(command, shell=True)\n',
        'def f():\n    expression = "2 + 2"\n    return eval(expression)\n',
        'def f():\n    blob = b"\\x80\\x04N."\n    return pickle.loads(blob)\n',
        'def f():\n    document = "key: value"\n    return yaml.load(document)\n',
        # Through two variables.
        'def f():\n    a = "ls -l"\n    command = a\n    os.system(command)\n',
        # A fixed value put into a query.
        (
            "def f(cursor):\n"
            "    limit = 10\n"
            '    cursor.execute(f"SELECT * FROM users LIMIT {limit}")\n'
        ),
        (
            "def f(cursor):\n"
            '    table = "users"\n'
            '    cursor.execute("SELECT * FROM %s" % table)\n'
        ),
        # Module-level code using its own variable.
        'COMMAND = "ls -l"\nos.system(COMMAND)\n',
    ],
)
def test_does_not_report_a_fixed_value_kept_in_a_variable(
    tmp_path: Path, code: str
) -> None:
    assert reported(tmp_path, code) == []


@pytest.mark.parametrize(
    "code",
    [
        # Assigned twice: one of the two values may be dangerous.
        (
            "def f(host, quick):\n"
            '    command = "ls -l"\n'
            "    if not quick:\n"
            '        command = "ping " + host\n'
            "    os.system(command)\n"
        ),
        # Extended after it was created.
        (
            "def f(host):\n"
            '    command = "ping "\n'
            "    command += host\n"
            "    os.system(command)\n"
        ),
        # A parameter with a harmless-looking default.
        'def f(command="ls -l"):\n    os.system(command)\n',
        # A list can be changed after it is created.
        (
            "def f(host):\n"
            '    command = ["ping"]\n'
            "    command.append(host)\n"
            "    subprocess.run(command, shell=True)\n"
        ),
        # Changed by another function.
        (
            'COMMAND = "ls -l"\n'
            "def change(value):\n"
            "    global COMMAND\n"
            "    COMMAND = value\n"
            "os.system(COMMAND)\n"
        ),
    ],
)
def test_still_reports_when_the_value_is_not_certain(tmp_path: Path, code: str) -> None:
    assert [rule_id for _, rule_id in reported(tmp_path, code)] == ["SL102"]


def test_variables_that_point_at_each_other_do_not_loop_for_ever(
    tmp_path: Path,
) -> None:
    code = (
        "def f(cursor):\n"
        "    a = b\n"
        "    b = a\n"
        "    os.system(a)\n"
        "    cursor.execute(a)\n"
        "    cursor.execute('SELECT ' + b)\n"
    )

    assert reported(tmp_path, code) == [(4, "SL102"), (6, "SL105")]


def test_a_long_chain_of_variables_stops_being_followed(tmp_path: Path) -> None:
    # v0 = "ls", v1 = v0, ... v20 = v19: longer than the rules follow.
    lines = ['    v0 = "ls -l"\n'] + [
        f"    v{number} = v{number - 1}\n" for number in range(1, 21)
    ]
    code = "def f():\n" + "".join(lines) + "    os.system(v20)\n    os.system(v5)\n"

    # The long chain is reported (the rule gave up, so it cannot say "fixed");
    # the short one is known to be fixed.
    assert reported(tmp_path, code) == [(23, "SL102")]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        # A dangerous function kept under another name.
        ("run = eval\nrun(data)\n", [(2, "SL101")]),
        (
            "def f(command):\n    launch = os.system\n    launch(command)\n",
            [(3, "SL102")],
        ),
        (
            "def f(blob):\n    restore = pickle.loads\n    return restore(blob)\n",
            [(3, "SL103")],
        ),
        # A module kept under another name.
        (
            "def f(command):\n    sp = subprocess\n    sp.run(command, shell=True)\n",
            [(3, "SL102")],
        ),
        # Through two variables.
        (
            "def f(command):\n    a = os\n    b = a.system\n    b(command)\n",
            [(4, "SL102")],
        ),
        # A renamed import, then a variable.
        (
            "import os as o\n\ndef f(command):\n    run = o.system\n    run(command)\n",
            [(5, "SL102")],
        ),
        # A method kept in a variable.
        (
            "def f(cursor, name):\n"
            "    execute = cursor.execute\n"
            "    execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
            [(3, "SL105")],
        ),
    ],
)
def test_reports_a_dangerous_function_kept_in_a_variable(
    tmp_path: Path, code: str, expected: list[tuple[int, str]]
) -> None:
    assert reported(tmp_path, code) == expected


@pytest.mark.parametrize(
    "code",
    [
        # A harmless function kept in a variable.
        "def f(data):\n    run = print\n    run(data)\n",
        "def f(text):\n    load = json.loads\n    return load(text)\n",
        # A project function that only shares a name.
        "def f(command):\n    system = safe_wrapper\n    system(command)\n",
        # A safe loader kept in a variable.
        (
            "def f(document):\n"
            "    loader = yaml.SafeLoader\n"
            "    return yaml.load(document, Loader=loader)\n"
        ),
        # Variables that point at each other.
        "def f(data):\n    a = b\n    b = a\n    a(data)\n",
    ],
)
def test_does_not_report_a_harmless_function_kept_in_a_variable(
    tmp_path: Path, code: str
) -> None:
    assert reported(tmp_path, code) == []
