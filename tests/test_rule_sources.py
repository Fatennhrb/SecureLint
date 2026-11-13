"""Tests for saying where a dangerous value comes from."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.model import Confidence, Finding
from securelint.rules import ALL_RULES


def finding_in(tmp_path: Path, code: str) -> Finding:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    (finding,) = scan(tmp_path, ALL_RULES).findings
    return finding


@pytest.mark.parametrize(
    ("code", "rule_id", "note"),
    [
        # Each rule, with the value taken straight from a web request.
        (
            'eval(request.args["expression"])\n',
            "SL101",
            "Here the value comes from request.args on line 1.",
        ),
        (
            'os.system("ping " + request.form["host"])\n',
            "SL102",
            "Here the value comes from request.form on line 1.",
        ),
        (
            "pickle.loads(request.data)\n",
            "SL103",
            "Here the value comes from request.data on line 1.",
        ),
        (
            "yaml.load(request.get_data())\n",
            "SL103",
            "Here the value comes from request.get_data on line 1.",
        ),
        (
            "cursor.execute(f\"SELECT * FROM users WHERE name = '{request.GET['name']}'\")\n",  # noqa: E501
            "SL105",
            "Here the value comes from request.GET on line 1.",
        ),
        # The other entry points.
        (
            'os.system("ping " + input("Host: "))\n',
            "SL102",
            "Here the value comes from input() on line 1.",
        ),
        (
            'os.system("ping " + sys.argv[1])\n',
            "SL102",
            "Here the value comes from sys.argv on line 1.",
        ),
        (
            "exec(sys.stdin.read())\n",
            "SL101",
            "Here the value comes from sys.stdin on line 1.",
        ),
        # The value passes through variables first; the note gives the line
        # where it entered the program.
        (
            "def find(cursor):\n"
            '    name = request.args.get("name")\n'
            "    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
            "    cursor.execute(query)\n",
            "SL105",
            "Here the value comes from request.args on line 2.",
        ),
        (
            "def ping():\n"
            "    host = input()\n"
            "    clean = host.strip()\n"
            '    os.system("ping " + clean)\n',
            "SL102",
            "Here the value comes from input() on line 2.",
        ),
        # Flask's request under the names an import can give it.
        (
            "from flask import request\n\neval(request.args['x'])\n",
            "SL101",
            "Here the value comes from request.args on line 3.",
        ),
        (
            "from flask import request as req\n\neval(req.json['x'])\n",
            "SL101",
            "Here the value comes from request.json on line 3.",
        ),
        (
            "import flask\n\neval(flask.request.cookies['x'])\n",
            "SL101",
            "Here the value comes from request.cookies on line 3.",
        ),
        (
            "from sys import argv\n\nos.system('ping ' + argv[1])\n",
            "SL102",
            "Here the value comes from sys.argv on line 3.",
        ),
    ],
)
def test_value_from_a_user_is_reported_with_high_confidence(
    tmp_path: Path, code: str, rule_id: str, note: str
) -> None:
    finding = finding_in(tmp_path, code)

    assert finding.rule_id == rule_id
    assert finding.confidence is Confidence.HIGH
    assert finding.message.endswith(note)


@pytest.mark.parametrize(
    ("code", "confidence"),
    [
        # A parameter: it may or may not come from a user.
        ("def f(expression):\n    eval(expression)\n", Confidence.MEDIUM),
        ('def f(host):\n    os.system("ping " + host)\n', Confidence.MEDIUM),
        ("def f(blob):\n    pickle.loads(blob)\n", Confidence.LOW),
        ("def f(document):\n    yaml.load(document)\n", Confidence.MEDIUM),
        (
            'def f(cursor, name):\n    cursor.execute("SELECT * FROM t WHERE n = " + name)\n',  # noqa: E501
            Confidence.MEDIUM,
        ),
        # The program's own data.
        ('os.system("ping " + settings.HOST)\n', Confidence.MEDIUM),
        ('os.system("ping " + os.environ["HOST"])\n', Confidence.MEDIUM),
        # Things that only look like an entry point.
        ('os.system("ping " + request.host_name)\n', Confidence.MEDIUM),
        ('os.system("ping " + my.request.args["h"])\n', Confidence.MEDIUM),
        ('os.system("ping " + parser.argv[1])\n', Confidence.MEDIUM),
        (
            "from mylib import input\n\nos.system('ping ' + input())\n",
            Confidence.MEDIUM,
        ),
        # The variable is assigned twice, so it is not followed.
        (
            "def f(default):\n"
            "    host = default\n"
            "    host = input()\n"
            '    os.system("ping " + host)\n',
            Confidence.MEDIUM,
        ),
    ],
)
def test_value_of_unknown_origin_keeps_its_confidence(
    tmp_path: Path, code: str, confidence: Confidence
) -> None:
    finding = finding_in(tmp_path, code)

    assert finding.confidence is confidence
    assert "Here the value comes from" not in finding.message


@pytest.mark.parametrize(
    "code",
    [
        # Turned into a number: whatever was typed, only a number comes out.
        'cursor.execute("SELECT * FROM t WHERE id = %d" % int(request.args["id"]))\n',
        'cursor.execute(f"SELECT * FROM t LIMIT {int(input())}")\n',
        'cursor.execute("SELECT * FROM t LIMIT " + str(len(sys.argv)))\n',
        # Quoted for the shell.
        'os.system("ping " + shlex.quote(request.args["host"]))\n',
    ],
)
def test_value_made_harmless_is_not_called_user_input(
    tmp_path: Path, code: str
) -> None:
    finding = finding_in(tmp_path, code)

    # Still reported, because the rule does not know the call is safe; but
    # it does not claim the value comes from a user.
    assert finding.confidence is Confidence.MEDIUM
    assert "Here the value comes from" not in finding.message


def test_the_first_part_of_the_message_is_unchanged(tmp_path: Path) -> None:
    plain = finding_in(tmp_path, "def f(x):\n    eval(x)\n")
    with_note = finding_in(tmp_path, "eval(input())\n")

    assert with_note.message == (
        plain.message + " Here the value comes from input() on line 1."
    )


def test_variables_that_point_at_each_other_do_not_loop_for_ever(
    tmp_path: Path,
) -> None:
    code = "def f():\n    a = b + a\n    b = a + b\n    os.system(a)\n"

    assert finding_in(tmp_path, code).confidence is Confidence.MEDIUM
