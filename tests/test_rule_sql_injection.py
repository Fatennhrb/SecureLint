"""Tests for SL105, an SQL query built by putting values into its text."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.model import Confidence, Finding, Severity
from securelint.rules.sql_injection import SqlInjection


def findings_in(tmp_path: Path, code: str) -> tuple[Finding, ...]:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return scan(tmp_path, [SqlInjection()]).findings


@pytest.mark.parametrize(
    "code",
    [
        # The four ways of putting a value into text.
        """cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")\n""",
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',
        'cursor.execute("DELETE FROM users WHERE id = %s" % user_id)\n',
        'cursor.execute("SELECT * FROM {}".format(table))\n',
        # Variations of them.
        'cursor.execute("SELECT * FROM t WHERE a = %s AND b = %s" % (a, b))\n',
        'cursor.execute("SELECT * FROM {name}".format(name=table))\n',
        'cursor.execute("select * from users where id = " + str(user_id))\n',
        'cursor.execute("SELECT * FROM users " + where_clause)\n',
        'cursor.execute("SELECT * FROM t WHERE a = " + f"{a}")\n',
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}", ())\n',
        # Other ways of sending a query.
        'cursor.executemany(f"INSERT INTO {table} VALUES (?)", rows)\n',
        'connection.executescript(f"DROP TABLE {table}")\n',
        'db.cursor().execute(f"DELETE FROM logs WHERE day < {day}")\n',
        'cursor.execute(sql=f"SELECT * FROM t WHERE id = {i}")\n',
        'User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")\n',
        'session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))\n',
        'session.execute(sqlalchemy.text("SELECT * FROM users WHERE id = " + uid))\n',
    ],
)
def test_reports_a_query_built_from_values(tmp_path: Path, code: str) -> None:
    assert [finding.rule_id for finding in findings_in(tmp_path, code)] == ["SL105"]


@pytest.mark.parametrize(
    "code",
    [
        # The values travel separately from the query.
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n',
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n',
        'cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})\n',
        'session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})\n',
        "session.execute(select(User).where(User.id == user_id))\n",
        # Queries fixed in the source.
        'cursor.execute("SELECT * FROM users")\n',
        'cursor.execute("SELECT * FROM users " + "ORDER BY name")\n',
        'cursor.execute("SELECT * FROM users LIMIT %d" % 10)\n',
        'cursor.execute(f"SELECT * FROM users LIMIT {10}")\n',
        'cursor.execute("SELECT * FROM users LIMIT {}".format(10))\n',
        # Built elsewhere: the rule cannot see how.
        "cursor.execute(query)\n",
        "cursor.execute(query, params)\n",
        "cursor.execute(build_query(user_id))\n",
        # execute() methods that have nothing to do with SQL.
        'executor.execute(f"job-{number}")\n',
        'task.execute("retry " + name)\n',
        # SQL text that is not sent to a database.
        'logger.info(f"SELECT * FROM users WHERE id = {user_id}")\n',
        'print("DELETE FROM users WHERE id = " + user_id)\n',
        "cursor.execute()\n",
        "cursor.fetchall()\n",
    ],
)
def test_does_not_report_safe_code(tmp_path: Path, code: str) -> None:
    assert findings_in(tmp_path, code) == ()


def test_finding_details(tmp_path: Path) -> None:
    code = (
        "def find_user(cursor, name):\n"
        "    return cursor.execute(\n"
        "        f\"SELECT * FROM users WHERE name = '{name}'\"\n"
        "    )\n"
    )

    (finding,) = findings_in(tmp_path, code)

    assert finding.path == "app.py"
    assert (finding.line, finding.column) == (2, 12)
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.message.startswith("execute() is given an SQL query")


def test_message_names_the_method_that_was_called(tmp_path: Path) -> None:
    (finding,) = findings_in(tmp_path, 'db.executescript(f"DROP TABLE {table}")\n')

    assert finding.message.startswith("executescript() is given an SQL query")


@pytest.mark.parametrize(
    ("code", "line"),
    [
        # Extended with +=.
        (
            "def find(cursor, name):\n"
            '    query = "SELECT * FROM users"\n'
            "    query += f\" WHERE name = '{name}'\"\n"
            "    cursor.execute(query)\n",
            4,
        ),
        # Extended in one branch only.
        (
            "def find(cursor, name, everyone):\n"
            '    query = "SELECT * FROM users"\n'
            "    if not everyone:\n"
            '        query = query + " WHERE name = \'" + name + "\'"\n'
            "    cursor.execute(query)\n",
            5,
        ),
        # Column names added in a loop.
        (
            "def pick(cursor, columns):\n"
            '    query = "SELECT id"\n'
            "    for column in columns:\n"
            '        query += ", " + column\n'
            "    cursor.execute(query)\n",
            5,
        ),
        # Built by a function in the same file.
        (
            "def find_user(name):\n"
            "    return f\"SELECT * FROM users WHERE name = '{name}'\"\n"
            "\n"
            "def find(cursor, name):\n"
            "    cursor.execute(find_user(name))\n",
            5,
        ),
        # The same, through a variable.
        (
            "def find_user(name):\n"
            "    return f\"SELECT * FROM users WHERE name = '{name}'\"\n"
            "\n"
            "def find(cursor, name):\n"
            "    query = find_user(name)\n"
            "    cursor.execute(query)\n",
            6,
        ),
    ],
)
def test_reports_queries_built_in_pieces_or_by_a_function(
    tmp_path: Path, code: str, line: int
) -> None:
    (finding,) = findings_in(tmp_path, code)

    assert finding.line == line


@pytest.mark.parametrize(
    "code",
    [
        # Every piece is fixed.
        (
            "def find(cursor, user_id):\n"
            '    query = "SELECT * FROM users"\n'
            '    query += " WHERE id = ?"\n'
            "    cursor.execute(query, (user_id,))\n"
        ),
        # The function returns a fixed query.
        (
            "def everyone():\n"
            '    return "SELECT * FROM users"\n'
            "\n"
            "def find(cursor):\n"
            "    cursor.execute(everyone())\n"
        ),
        # Not SQL, whatever the pieces.
        (
            "def run(executor, number):\n"
            '    job = "job-"\n'
            "    job += str(number)\n"
            "    executor.execute(job)\n"
        ),
    ],
)
def test_does_not_report_fixed_pieces_or_fixed_returns(
    tmp_path: Path, code: str
) -> None:
    assert findings_in(tmp_path, code) == ()


def test_a_query_extended_many_times_is_read_quickly(tmp_path: Path) -> None:
    # Each "query = query + ..." reads query again; it must not be read
    # once per path through all the lines.
    lines = "".join(f"    query = query + ' AND c{i} = ' + v{i}\n" for i in range(30))
    start = "def f(cursor):\n    query = 'SELECT * FROM t WHERE 1 = 1'\n"
    code = start + lines
    code += "    cursor.execute(query)\n"

    (finding,) = findings_in(tmp_path, code)

    assert finding.line == 33


@pytest.mark.parametrize(
    "code",
    [
        "pandas.read_sql(f\"SELECT * FROM users WHERE city = '{city}'\", db)\n",
        (
            "import pandas as pd\n\n"
            'pd.read_sql_query("SELECT * FROM t WHERE a = " + a, db)\n'
        ),
        (
            "from pandas import read_sql\n\n"
            'read_sql(sql=f"DELETE FROM t WHERE id = {i}", con=db)\n'
        ),
    ],
)
def test_reports_pandas_read_sql(tmp_path: Path, code: str) -> None:
    (finding,) = findings_in(tmp_path, code)

    assert "read_sql" in finding.message


@pytest.mark.parametrize(
    "code",
    [
        # The values passed separately.
        'pandas.read_sql("SELECT * FROM users WHERE city = ?", db, params=(city,))\n',
        # A table name, not a query: a different function.
        "pandas.read_sql_table(table, db)\n",
        # Some other read_sql, not pandas.
        'reports.read_sql(f"SELECT * FROM {table}")\n',
    ],
)
def test_does_not_report_safe_pandas_queries(tmp_path: Path, code: str) -> None:
    assert findings_in(tmp_path, code) == ()
