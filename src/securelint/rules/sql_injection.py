"""Rules about database queries built from text."""

import ast
import re
from collections.abc import Iterable

from securelint.context import FileContext
from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity
from securelint.rules._helpers import is_fixed

# Methods that send a query to a database. A cursor is an ordinary object,
# so there is no import to follow: the method is recognised by its name,
# and the text must also look like SQL (see ``_SQL_WORD``).
_QUERY_METHODS = frozenset({"execute", "executemany", "executescript", "raw"})

# Names used for the query when it is passed as a keyword argument.
_QUERY_KEYWORDS = frozenset({"sql", "query", "statement", "operation"})

_SQL_WORD = re.compile(
    r"\b(select|insert|update|delete|drop|create|alter|truncate|replace|merge)\b",
    re.IGNORECASE,
)


class SqlInjection(Rule):
    """SL105: an SQL query is built by putting values into its text.

    When a value becomes part of the query text, the database cannot tell
    the value from the query. A name such as ``' OR '1'='1`` then changes
    what the query does.

    Reported::

        cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        cursor.execute("DELETE FROM users WHERE id = %s" % user_id)
        cursor.execute("SELECT * FROM {}".format(table))
        session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))

    Not reported::

        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        cursor.execute("SELECT * FROM users")
        cursor.execute(query)        # built elsewhere; the rule cannot see how

    In the first safe example the value travels separately from the query,
    so the database always treats it as a value.
    """

    rule_id = "SL105"
    node_types = (ast.Call,)

    def check(self, node: ast.AST, context: FileContext) -> Iterable[Finding]:
        if not isinstance(node, ast.Call):
            return []
        if not isinstance(node.func, ast.Attribute):
            return []
        method = node.func.attr
        if method not in _QUERY_METHODS:
            return []
        query = _query_argument(node, context)
        if query is None:
            return []

        text, has_values = _built_text(query)
        if not has_values or _SQL_WORD.search(text) is None:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                message=(
                    f"{method}() is given an SQL query with values put into "
                    "its text; a value can then change the query. Keep the "
                    'query fixed and pass the values separately: "... WHERE '
                    'id = ?", (value,).'
                ),
                severity=Severity.HIGH,
                # The value may be one the program controls, such as a
                # table name from its own settings.
                confidence=Confidence.MEDIUM,
                path=context.path,
                line=node.lineno,
                column=node.col_offset + 1,
            )
        ]


def _query_argument(call: ast.Call, context: FileContext) -> ast.expr | None:
    """Return the expression that holds the query, if the call has one."""
    query: ast.expr | None = call.args[0] if call.args else None
    if query is None:
        for keyword in call.keywords:
            if keyword.arg in _QUERY_KEYWORDS:
                query = keyword.value
    # SQLAlchemy wraps raw SQL: session.execute(text("SELECT ...")).
    if isinstance(query, ast.Call) and query.args:
        name = context.qualified_name(query.func)
        if name is not None and name.rpartition(".")[2] == "text":
            return query.args[0]
    return query


def _built_text(node: ast.expr) -> tuple[str, bool]:
    """Describe how a string is put together.

    Returns the text written in the source, and whether anything else is
    added to it when the program runs. For ``"SELECT " + column`` that is
    ``("SELECT ", True)``.
    """
    # "SELECT ..."
    if isinstance(node, ast.Constant):
        return (node.value if isinstance(node.value, str) else "", False)

    # f"SELECT ... {value}"
    if isinstance(node, ast.JoinedStr):
        text = ""
        has_values = False
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                has_values = has_values or not is_fixed(part.value)
            else:
                text += _built_text(part)[0]
        return text, has_values

    # "SELECT ..." + value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_text, left_values = _built_text(node.left)
        right_text, right_values = _built_text(node.right)
        return left_text + right_text, left_values or right_values

    # "SELECT ... %s" % value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        text, has_values = _built_text(node.left)
        return text, has_values or not is_fixed(node.right)

    # "SELECT ... {}".format(value)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        text, has_values = _built_text(node.func.value)
        arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
        return text, has_values or not all(is_fixed(arg) for arg in arguments)

    # A variable, a function call...: no text to read, and not fixed.
    return "", True
