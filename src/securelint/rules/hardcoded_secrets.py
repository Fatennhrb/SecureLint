"""Rules about passwords and keys written directly in the code."""

import ast
import re
from collections.abc import Iterable, Iterator

from securelint.context import FileContext
from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity

# Splits a name into its words: "DB_PASSWORD", "dbPassword" and "X-API-Key"
# give ["DB", "PASSWORD"], ["db", "Password"] and ["X", "API", "Key"].
_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")

# A name ending with one of these words holds a secret.
_SECRET_WORDS = frozenset(
    {"password", "passwd", "pwd", "passphrase", "secret", "apikey"}
)

# "key" alone is too common ("cache_key", "primary_key"), so it only counts
# after one of these words: "api_key", "secret_key", "private_key"...
_KEY_KINDS = frozenset(
    {"api", "secret", "private", "access", "auth", "encryption", "signing"}
)

# "token" is also what parsers call a piece of text (token = "("). A real
# access token is a long random string, so short values are ignored.
_MIN_TOKEN_LENGTH = 16

# Values that only mark where the real secret goes: "<password>",
# "{password}", "${DB_PASSWORD}", "%s", "%(password)s".
_PLACEHOLDER = re.compile(r"<.*>|\$?\{.*\}|%s|%\(.*\)s")


class HardcodedSecret(Rule):
    """SL104: a password or key is written directly in the code.

    Everyone who can read the code can read the secret: teammates, anyone
    the repository is shared with, and anyone who gets a copy later. It
    also stays in the Git history after the line is deleted.

    Reported::

        password = "hunter2"
        API_KEY: str = "sk-live-123"
        self.secret_key = "s3cr3t"
        connect(host, password="hunter2")
        settings = {"password": "hunter2"}

    Not reported::

        password = os.environ["DB_PASSWORD"]    # read when the program runs
        password = ""                           # nothing to steal
        password = "<your password>"            # a placeholder
        password_field = "password"             # a name, not a password
        cache_key = "user:42"                   # not that kind of key

    The rule only reads names, so it cannot find a secret stored under an
    ordinary name such as ``x = "hunter2"``.
    """

    rule_id = "SL104"
    title = "Password or key written in the code"
    node_types = (ast.Assign, ast.AnnAssign, ast.keyword, ast.Dict)

    def check(self, node: ast.AST, context: FileContext) -> Iterable[Finding]:
        for name, value, where in _named_values(node):
            text = _text_of(value)
            if text is None or not _is_secret_name(name, text):
                continue
            if not _looks_real(text):
                continue
            yield Finding(
                rule_id=self.rule_id,
                # The secret itself is never repeated in the report.
                message=(
                    f"A password or key is written in the code as {name!r}; "
                    "anyone who can read the code can use it. Read it from "
                    "an environment variable or a secret store instead."
                ),
                severity=Severity.MEDIUM,
                # A name is only a hint: the value may be a test value.
                confidence=Confidence.MEDIUM,
                path=context.path,
                line=where.lineno,
                column=where.col_offset + 1,
            )


def _named_values(
    node: ast.AST,
) -> Iterator[tuple[str, ast.expr, ast.expr | ast.keyword]]:
    """Yield ``(name, value, where)`` for each value that is given a name.

    ``where`` is the node holding the name, used for the finding's position.
    """
    if isinstance(node, ast.Assign):
        # "a = b = value" has two targets.
        for target in node.targets:
            name = _target_name(target)
            if name is not None:
                yield name, node.value, target
    elif isinstance(node, ast.AnnAssign):
        name = _target_name(node.target)
        if name is not None and node.value is not None:
            yield name, node.value, node.target
    elif isinstance(node, ast.keyword):
        # "**options" is a keyword without a name.
        if node.arg is not None:
            yield node.arg, node.value, node
    elif isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                yield key.value, value, key


def _target_name(target: ast.expr) -> str | None:
    """Return the name being assigned to, for the simple cases."""
    if isinstance(target, ast.Name):  # password = ...
        return target.id
    if isinstance(target, ast.Attribute):  # self.password = ...
        return target.attr
    if (  # config["password"] = ...
        isinstance(target, ast.Subscript)
        and isinstance(target.slice, ast.Constant)
        and isinstance(target.slice.value, str)
    ):
        return target.slice.value
    return None


def _text_of(value: ast.expr) -> str | None:
    """Return the text of a string or bytes literal, or None for anything else."""
    if isinstance(value, ast.Constant):
        if isinstance(value.value, str):
            return value.value
        if isinstance(value.value, bytes):
            return value.value.decode("latin-1")
    return None


def _is_secret_name(name: str, text: str) -> bool:
    """Return True if a value with this name is meant to be kept secret."""
    words = [word.lower() for word in _WORD.findall(name)]
    if not words:
        return False
    # Only the last word says what the value is: "password_field" is a
    # field, "db_password" is a password.
    last = words[-1]
    if last in _SECRET_WORDS:
        return True
    if last == "key":
        return len(words) >= 2 and words[-2] in _KEY_KINDS
    if last == "token":
        return len(text) >= _MIN_TOKEN_LENGTH
    return False


def _looks_real(text: str) -> bool:
    """Return False for values that are clearly not a usable secret."""
    if not text:
        return False
    # A sentence such as "Enter your password".
    if any(character.isspace() for character in text):
        return False
    # "x", "****", "........"
    if len(set(text)) == 1:
        return False
    return _PLACEHOLDER.fullmatch(text) is None
