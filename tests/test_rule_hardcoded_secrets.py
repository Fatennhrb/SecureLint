"""Tests for SL104, a password or key written directly in the code."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.model import Confidence, Finding, Severity
from securelint.rules.hardcoded_secrets import HardcodedSecret


def findings_in(tmp_path: Path, code: str) -> tuple[Finding, ...]:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return scan(tmp_path, [HardcodedSecret()]).findings


@pytest.mark.parametrize(
    "code",
    [
        'password = "hunter2"\n',
        'db_password = "hunter2"\n',
        'DB_PASSWORD = "hunter2"\n',
        'dbPassword = "hunter2"\n',
        'passwd = "hunter2"\n',
        'pwd = "hunter2"\n',
        'passphrase = "correct-horse"\n',
        'client_secret = "abc123"\n',
        'SECRET_KEY = "django-insecure-4f9x"\n',
        'API_KEY = "sk-live-123"\n',
        'apiKey = "sk-live-123"\n',
        'apikey = "sk-live-123"\n',
        'private_key = "MIIEvQIBADANBg"\n',
        'aws_secret_access_key = "wJalrXUtnFEMI"\n',
        'auth_token = "ghp_0123456789abcdefghij"\n',
        # Other ways of giving a value a name.
        'password: str = "hunter2"\n',
        'self.password = "hunter2"\n',
        'config["password"] = "hunter2"\n',
        'app.secret_key = b"_5#y2LF4Q8z"\n',
        'connect(host, password="hunter2")\n',
        'settings = {"user": "admin", "password": "hunter2"}\n',
        'headers = {"X-API-Key": "abc123def"}\n',
        'backup = password = "hunter2"\n',
    ],
)
def test_reports_a_secret_written_in_the_code(tmp_path: Path, code: str) -> None:
    assert [finding.rule_id for finding in findings_in(tmp_path, code)] == ["SL104"]


@pytest.mark.parametrize(
    "code",
    [
        # The value comes from outside the code.
        'password = os.environ["DB_PASSWORD"]\n',
        "password = getpass.getpass()\n",
        "connect(host, password=password)\n",
        'settings = {"password": password}\n',
        'password = f"{user}-{pin}"\n',
        # Nothing to steal.
        "password = None\n",
        'password = ""\n',
        "PASSWORD_MIN_LENGTH = 8\n",
        # Placeholders and messages.
        'password = "<password>"\n',
        'password = "{password}"\n',
        'password = "${DB_PASSWORD}"\n',
        'password = "%s"\n',
        'password = "%(password)s"\n',
        'password = "********"\n',
        'password = "Enter your password"\n',
        # The last word of the name says it is not a secret.
        'password_field = "password"\n',
        'token_url = "https://example.com/token"\n',
        'secret_name = "prod/database"\n',
        'field = {"type": "password"}\n',
        # Keys that open nothing.
        'key = "name"\n',
        'primary_key = "id"\n',
        'cache_key = "user:42"\n',
        # A parser's tokens are short pieces of text.
        'token = "("\n',
        'next_token = "IDENTIFIER"\n',
        # Words that only contain "pass" or "secret".
        'compass = "north"\n',
        'username = "admin"\n',
        'secretary = "Alice"\n',
    ],
)
def test_does_not_report_other_values(tmp_path: Path, code: str) -> None:
    assert findings_in(tmp_path, code) == ()


def test_finding_details(tmp_path: Path) -> None:
    code = 'class Config:\n    DB_PASSWORD = "hunter2"\n'

    (finding,) = findings_in(tmp_path, code)

    assert finding.path == "app.py"
    assert (finding.line, finding.column) == (2, 5)
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.MEDIUM
    assert "'DB_PASSWORD'" in finding.message


def test_the_secret_is_not_repeated_in_the_message(tmp_path: Path) -> None:
    (finding,) = findings_in(tmp_path, 'password = "hunter2"\n')

    assert "hunter2" not in finding.message


@pytest.mark.parametrize(
    ("code", "column"),
    [
        ('connect(host, password="hunter2")\n', 15),
        ('settings = {"user": "admin", "password": "hunter2"}\n', 30),
        ('self.password = "hunter2"\n', 1),
    ],
)
def test_finding_points_at_the_name(tmp_path: Path, code: str, column: int) -> None:
    (finding,) = findings_in(tmp_path, code)

    assert (finding.line, finding.column) == (1, column)


def test_each_secret_in_a_file_is_reported(tmp_path: Path) -> None:
    code = (
        'USER = "admin"\n'
        'PASSWORD = "hunter2"\n'
        'client = Client(api_key="sk-live-123", timeout=5)\n'
    )

    assert [(f.line, f.column) for f in findings_in(tmp_path, code)] == [
        (2, 1),
        (3, 17),
    ]
