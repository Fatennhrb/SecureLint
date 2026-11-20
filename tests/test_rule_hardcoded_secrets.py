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


@pytest.mark.parametrize(
    ("code", "line"),
    [
        ('DATABASE_URL = "postgres://app:hunter2@db.local/app"\n', 1),
        ('CACHE = "redis://:hunter2@cache:6379/0"\n', 1),
        ('settings = {"broker": "amqp://guest:s3cr3t@rabbit//"}\n', 1),
        ('engine = create_engine(\n    "mysql://root:toor@localhost/shop"\n)\n', 2),
        ('connect(url="postgresql+psycopg://app:hunter2@db/app")\n', 1),
    ],
)
def test_reports_a_password_inside_an_address(
    tmp_path: Path, code: str, line: int
) -> None:
    (finding,) = findings_in(tmp_path, code)

    assert finding.line == line
    assert "inside" in finding.message
    # The password is never repeated in the report.
    assert "hunter2" not in finding.message


@pytest.mark.parametrize(
    "code",
    [
        # A user name but no password.
        'DATABASE_URL = "postgres://app@db.local/app"\n',
        # A port, not a password.
        'API = "https://example.com:8443/v1"\n',
        # Placeholders.
        'DATABASE_URL = "postgres://app:${DB_PASSWORD}@db/app"\n',
        'DATABASE_URL = "postgres://app:<password>@db/app"\n',
        'DATABASE_URL = "postgres://app:****@db/app"\n',
        # Built when the program runs.
        'DATABASE_URL = f"postgres://app:{password}@db/app"\n',
        # An e-mail address in a path.
        'LINK = "https://example.com/users/me@example.com"\n',
    ],
)
def test_does_not_report_addresses_without_a_real_password(
    tmp_path: Path, code: str
) -> None:
    assert findings_in(tmp_path, code) == ()


def test_an_address_under_a_secret_name_is_reported_once(tmp_path: Path) -> None:
    code = 'DB_PASSWORD = "postgres://app:hunter2@db/app"\n'

    (finding,) = findings_in(tmp_path, code)

    assert "'DB_PASSWORD'" in finding.message
