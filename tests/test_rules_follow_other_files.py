"""Tests for following a call into a function defined in another file."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.model import Confidence, Finding
from securelint.rules import ALL_RULES
from securelint.rules.sql_injection import SqlInjection

FIND_USER = (
    "def find_user(name):\n    return f\"SELECT * FROM users WHERE name = '{name}'\"\n"
)


def findings_in(tmp_path: Path, files: dict[str, str]) -> tuple[Finding, ...]:
    for name, code in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
    return scan(tmp_path, [SqlInjection()]).findings


@pytest.mark.parametrize(
    "files",
    [
        # from module import function
        {
            "queries.py": FIND_USER,
            "app.py": "from queries import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
        # import module, then module.function
        {
            "queries.py": FIND_USER,
            "app.py": "import queries\n\ncursor.execute(queries.find_user(name))\n",
        },
        # A renamed import.
        {
            "queries.py": FIND_USER,
            "app.py": "from queries import find_user as fu\n\n"
            "cursor.execute(fu(name))\n",
        },
        # Inside a package.
        {
            "shop/__init__.py": "",
            "shop/queries.py": FIND_USER,
            "app.py": "from shop.queries import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
        # A relative import.
        {
            "shop/__init__.py": "",
            "shop/queries.py": FIND_USER,
            "shop/app.py": "from .queries import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
        # Two levels up.
        {
            "shop/__init__.py": "",
            "shop/queries.py": FIND_USER,
            "shop/views/__init__.py": "",
            "shop/views/app.py": "from ..queries import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
        # A package's own __init__.py.
        {
            "shop/__init__.py": FIND_USER,
            "app.py": "from shop import find_user\n\ncursor.execute(find_user(name))\n",
        },
        # Scanned from above a "src" folder: imported without "src.".
        {
            "src/shop/__init__.py": "",
            "src/shop/queries.py": FIND_USER,
            "src/shop/app.py": "from shop.queries import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
        # Through a variable, and through a function of the other file.
        {
            "queries.py": FIND_USER + "\n\ndef query(name):\n"
            "    return find_user(name)\n",
            "app.py": "from queries import query\n\n"
            "sql = query(name)\ncursor.execute(sql)\n",
        },
    ],
)
def test_reports_a_query_built_in_another_file(
    tmp_path: Path, files: dict[str, str]
) -> None:
    (finding,) = findings_in(tmp_path, files)

    assert finding.rule_id == "SL105"
    assert finding.path.endswith("app.py")


@pytest.mark.parametrize(
    "files",
    [
        # The other file's query is fixed, using its own constant.
        {
            "queries.py": 'TABLE = "users"\n\n\ndef everyone():\n'
            '    return f"SELECT * FROM {TABLE}"\n',
            "app.py": "from queries import everyone\n\ncursor.execute(everyone())\n",
        },
        # Not imported: a name that is only the same.
        {
            "queries.py": FIND_USER,
            "app.py": "cursor.execute(find_user(name))\n",
        },
        # Two files that "from utils import" could mean.
        {
            "a/utils.py": FIND_USER,
            "b/utils.py": FIND_USER,
            "app.py": "from utils import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
        # Not at the top of the file: a method.
        {
            "queries.py": "class Queries:\n"
            "    def find_user(self, name):\n"
            "        return f\"SELECT * FROM users WHERE name = '{name}'\"\n",
            "app.py": "from queries import Queries\n\n"
            "cursor.execute(Queries().find_user(name))\n",
        },
        # A module outside the project, with the same name as nothing here.
        {
            "app.py": "from somewhere import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
        # Relative dots that climb above the scanned folder.
        {
            "queries.py": FIND_USER,
            "app.py": "from ..queries import find_user\n\n"
            "cursor.execute(find_user(name))\n",
        },
    ],
)
def test_does_not_report_what_cannot_be_followed_or_is_fixed(
    tmp_path: Path, files: dict[str, str]
) -> None:
    # Only the query in queries.py itself is never run: no finding there.
    assert findings_in(tmp_path, files) == ()


def test_source_given_to_the_other_file_is_named(tmp_path: Path) -> None:
    (tmp_path / "queries.py").write_text(FIND_USER, encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from queries import find_user\n\n"
        'cursor.execute(find_user(request.args["name"]))\n',
        encoding="utf-8",
    )

    (finding,) = scan(tmp_path, ALL_RULES).findings

    assert finding.confidence is Confidence.HIGH
    assert "Here the value comes from request.args" in finding.message


def test_files_scanned_still_counts_each_file_once(tmp_path: Path) -> None:
    (tmp_path / "queries.py").write_text(FIND_USER, encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")

    result = scan(tmp_path, [SqlInjection()])

    assert result.files_scanned == 2
    assert len(result.failures) == 1
