"""Keep the threat model honest: every test it names must exist."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
THREAT_MODEL = ROOT / "docs" / "threat-model.md"

_REFERENCE = re.compile(r"tests/(test_\w+\.py)::(test_\w+)")


def named_tests() -> list[tuple[str, str]]:
    return _REFERENCE.findall(THREAT_MODEL.read_text(encoding="utf-8"))


def test_the_threat_model_names_its_tests() -> None:
    assert len(named_tests()) >= 30


def test_every_named_test_exists() -> None:
    missing = []
    for file_name, test_name in named_tests():
        path = ROOT / "tests" / file_name
        defined = set()
        if path.exists():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            defined = {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
            }
        if test_name not in defined:
            missing.append(f"{file_name}::{test_name}")

    # A protection whose test was renamed or removed is a promise nobody
    # checks any more: rename it here too, or say why it is gone.
    assert missing == []


def test_security_policy_points_to_the_threat_model() -> None:
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "docs/threat-model.md" in policy
    assert "Report a vulnerability" in policy
