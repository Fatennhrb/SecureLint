"""Tests for Lint, SecureLint's mascot (assets/lint).

The drawings will be shown inside VS Code, so they must stay plain images:
no script, no event handler, nothing loaded from elsewhere.
"""

import re
from pathlib import Path
from xml.etree import ElementTree

import pytest

LINT = Path(__file__).parent.parent / "assets" / "lint"
MOODS = ["clean", "thinking", "problem"]
SVG = "{http://www.w3.org/2000/svg}"


def drawing(mood: str) -> str:
    return (LINT / f"lint-{mood}.svg").read_text(encoding="utf-8")


def test_there_is_one_drawing_per_mood() -> None:
    assert sorted(path.name for path in LINT.glob("*.svg")) == sorted(
        f"lint-{mood}.svg" for mood in MOODS
    )


@pytest.mark.parametrize("mood", MOODS)
def test_a_drawing_is_valid_and_has_a_title(mood: str) -> None:
    # Our own files, not data from outside.
    root = ElementTree.fromstring(drawing(mood))  # noqa: S314

    assert root.tag == f"{SVG}svg"
    assert root.get("viewBox") == "0 0 100 100"
    title = root.find(f"{SVG}title")
    assert title is not None
    assert title.text is not None
    assert title.text.startswith("Lint")


@pytest.mark.parametrize("mood", MOODS)
def test_a_drawing_holds_no_script_and_loads_nothing(mood: str) -> None:
    text = drawing(mood)

    assert "<script" not in text
    assert re.search(r"\son\w+\s*=", text) is None
    assert "href" not in text
    assert "url(" not in text
    assert "@import" not in text


@pytest.mark.parametrize("mood", MOODS)
def test_a_drawing_stays_still_for_people_who_ask(mood: str) -> None:
    assert "prefers-reduced-motion" in drawing(mood)


def test_every_mood_is_the_same_lint() -> None:
    # Only the face, the brackets and the shield change between moods.
    bodies = {
        mood: drawing(mood).split('<g stroke="#1E2433"')[1].split("</g>")[0]
        for mood in MOODS
    }

    assert len(set(bodies.values())) == 1
