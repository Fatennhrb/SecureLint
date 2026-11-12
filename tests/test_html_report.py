"""Tests for the HTML report."""

from html.parser import HTMLParser

from securelint import __version__
from securelint.engine import ScanResult
from securelint.html_report import format_html
from securelint.model import Confidence, Finding, Severity
from securelint.parsing import ParseFailure

# Tags that never have a closing tag.
VOID_TAGS = {"meta", "br", "hr", "img", "input", "link"}


def finding(
    severity: Severity = Severity.HIGH,
    line: int = 1,
    path: str = "pkg/app.py",
    message: str = "Example problem.",
) -> Finding:
    return Finding(
        rule_id="T001",
        message=message,
        severity=severity,
        confidence=Confidence.MEDIUM,
        path=path,
        line=line,
        column=5,
    )


def result(*findings: Finding, files_scanned: int = 3) -> ScanResult:
    return ScanResult(findings=findings, failures=(), files_scanned=files_scanned)


class PageReader(HTMLParser):
    """Reads a page the way a browser would, and records what it finds."""

    def __init__(self) -> None:
        super().__init__()
        self.open_tags: list[str] = []
        self.all_tags: list[str] = []
        self.badly_closed: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.all_tags.append(tag)
        if tag not in VOID_TAGS:
            self.open_tags.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if not self.open_tags or self.open_tags.pop() != tag:
            self.badly_closed.append(tag)

    def handle_data(self, data: str) -> None:
        # The style sheet is not text a reader sees.
        if self.open_tags and self.open_tags[-1] != "style":
            self.text.append(data)


def read(page: str) -> PageReader:
    reader = PageReader()
    reader.feed(page)
    reader.close()
    return reader


def visible_text(page: str) -> str:
    return " ".join(" ".join(read(page).text).split())


def test_page_is_complete_and_every_tag_is_closed() -> None:
    page = format_html(result(finding(), finding(Severity.LOW, line=2)))

    reader = read(page)

    assert page.startswith("<!DOCTYPE html>")
    assert page.endswith("</html>")
    assert reader.badly_closed == []
    assert reader.open_tags == []


def test_clean_scan() -> None:
    text = visible_text(format_html(result()))

    assert "No problems found in 3 files." in text
    assert f"Made by SecureLint {__version__}" in text
    assert "Problems" not in text.replace("No problems", "")


def test_finding_shows_all_its_details() -> None:
    text = visible_text(format_html(result(finding(Severity.HIGH, line=12))))

    assert "1 problem found in 3 files (1 high)." in text
    assert "pkg/app.py (1)" in text
    assert "high T001 line 12, column 5 confidence: medium" in text
    assert "Example problem." in text


def test_findings_are_grouped_by_file() -> None:
    page = format_html(
        result(
            finding(path="a.py", line=1),
            finding(path="a.py", line=7),
            finding(path="b.py", line=3),
        )
    )

    text = visible_text(page)
    assert text.count("a.py (2)") == 1
    assert text.count("b.py (1)") == 1
    assert page.count('<section class="file">') == 2


def test_cards_count_each_severity() -> None:
    page = format_html(
        result(
            finding(Severity.CRITICAL),
            finding(Severity.LOW, line=2),
            finding(Severity.LOW, line=3),
            files_scanned=4,
        )
    )

    text = visible_text(page)
    assert "4 files scanned 3 problems 1 critical 0 high 0 medium 2 low" in text


def test_text_from_the_scanned_project_cannot_become_html() -> None:
    attack_path = "<script>alert(1)</script>.py"
    attack_message = 'Name <img src=x onerror="alert(2)"> & more.'
    page = format_html(result(finding(path=attack_path, message=attack_message)))

    reader = read(page)

    # The browser sees no script and no image, only text...
    assert "script" not in reader.all_tags
    assert "img" not in reader.all_tags
    assert "<script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.py" in page
    # ...and the reader still sees exactly what the name was.
    assert attack_path in visible_text(page)
    assert attack_message in visible_text(page)


def test_failure_text_is_escaped_too() -> None:
    failures = (ParseFailure("<b>bad</b>.py", "unexpected <token>", line=4),)
    scan_result = ScanResult(findings=(), failures=failures, files_scanned=0)

    page = format_html(scan_result)

    assert "b" not in read(page).all_tags
    assert "<b>bad</b>.py:4 unexpected <token>" in visible_text(page)


def test_page_has_no_script_and_forbids_them() -> None:
    page = format_html(result(finding()))

    assert "<script" not in page.lower()
    assert "javascript:" not in page.lower()
    assert (
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#x27;none&#x27;; style-src &#x27;unsafe-inline&#x27;">'
    ) in page


def test_page_loads_nothing_from_outside() -> None:
    page = format_html(result(finding()))

    assert "http://" not in page
    assert "https://" not in page
    assert "url(" not in page
    assert "@import" not in page


def test_page_uses_only_ascii_characters() -> None:
    page = format_html(result(finding(path="café/app.py")))

    assert page.isascii()
    assert "caf&#233;/app.py" in page
    assert "café/app.py (1)" in visible_text(page)


def test_files_that_could_not_be_scanned_are_listed() -> None:
    failures = (
        ParseFailure("broken.py", "invalid syntax", line=4),
        ParseFailure("locked.py", "permission denied"),
    )
    scan_result = ScanResult(findings=(), failures=failures, files_scanned=1)

    text = visible_text(format_html(scan_result))

    assert "The scan is incomplete: 2 files could not be scanned" in text
    assert "broken.py:4 invalid syntax" in text
    assert "locked.py permission denied" in text


def test_no_failure_section_when_every_file_was_scanned() -> None:
    text = visible_text(format_html(result(finding())))

    assert "incomplete" not in text
    assert "could not be scanned" not in text
