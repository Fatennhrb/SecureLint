"""Turn a scan result into one HTML page to open in a browser.

The page is a single file: its style is inside it, and it loads nothing
from the network, so it can be saved, sent or attached to a CI run as is.

The page shows text taken from the scanned project (file names, and names
quoted in messages). That text is not trusted: every piece goes through
``_text`` before it is written, and the page carries no script at all.
"""

import html
from collections import Counter
from itertools import groupby

from securelint import __version__
from securelint.engine import ScanResult
from securelint.model import Finding, Severity
from securelint.parsing import ParseFailure
from securelint.report import summary_line
from securelint.suppressions import Silenced

# Forbids scripts, images, fonts and network requests; only the style
# written in the page itself is allowed. Even if some text slipped through
# unescaped, the browser would refuse to run it.
_CONTENT_SECURITY_POLICY = "default-src 'none'; style-src 'unsafe-inline'"

_STYLE = """
:root {
  --page: #f6f7f9; --card: #ffffff; --text: #1c2430; --muted: #5b6676;
  --line: #dde2ea; --ok: #1a7f4b; --warn: #9a5b00;
  --critical: #a4161a; --high: #c2410c; --medium: #a16207; --low: #3b6ea5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --page: #12161c; --card: #1b212a; --text: #e6eaf0; --muted: #9aa5b4;
    --line: #2c3541; --ok: #4ccb8a; --warn: #f0b354;
    --critical: #ff7b7f; --high: #ff9a62; --medium: #e8c04d; --low: #7fb2e8;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px 16px 48px; background: var(--page);
  color: var(--text); line-height: 1.5;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 900px; margin: 0 auto; }
h1 { margin: 0; font-size: 1.7rem; }
h2 { margin: 32px 0 12px; font-size: 1.2rem; }
h3 {
  margin: 0; padding: 10px 14px; font-size: 0.95rem; overflow-wrap: anywhere;
  font-family: ui-monospace, Consolas, monospace;
  border-bottom: 1px solid var(--line);
}
.meta, .place, .confidence, .label { color: var(--muted); font-size: 0.85rem; }
.status {
  margin: 20px 0; padding: 12px 14px; border-radius: 8px; font-weight: 600;
  background: var(--card); border: 1px solid var(--line);
  border-left: 6px solid var(--muted);
}
.status.ok { border-left-color: var(--ok); }
.status.bad { border-left-color: var(--high); }
.status.warn { border-left-color: var(--warn); }
.cards { display: flex; flex-wrap: wrap; gap: 10px; }
.card {
  flex: 1 1 110px; padding: 12px 14px; border-radius: 8px;
  background: var(--card); border: 1px solid var(--line);
  border-top: 4px solid var(--line);
}
.card .number { display: block; font-size: 1.6rem; font-weight: 700; }
.card.critical { border-top-color: var(--critical); }
.card.high { border-top-color: var(--high); }
.card.medium { border-top-color: var(--medium); }
.card.low { border-top-color: var(--low); }
.file {
  margin-bottom: 16px; border-radius: 8px; overflow: hidden;
  background: var(--card); border: 1px solid var(--line);
}
.count { color: var(--muted); font-weight: 400; }
ol, ul { margin: 0; padding: 0; list-style: none; }
.finding { padding: 12px 14px; border-left: 4px solid var(--line); }
.finding + .finding, .failure + .failure { border-top: 1px solid var(--line); }
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.top { display: flex; flex-wrap: wrap; gap: 6px 12px; align-items: baseline; }
.badge {
  padding: 1px 8px; border-radius: 999px; font-size: 0.75rem;
  font-weight: 700; text-transform: uppercase; border: 1px solid currentColor;
}
.badge.critical { color: var(--critical); }
.badge.high { color: var(--high); }
.badge.medium { color: var(--medium); }
.badge.low { color: var(--low); }
.rule { font-weight: 700; font-family: ui-monospace, Consolas, monospace; }
.finding p { margin: 6px 0 0; overflow-wrap: anywhere; }
.failure { padding: 10px 14px; overflow-wrap: anywhere; }
footer { margin-top: 32px; color: var(--muted); font-size: 0.85rem; }
"""


def format_html(result: ScanResult) -> str:
    """Return the scan result as one complete HTML page."""
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" '
        f'content="{_text(_CONTENT_SECURITY_POLICY)}">',
        "<title>SecureLint report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        "<main>",
        "<header>",
        "<h1>SecureLint report</h1>",
        f'<p class="meta">Made by SecureLint {_text(__version__)}</p>',
        "</header>",
        *_status(result),
        *_cards(result),
        *_findings(result.findings),
        *_silenced(result.silenced),
        *_failures(result.failures),
        "<footer>The exact place of each problem is given as line and column, "
        "both counted from 1.</footer>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts)


def _text(value: object) -> str:
    """Make any value safe to write into the page.

    ``html.escape`` turns ``<``, ``>``, ``&`` and both quotes into harmless
    codes, so the browser shows the text instead of reading it as HTML.
    Characters outside ASCII become numeric codes too, so the page is the
    same whatever encoding the terminal or the shell writes it with.
    """
    escaped = html.escape(str(value), quote=True)
    return escaped.encode("ascii", "xmlcharrefreplace").decode("ascii")


def _status(result: ScanResult) -> list[str]:
    kind = "bad" if result.findings else "ok"
    lines = [f'<p class="status {kind}">{_text(summary_line(result))}</p>']
    if result.failures:
        number = len(result.failures)
        files = "1 file" if number == 1 else f"{number} files"
        lines.append(
            f'<p class="status warn">The scan is incomplete: {files} could '
            "not be scanned, so problems in them are not shown.</p>"
        )
    return lines


def _cards(result: ScanResult) -> list[str]:
    counts = Counter(finding.severity for finding in result.findings)
    cards = [
        _card("", result.files_scanned, "files scanned"),
        _card("", len(result.findings), "problems"),
    ]
    # All four severities are always shown, so the page keeps its shape.
    cards += [
        _card(severity.name.lower(), counts[severity], severity.name.lower())
        for severity in sorted(Severity, reverse=True)
    ]
    return ['<section class="cards">', *cards, "</section>"]


def _card(kind: str, number: int, label: str) -> str:
    return (
        f'<div class="card {kind}"><span class="number">{number}</span>'
        f'<span class="label">{_text(label)}</span></div>'
    )


def _findings(findings: tuple[Finding, ...]) -> list[str]:
    if not findings:
        return []
    lines = ["<h2>Problems</h2>"]
    # The findings arrive sorted by path, so each file forms one group.
    for path, group in groupby(findings, key=lambda finding: finding.path):
        in_file = list(group)
        lines += [
            '<section class="file">',
            f'<h3>{_text(path)} <span class="count">({len(in_file)})</span></h3>',
            "<ol>",
            *(_finding(finding) for finding in in_file),
            "</ol>",
            "</section>",
        ]
    return lines


def _finding(finding: Finding) -> str:
    severity = finding.severity.name.lower()
    confidence = finding.confidence.name.lower()
    return (
        f'<li class="finding {severity}">'
        '<div class="top">'
        f'<span class="badge {severity}">{severity}</span>'
        f'<span class="rule">{_text(finding.rule_id)}</span>'
        f'<span class="place">line {finding.line}, column {finding.column}</span>'
        f'<span class="confidence">confidence: {confidence}</span>'
        "</div>"
        f"<p>{_text(finding.message)}</p>"
        "</li>"
    )


def _silenced(silenced: tuple[Silenced, ...]) -> list[str]:
    """List the findings hidden by a comment, each with the reason given."""
    if not silenced:
        return []
    lines = ["<h2>Silenced by a comment</h2>", '<section class="file">', "<ul>"]
    for item in silenced:
        finding = item.finding
        place = f"{finding.path}:{finding.line}"
        reason = item.reason or "No reason given."
        lines.append(
            f'<li class="failure"><span class="rule">{_text(place)} '
            f"{_text(finding.rule_id)}</span> {_text(reason)}</li>"
        )
    lines += ["</ul>", "</section>"]
    return lines


def _failures(failures: tuple[ParseFailure, ...]) -> list[str]:
    if not failures:
        return []
    lines = [
        "<h2>Files that could not be scanned</h2>",
        '<section class="file">',
        "<ul>",
    ]
    for failure in failures:
        place = failure.relative_path
        if failure.line is not None:
            place += f":{failure.line}"
        lines.append(
            f'<li class="failure"><span class="rule">{_text(place)}</span> '
            f"{_text(failure.message)}</li>"
        )
    lines += ["</ul>", "</section>"]
    return lines
