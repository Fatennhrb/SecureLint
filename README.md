# SecureLint

SecureLint is a security scanner and CI policy gate for Python projects.
It is built step by step, and this README describes only what works today.

**Status:** version 0.1.0, the first release. `securelint scan` finds the Python
files in a project, parses them and checks them against the five rules listed
below, then writes a text, JSON or HTML report. See the
[changelog](CHANGELOG.md) for what each version contains.

## Requirements

- Python 3.11 or newer

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Checks to run before every commit:

```bash
python -m ruff check .            # lint
python -m ruff format --check .   # formatting (drop --check to apply it)
python -m mypy                    # type check (strict mode)
python -m pytest                  # tests
```

GitHub Actions runs the same four checks on every push to `main` and on every
pull request, on Python 3.11 and 3.14 (see [ci.yml](.github/workflows/ci.yml)).

## Usage

```bash
securelint --version
securelint scan              # scan the current directory
securelint scan src/         # scan one directory
securelint scan app.py       # scan one file
securelint scan src/ --format json > report.json
securelint scan src/ --format html > report.html
```

`--format json` writes the same result as a JSON document for other programs
to read: a summary, then every finding with its rule, severity, confidence,
path, line, column and message, and the files that could not be scanned.

`--format html` writes one page to open in a browser: a summary, then the
problems grouped by file. The page is a single file with its style inside. It
contains no script and loads nothing from the network, and every file name and
message is escaped before it is written into the page.

The exit code tells a script or a CI job what happened:

| Code | Meaning |
|------|---------|
| 0 | The scan finished and found no problems. |
| 1 | The scan finished and found at least one problem. |
| 2 | The scan could not be completed: wrong command line, a path that does not exist, or a file that could not be read or parsed. |

## Rules

| ID | Severity | What it reports |
|----|----------|-----------------|
| SL101 | High | `eval()` or `exec()` called with a value built at run time. A fixed string such as `eval("2 + 2")` is not reported. |
| SL102 | High | A shell command built at run time: `os.system()`, `os.popen()`, `subprocess.getoutput()`, or a `subprocess` call with `shell=True`. A fixed command, or a list of arguments without `shell=True`, is not reported. |
| SL103 | High | Data loaded with a format that can run code: `pickle`, `dill` or `marshal` loading, and `yaml.load()` without a safe loader. `yaml.safe_load()` and JSON are not reported. |
| SL104 | Medium | A password or key written directly in the code, such as `password = "hunter2"`, `connect(password="hunter2")` or `{"api_key": "sk-live-123"}`. The rule reads the name, so `password_field = "password"`, empty strings and placeholders such as `"<password>"` are not reported. The secret itself is never printed in the report. |
| SL105 | High | An SQL query with values put into its text, passed to `execute()`, `executemany()`, `executescript()` or `raw()`: `"..." + name`, an f-string, `"..." % name` or `"...".format(name)`. A fixed query with the values passed separately, such as `execute("... WHERE id = ?", (user_id,))`, is not reported. |

Rules follow imports, so a function is recognised under any name the file gives
it: `import subprocess as sp`, `from os import system` and
`from os import system as sh` are all understood.

## How well does it detect?

The rules are measured against a set of annotated example files in
[tests/corpus](tests/corpus/README.md). Every dangerous line there is marked,
including the ones SecureLint does not find yet.

| | Count |
|---|---:|
| Dangerous lines reported | 50 |
| Dangerous lines missed | 13 |
| Safe lines reported by mistake | 8 |

The misses are mostly values that pass through a variable before reaching the
dangerous call (`query = f"..."` then `cursor.execute(query)`), which the
scanner cannot follow yet. These examples were written for this project, so the
numbers show what works and what does not today, not results on real projects.

Scanning this repository itself reports the corpus files, since they contain
dangerous code on purpose.

## How fast is it?

Measured by scanning Python's own standard library with all five rules
(`python benchmarks/scan_speed.py`), keeping the fastest of five runs:

| | |
|---|---|
| Code scanned | 3,659 files, 58.6 MB |
| Time | 12.25 s |
| Speed | 299 files per second (4.8 MB per second) |
| Measured with | SecureLint 0.1.0.dev0, Python 3.13.5, Windows 11, on 2026-11-12 |

This is one laptop, so the number is a reference point for later versions and
not a promise. The very first scan of files the system has not read recently
was much slower (131 s in this measurement), because the time then goes to
reading from the disk. A profile shows about half of the scan time is spent
walking the syntax trees and about a quarter parsing the files; the rules
themselves are a small part.

## License

MIT. See [LICENSE](LICENSE).
