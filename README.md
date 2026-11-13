# SecureLint

SecureLint is a security scanner and CI policy gate for Python projects.
It is built step by step, and this README describes only what works today.

**Status:** version 0.2.0. `securelint scan` finds the Python files in a
project, parses them and checks them against the five rules listed below,
following values through variables, then writes a text, JSON or HTML report.
See the
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

## Settings

SecureLint reads its settings from the project's `pyproject.toml`:

```toml
[tool.securelint]
exclude = ["tests/fixtures", "docs/examples.py"]
ignore = ["SL104"]
```

| Setting | Meaning |
|---------|---------|
| `exclude` | Files and directories to leave out. Paths are relative to the `pyproject.toml`. |
| `ignore` | Rules to turn off, by id. |

The file is looked for in the scanned directory, then in the directories above
it, up to the top of the Git repository. When settings are used, SecureLint
says so on standard error.

A file or directory named on the command line is always scanned, even if the
settings exclude it: `securelint scan tests/fixtures` scans that folder.

A mistake in the settings stops the scan with exit code 2: an unknown setting,
an unknown rule or a wrong type is an error, never skipped silently.

## Silencing one finding

When a reported line has been checked and is fine, say so on that line, naming
the rule:

```python
os.system(command)  # securelint: ignore[SL102] command is our own setting
```

- The rule must be named. Several can be given: `ignore[SL101, SL102]`. There
  is no way to silence everything on a line.
- The text after the brackets is the reason. It is optional, and shown in the
  reports.
- The comment goes on the line where the finding is reported. For a call
  written on several lines, that is its first line.
- A silenced finding is not thrown away: the summary counts it, and the JSON
  and HTML reports list it with its reason.
- A comment that silences nothing is reported as `SL001`: the rule reports
  nothing on that line any more, the rule does not exist, or the comment is
  not written correctly.

## Rules

| ID | Severity | What it reports |
|----|----------|-----------------|
| SL001 | Low | A `securelint:` comment that silences nothing. |
| SL101 | High | `eval()` or `exec()` called with a value built at run time. A fixed string such as `eval("2 + 2")` is not reported. |
| SL102 | High | A shell command built at run time: `os.system()`, `os.popen()`, `subprocess.getoutput()`, or a `subprocess` call with `shell=True`. A fixed command, or a list of arguments without `shell=True`, is not reported. |
| SL103 | High | Data loaded with a format that can run code: `pickle`, `dill` or `marshal` loading, and `yaml.load()` without a safe loader. `yaml.safe_load()` and JSON are not reported. |
| SL104 | Medium | A password or key written directly in the code, such as `password = "hunter2"`, `connect(password="hunter2")` or `{"api_key": "sk-live-123"}`. The rule reads the name, so `password_field = "password"`, empty strings and placeholders such as `"<password>"` are not reported. The secret itself is never printed in the report. |
| SL105 | High | An SQL query with values put into its text, passed to `execute()`, `executemany()`, `executescript()` or `raw()`: `"..." + name`, an f-string, `"..." % name` or `"...".format(name)`. A fixed query with the values passed separately, such as `execute("... WHERE id = ?", (user_id,))`, is not reported. |

Rules follow imports, so a function is recognised under any name the file gives
it: `import subprocess as sp`, `from os import system` and
`from os import system as sh` are all understood.

Rules also look through a variable to the value it was given, inside one
function:

```python
query = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(query)  # reported: the query is built from a value

command = "ls -l"
os.system(command)  # not reported: the command is fixed
```

A function kept in a variable is followed the same way: after
`run = os.system`, the call `run(command)` is checked as `os.system(command)`.

This is done only when the variable is assigned exactly once. A variable
assigned twice, changed with `+=`, or received as a parameter has no single
value, and is treated as before.

A value set once at the top of a file is known inside every function of that
file, and fixed pieces put together are still fixed. None of these is reported:

```python
TABLE = "users"


def find(cursor, ids):
    marks = ", ".join("?" for _ in ids)  # only "?" and ", ", however many
    cursor.execute(f"SELECT * FROM {TABLE} WHERE id IN ({marks})", ids)


os.system("ls " + "-l")
```

### Confidence

Every finding has a confidence: how sure SecureLint is that the problem is
real. It is shown in the JSON and HTML reports.

Most findings are **medium**: the value is not fixed, but SecureLint cannot see
where it comes from. A finding becomes **high** when the value is followed back
to a place where outside data enters the program: a web request
(`request.args`, `request.form`, `request.GET`...), `input()`, `sys.argv` or
`sys.stdin`. The message then says where:

```python
name = request.args["name"]
query = f"SELECT * FROM users WHERE name = '{name}'"
cursor.execute(query)
# ... Here the value comes from request.args on line 1.
```

## How well does it detect?

The rules are measured against a set of annotated example files in
[tests/corpus](tests/corpus/README.md). Every dangerous line there is marked,
including the ones SecureLint does not find yet.

| | Count |
|---|---:|
| Dangerous lines reported | 54 |
| Dangerous lines missed | 9 |
| Safe lines reported by mistake | 4 |

The misses are cases the scanner cannot follow yet, such as a shell started
by hand (`subprocess.run(["sh", "-c", command])`) or a password inside a
database address.
Version 0.1.0 reported 50, missed 13 and had 8 false alarms. These examples were written for this
project, so the
numbers show what works and what does not today, not results on real projects.

The corpus files contain dangerous code on purpose, so this repository's own
settings leave that folder out of a normal scan.

## How fast is it?

Measured by scanning Python's own standard library with all five rules
(`python benchmarks/scan_speed.py`), keeping the fastest of five runs:

| | Version 0.1.0 | Version 0.2.0 |
|---|---|---|
| Code scanned | 3,659 files, 58.6 MB | 3,659 files, 58.6 MB |
| Time | 12.25 s | 11.64 s |
| Speed | 299 files per second | 314 files per second |
| Measured on | 2026-11-12 | 2026-11-13 |

Both were measured on the same laptop with Python 3.13.5 on Windows 11.

Version 0.2.0 does more work for each file, because it follows values through
variables, yet it is not slower. A first attempt at that feature walked every
file twice and took 25 s; this benchmark showed it, and the two walks were
merged into one.

This is one laptop, so the numbers are a reference point for later versions
and not a promise. The very first scan of files the system has not read
recently is much slower (131 s when version 0.1.0 was measured), because the
time then goes to reading from the disk.

## License

MIT. See [LICENSE](LICENSE).
