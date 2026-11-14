# Changelog

What changed in each version of SecureLint, newest first.

## Unreleased

- Settings in `pyproject.toml`: `exclude` leaves files and directories out
  of a scan, `ignore` turns rules off. A mistake in the settings stops the
  scan instead of being skipped.
- One finding can be silenced with a comment on its line:
  `# securelint: ignore[SL102] reason`. Silenced findings are counted and
  listed in the reports, and a comment that silences nothing is reported as
  `SL001`.
- Each finding has a `fingerprint` in the JSON report: an identity that
  does not change when lines are added or removed elsewhere in the file.
- `securelint baseline` records the findings a project has today in
  `.securelint-baseline.json`. Later scans report only new findings; the
  known ones are counted, and listed in the JSON and HTML reports.

## 0.2.0 (2026-11-13)

Data-flow analysis: the rules follow a value from where it is created to
where it is used, inside one file.

- Rules look through a variable to the value it was given, inside one
  function. A query built on one line and run on the next is now reported,
  and a fixed value kept in a variable is no longer reported. This is done
  only when the variable is assigned exactly once.
- A function kept in a variable is followed: after `run = os.system`,
  `run(command)` is checked as `os.system(command)`.
- A value set once at the top of a file is known inside the functions of
  that file, and fixed pieces put together (`"ls " + "-l"`, an f-string of
  fixed values, `", ".join("?" for _ in ids)`) count as fixed. This removes
  false alarms.
- A finding whose value comes from a web request, `input()`, `sys.argv` or
  `sys.stdin` is reported with high confidence, and its message says where
  the value comes from and on which line.
- Corpus: 54 dangerous lines reported (was 50), 9 missed (was 13), 4 safe
  lines reported by mistake (was 8).
- Speed: 314 files per second on Python's standard library (was 299).

Known limits: a value passed from one function to another is not followed,
and a variable assigned more than once is not followed.

## 0.1.0 (2026-11-12)

The first release: a working scanner for Python source code.

### Scanning

- `securelint scan [path]` scans one Python file, or every Python file in a
  directory. Hidden directories, `__pycache__`, `node_modules`, virtual
  environments and symbolic links are skipped.
- Files are only parsed, never imported or run. A file that cannot be read or
  parsed is reported and the scan continues with the others.
- Exit codes for scripts and CI jobs: `0` no problems, `1` problems found,
  `2` the scan could not be completed.

### Rules

- **SL101**: `eval()` or `exec()` called with a value built at run time.
- **SL102**: a shell command built at run time (`os.system()`,
  `subprocess` with `shell=True`, and similar).
- **SL103**: data loaded with a format that can run code (`pickle`, `dill`,
  `marshal`, `yaml.load()` without a safe loader).
- **SL104**: a password or key written directly in the code.
- **SL105**: an SQL query with values put into its text.
- Rules follow imports, so `import subprocess as sp` and
  `from os import system as sh` are understood.

### Reports

- Text report for the terminal (the default).
- `--format json`: the full result as a JSON document.
- `--format html`: one self-contained page to open in a browser, with no
  script and no network access.

### Quality

- An annotated corpus of example files measures the rules: 50 dangerous
  lines reported, 13 missed, 8 safe lines reported by mistake.
- A benchmark script measures scan speed: 299 files per second on Python's
  standard library, on the author's laptop.
- Every change is checked on Python 3.11 and 3.14 with Ruff, mypy (strict)
  and pytest.

### Known limits

- A value that passes through a variable before reaching a dangerous call is
  not followed (`query = f"..."` then `cursor.execute(query)`).
- `from module import *` is not followed.
- There is no configuration file and no way to silence a finding yet.
