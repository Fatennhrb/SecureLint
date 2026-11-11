# SecureLint

SecureLint is a security scanner and CI policy gate for Python projects.
It is built step by step, and this README describes only what works today.

**Status:** early. `securelint scan` finds the Python files in a project, parses
them and checks them against the rules listed below. There are three rules so far.

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
```

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

## License

MIT. See [LICENSE](LICENSE).
