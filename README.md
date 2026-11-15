# SecureLint

SecureLint is a security scanner and CI policy gate for Python projects.
It is built step by step, and this README describes only what works today.

**Status:** version 0.5.0. `securelint scan` finds the Python files in a
project, parses them and checks them against the five rules listed below,
following values through variables, then writes a text, JSON, HTML or SARIF
report. It can add the vulnerable dependencies and unsafe Dockerfile settings
that Trivy found. A project can set which findings block, silence a checked
finding, and accept the problems it already has while stopping new ones. As a
GitHub Action, it reports findings on the lines a pull request changed. See the
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
securelint scan --format sarif > securelint.sarif
securelint scan --format github   # inside GitHub Actions
```

`--format json` writes the same result as a JSON document for other programs
to read: a summary, then every finding with its rule, severity, confidence,
path, line, column and message, and the files that could not be scanned.

Each finding in the JSON report has a `fingerprint`: a short code built from
the rule, the file path and the text of the reported line, not its line number.
It stays the same when code is added or removed elsewhere in the file, and
changes when the reported line itself is edited.

`--format html` writes one page to open in a browser: a summary, then the
problems grouped by file. The page is a single file with its style inside. It
contains no script and loads nothing from the network, and every file name and
message is escaped before it is written into the page.

`--format sarif` writes SARIF 2.1.0, the standard format GitHub reads for
security tools. Uploaded to GitHub, the results appear in the repository's
Security tab and next to the changed lines of a pull request. Every finding is
written, with a level that follows the policy:

| SARIF level | Meaning |
|-------------|---------|
| `error` | The finding blocks. |
| `warning` | The policy reports it without blocking, or a comment silenced it (it is then also marked as suppressed). |
| `note` | The finding is listed in the baseline file (marked `"baselineState": "unchanged"`), or it is on a line the change did not touch (with `--changed-since`). |

Paths are written from the top of the project, whatever folder was scanned,
and each result carries its fingerprint so GitHub can follow it between scans.

`--format github` is meant for GitHub Actions. Each blocking finding is printed
as an error note and each warning as a warning note, in the form GitHub reads
by itself: they appear on the exact line of the pull request, without any
upload or extra permission. Known, silenced and out-of-change findings are only
counted. When GitHub gives a summary file (`GITHUB_STEP_SUMMARY`), SecureLint
also adds a table to the job's page with the verdict: passed, blocked or
incomplete. File names and messages are escaped, so a strange name cannot break
a note or create a fake one. GitHub limits how many notes it shows for one
step, so on a large project use SARIF as well.

The exit code tells a script or a CI job what happened:

| Code | Meaning |
|------|---------|
| 0 | The scan finished and nothing blocks. There may be warnings, if the project has a policy. |
| 1 | The scan finished and found at least one problem that blocks. |
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
| `policy` | Which findings block; see [Deciding what blocks](#deciding-what-blocks). |

The file is looked for in the scanned directory, then in the directories above
it, up to the top of the Git repository. When settings are used, SecureLint
says so on standard error.

A file or directory named on the command line is always scanned, even if the
settings exclude it: `securelint scan tests/fixtures` scans that folder.

A mistake in the settings stops the scan with exit code 2: an unknown setting,
an unknown rule or a wrong type is an error, never skipped silently.

## Deciding what blocks

Without a policy, every finding makes `securelint scan` fail (exit code 1). A
policy says which findings must be fixed and which are only warnings:

```toml
[tool.securelint.policy]
block-severity = "high"
block-confidence = "medium"
```

| Setting | Values | Default |
|---------|--------|---------|
| `block-severity` | `"low"`, `"medium"`, `"high"`, `"critical"` | `"low"` |
| `block-confidence` | `"low"`, `"medium"`, `"high"` | `"low"` |

A finding blocks when it is at least that severe **and** the rule is at least
that sure. With the example above, a high-severity finding of medium confidence
blocks, while a medium-severity one is a warning.

Warnings are still reported: marked `(warning)` in the text report, and listed
apart in the JSON and HTML reports. They do not change the exit code, so a scan
with only warnings exits with 0.

The defaults are the lowest levels, so a project that writes no policy keeps
the strict behaviour.

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

## Starting on a project that already has problems

A project may have findings it cannot fix at once. The baseline lets it
accept what exists today and still stop anything new:

```bash
securelint baseline     # remember today's findings
securelint scan         # from now on, only new findings count
```

`securelint baseline` scans the whole project and writes
`.securelint-baseline.json` at its top (next to `pyproject.toml` or the `.git`
folder). Commit this file: the team then shares it, and every change to it is
visible in code review.

After that, `securelint scan`:

- reports new findings as before, and only they change the exit code;
- counts the known ones (`Known problems not shown: 12.`) and still lists them
  in the JSON and HTML reports;
- says so when a known finding is no longer found, so the baseline can be
  written again and does not keep entries for problems that were fixed.

A known finding stays known when the code around it moves, because it is
matched by its fingerprint. Editing the reported line makes it new again.

`securelint scan --no-baseline` shows everything, known or not.

## Using SecureLint in GitHub Actions

The repository is also a GitHub Action. Add this workflow to a project, as
`.github/workflows/securelint.yml`:

```yaml
name: SecureLint
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  securelint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0 # the whole history, to find the changed lines
          persist-credentials: false
      - uses: Fatennhrb/SecureLint@v0.5.0 # pin the commit in real use
```

On a pull request, SecureLint reports the findings on the lines the pull
request changed, as notes on those lines, adds a summary table to the job's
page, and fails the check when the project's policy says something blocks. On
a push, it scans everything. It needs no token and no write permission.

See it on a real pull request in the demo repository:
[securelint-demo pull request #1](https://github.com/Fatennhrb/securelint-demo/pull/1)
fails because of a shell command built from typed input, shows a warning for
a hard-coded password, and leaves alone an old problem listed in its baseline.
[Pull request #2](https://github.com/Fatennhrb/securelint-demo/pull/2) runs
Trivy too: it fails on a Dockerfile that runs as `root`, and warns about four
known vulnerabilities in an old `requests`.

| Input | Default | Meaning |
|-------|---------|---------|
| `path` | `.` | File or directory to scan. |
| `changed-only` | `true` | On a pull request, report only the changed lines. |
| `sarif-file` | (empty) | Also write a SARIF report of the whole scan to this file. |
| `python-version` | `3.13` | Python used to run SecureLint. The job's own Python is not changed. |
| `trivy` | `false` | Also check dependencies and Dockerfiles with Trivy (Linux runners only). |

To see the findings in the repository's Security tab as well, set
`sarif-file: securelint.sarif`, give the job the `security-events: write`
permission, and upload the file with the `upload-sarif` step of
`github/codeql-action`, pinned to a commit like the steps above. GitHub does
not let pull requests from forks upload SARIF; the notes on the lines still
work for them.

With `trivy: "true"`, the Action downloads Trivy 0.76.2 from its GitHub
release, checks the download against the checksum written in `action.yml`, and
runs it only if they match. Trivy then checks the same folder, and its report
is read as described in
[Checking dependencies and Dockerfiles with Trivy](#checking-dependencies-and-dockerfiles-with-trivy).
The version is pinned on purpose: Trivy's own release 0.69.4 was compromised in
March 2026 (CVE-2026-33634), so a new version is only used after it has been
checked and the pin changed.

The Action installs SecureLint from its own files, so `@v0.5.0` always runs
SecureLint 0.5.0; the `trivy` input exists from that version. Settings,
silencing comments, the baseline and the policy are read from the scanned
project as usual.

## Checking only what a change touched

```bash
securelint scan --changed-since main
```

SecureLint asks Git which lines the current branch added or changed since it
left `main`, including changes not committed yet, and reports only the findings
on those lines. A file Git does not track yet counts as changed in full.
Findings elsewhere are counted (`Outside the changed lines: 5.`) and listed in
the JSON, HTML and SARIF reports, but they do not change the exit code.

Settings, silencing comments, the baseline and the policy all still apply.

If Git is missing, the folder is not in a Git repository, or the branch cannot
be found, the scan stops with exit code 2: reporting nothing would look like a
clean change. In GitHub Actions, check out the whole history
(`fetch-depth: 0`), or Git cannot find where the branch started.

A change can make an unchanged line dangerous, for example by changing a value
that line reads. Such a finding is counted as outside the change, so run the
full scan as well, for example on `main` after each merge.

## Checking dependencies and Dockerfiles with Trivy

SecureLint checks the code you write. The packages a project uses can have
known vulnerabilities too, and its Dockerfile can have unsafe settings;
[Trivy](https://trivy.dev) finds both. SecureLint does not run Trivy: run it
yourself on the same folder, then give SecureLint its JSON report.

```console
trivy fs --scanners vuln,misconfig --format json --output trivy.json .
securelint scan . --trivy-report trivy.json
```

Each vulnerability becomes a finding of rule `SL201`, reported on the line of
`requirements.txt` (or of the lock file) that names the package, with the
installed version and the version that fixes it.

Each failed check of a Dockerfile (or of another configuration file Trivy
checks) becomes a finding of rule `SL202`, on the line Trivy points to, with
Trivy's check ID and how to fix it. A check about the whole file, such as a
missing `USER` line, is reported on line 1. Checks the file passed, and those
the project accepted as exceptions, are not reported. Trivy's secret scanner is
not read; rule `SL104` looks for secrets in the code.

The baseline, the policy, `--changed-since` and every report format work for
these findings as for the code's.
`securelint baseline --trivy-report trivy.json` records them as known; run
Trivy on the top of the project for that.

A dependency finding keeps its identity when other lines of the file change,
and becomes new when the package's version changes. A Dockerfile finding is
identified like the code's: by its check and the text of its line.

The report is checked before it is used: one that cannot be read, is not a
Trivy JSON report, or names a file outside the scanned folder stops the scan
with exit code 2, instead of being taken as "no problems".

## Explaining findings with an AI

`scan --explain` adds a short explanation, written by an AI, under each
finding shown: why the code is risky here and how to fix it. It is off unless
asked for, and the AI is the one the project chooses in its settings:

```toml
[tool.securelint.ai]
provider = "anthropic"            # Claude
model = "claude-opus-5-5"
api-key-env = "ANTHROPIC_API_KEY" # the variable that holds the key
```

```toml
[tool.securelint.ai]
provider = "openai-compatible"    # OpenAI, or a model on this machine
model = "llama3"
base-url = "http://localhost:11434/v1"  # here: Ollama, no key needed
```

| Setting | Meaning |
|---------|---------|
| `provider` | `"anthropic"` or `"openai-compatible"`. |
| `model` | The provider's name for the model. |
| `base-url` | Only for `openai-compatible`: where the service answers. It must be `https://`, or `http://` on this machine. |
| `api-key-env` | The environment variable that holds the key. The key itself is never written in the settings: a setting that looks like a key stops the scan. Optional for Anthropic, which then finds its key itself; leave it out for a local model. |

The `anthropic` provider uses Anthropic's own Python package, installed only
when asked for: `pip install "securelint[anthropic]"`. SecureLint itself still
needs nothing beyond Python. With the Claude models that support it, a request
the model declines is answered by Anthropic's fallback model in the same call.
The `openai-compatible` provider needs no package.

What the AI can and cannot do:

- It only explains. Explanations are added after the policy has decided what
  blocks, so they never change the exit code; one that fails is skipped and
  said on standard error.
- It receives the finding and the 3 lines around it, never the whole file. A
  hard-coded secret, the value of a name that sounds secret, and text shaped
  like a known key are replaced by `***` before anything is sent.
- Its answer must be the short JSON the prompt asks for, or it is dropped.
  Control characters are removed, and every report labels it "AI explanation
  (may be wrong)".
- At most 10 findings are explained in one scan, blocking ones first. Each
  explanation is a paid request to the provider, unless the model runs on this
  machine.

## Rules

| ID | Severity | What it reports |
|----|----------|-----------------|
| SL001 | Low | A `securelint:` comment that silences nothing. |
| SL101 | High | `eval()` or `exec()` called with a value built at run time. A fixed string such as `eval("2 + 2")` is not reported. |
| SL102 | High | A shell command built at run time: `os.system()`, `os.popen()`, `subprocess.getoutput()`, or a `subprocess` call with `shell=True`. A fixed command, or a list of arguments without `shell=True`, is not reported. |
| SL103 | High | Data loaded with a format that can run code: `pickle`, `dill` or `marshal` loading, and `yaml.load()` without a safe loader. `yaml.safe_load()` and JSON are not reported. |
| SL104 | Medium | A password or key written directly in the code, such as `password = "hunter2"`, `connect(password="hunter2")` or `{"api_key": "sk-live-123"}`. The rule reads the name, so `password_field = "password"`, empty strings and placeholders such as `"<password>"` are not reported. The secret itself is never printed in the report. |
| SL105 | High | An SQL query with values put into its text, passed to `execute()`, `executemany()`, `executescript()` or `raw()`: `"..." + name`, an f-string, `"..." % name` or `"...".format(name)`. A fixed query with the values passed separately, such as `execute("... WHERE id = ?", (user_id,))`, is not reported. |
| SL201 | From Trivy | A dependency with a known vulnerability, read from a Trivy report (see [Checking dependencies and Dockerfiles with Trivy](#checking-dependencies-and-dockerfiles-with-trivy)). Critical, high, medium and low come from Trivy; a vulnerability Trivy has no severity for yet counts as medium. |
| SL202 | From Trivy | An unsafe setting in a Dockerfile or another configuration file, read from a Trivy report: for example, a container that runs as `root`. Medium confidence: the setting may be on purpose. |

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

| | Version 0.1.0 | Version 0.2.0 | Version 0.3.0 | Version 0.4.0 | Version 0.5.0 |
|---|---|---|---|---|---|
| Code scanned | 3,659 files, 58.6 MB | 3,659 files, 58.6 MB | 3,659 files, 58.6 MB | 3,659 files, 58.6 MB | 3,659 files, 58.6 MB |
| Time | 12.25 s | 11.64 s | 14.06 s | 11.68 s | 11.77 s |
| Speed | 299 files per second | 314 files per second | 260 files per second | 313 files per second | 311 files per second |
| Measured on | 2026-11-12 | 2026-11-13 | 2026-11-14 | 2026-11-15 | 2026-11-15 |

All were measured on the same laptop with Python 3.13.5 on Windows 11.

The laptop itself was slower on 2026-11-14, so the 0.3.0 column cannot be
compared with the others. Version 0.2.0 was timed again that day, right
after version 0.3.0, and took 15.36 s. Measured side by side, version 0.3.0 is
therefore not slower than version 0.2.0. Its new features (settings, silencing
comments, fingerprints, the baseline and the policy) do their work only on
files that have findings, or after the scan.

Version 0.3.0 was timed again on 2026-11-15, right after version 0.4.0, and
took 11.65 s: the two are as fast as each other. The 0.4.0 features (SARIF,
GitHub notes, changed lines) only change what is reported after the scan.

Version 0.4.0 was timed again right before version 0.5.0 and took 11.75 s, so
these two are as fast as each other too. This benchmark scans Python code
only; reading a Trivy report adds the time Trivy itself takes, which depends
on Trivy and not on SecureLint.

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
