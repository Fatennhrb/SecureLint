# Changelog

What changed in each version of SecureLint, newest first.

## Unreleased

- Lint, SecureLint's mascot, in `assets/lint`: a small hooded guardian
  with code-bracket arms, a cape and a shield, in three moods (all clean,
  thinking, found a problem). Plain SVG files with no script and nothing
  loaded from elsewhere; they stay still when "reduce motion" is on.

## 1.0.0 (2026-11-16)

Measured, threat-modelled and installable: `pip install securelint`. The
README's Stability section lists what stays the same across 1.x (commands,
exit codes, JSON and SARIF formats, rule ids, fingerprints, settings and the
Action's inputs).

- `benchmarks/compare_bandit.py` runs SecureLint and Bandit 1.9.4 on the
  annotated corpus and scores both the same way, by statement, for the five
  kinds of problems both look for. The README shows the results and what
  they leave out: the corpus favours SecureLint, and Bandit does better on
  hard-coded secrets.
- `docs/real-projects.md` sorts by hand every finding of SecureLint and
  Bandit on four real projects (Flask, Requests, HTTPie, Jinja):
  SecureLint 6 findings with 1 false alarm, Bandit 20 with 15.
  `benchmarks/real_projects.py` lists the findings again for any folder.
- `docs/threat-model.md` lists what SecureLint protects, what it does not
  trust, the attacks it was built against with the test behind each
  protection, and the remaining risks. A test fails if a named test
  disappears. `SECURITY.md` says how to report a vulnerability privately.
- The Action installs Anthropic's package only when the project's settings
  choose the `anthropic` provider, not for every `explain: "true"`.
- An OpenAI-compatible service that does not answer within 60 seconds is
  asked once more, at once; a second slow answer ends the attempt.
- Ready for PyPI: the package now has classifiers, keywords and project
  links, ships a `py.typed` marker, and the README's links are full
  addresses so they also work on PyPI. A new CI job builds the package,
  checks it with `twine check --strict`, and installs it in an empty
  environment to use it from outside the repository.
- A Release workflow publishes with PyPI's Trusted Publishing (no password
  or token stored anywhere) and digital attestations: by hand to TestPyPI
  as a rehearsal, and on a `v*` tag to TestPyPI then PyPI, after checking
  that the tag matches the package version. `docs/releasing.md` explains
  the one-time setup and the steps of a release. A rehearsal published 0.6.0
  to TestPyPI with attestations naming this repository and workflow.
- The README explains installing from PyPI and what is stable in 1.x.
- The corpus numbers are unchanged (54 reported, 9 missed, 4 reported by
  mistake).

Known limits: the rules find five kinds of problems in Python code, not all
security problems; a pull request can silence its own findings, which is
visible but not blocked (see the threat model); there is no size limit on
scanned files.

## 0.6.0 (2026-11-15)

AI explanations: a few plain words under each finding, from the AI the
project chooses, without ever changing what blocks.

- `scan --explain` adds a short explanation, written by an AI, under each
  finding shown (at most 10), in the text and JSON reports. It is added
  after the policy has decided, so it never changes what blocks or the exit
  code, and an explanation that fails is only skipped.
- The AI is chosen in `[tool.securelint.ai]`: `anthropic` (Claude, through
  Anthropic's Python package, an optional extra:
  `pip install "securelint[anthropic]"`) or `openai-compatible` (OpenAI, or a
  local model such as Ollama, with no package). The key is read from an
  environment variable; a key written in the settings stops the scan. A
  `base-url` must be `https://`, or `http://` on this machine, and redirects
  are not followed. A busy OpenAI-compatible service (429 or 5xx) is asked
  again up to two times, waiting longer each time.
- Explanations are kept in `.securelint-cache/` (never committed, no code in
  it), so the same finding with the same lines around it is not sent to the
  AI again. A damaged or unwritable cache is reported and changes nothing.
- The Action's `explain` input adds the explanations to the notes on a pull
  request; the key comes from a repository secret given to the step. Only
  the notes are explained, not the SARIF report, and pull requests from
  forks, which get no secrets, are checked as usual without explanations.
- What is sent to explain a finding is the finding and the 3 lines before
  and after it, never the whole file. Before it leaves, every string on the
  line of a hard-coded secret, the value of any name that sounds secret, and
  text shaped like a well-known key are replaced by `***`. Lines are cut at
  200 characters.
- The AI must answer with a JSON object holding an `explanation` and,
  optionally, a `fix`; any other answer is dropped. Control characters are
  removed and long answers are cut. Explanations are shown, labelled "AI
  explanation (may be wrong)", in the text, JSON and HTML reports and in the
  GitHub notes, never in the job summary.
- Tested for real with Gemini's free tier (`gemini-3.5-flash-lite`, through
  the `openai-compatible` provider), on the laptop and in GitHub Actions on
  [securelint-demo pull request #1](https://github.com/Fatennhrb/securelint-demo/pull/1).
  The Claude provider is tested against Anthropic's real package and a fake
  service, not yet with a real key.
- The corpus numbers are unchanged (54 reported, 9 missed, 4 reported by
  mistake).

Known limits: the Action installs Anthropic's package whenever `explain` is
on, even for another provider; a request that times out is not retried; on
Gemini's free tier Google may use what is sent, so it suits made-up code only.

## 0.5.0 (2026-11-15)

Dependencies and Dockerfiles: Trivy's findings go through the same gate as
the code's.

- `--trivy-report FILE` adds the vulnerable dependencies found by Trivy
  (`trivy fs --format json`) to the scan, as findings of rule `SL201` on the
  line that names the package. They go through the baseline, the policy and
  every report like the other findings. SecureLint reads the report; it does
  not run Trivy.
- The same report's failed configuration checks (Trivy's `misconfig`
  scanner) become findings of rule `SL202`, on the Dockerfile line Trivy
  points to.
- The Action's `trivy` input downloads Trivy 0.76.2, checks it against a
  pinned checksum before running it, and adds its report to the scan.
  SecureLint's own CI uses it, and
  [securelint-demo pull request #2](https://github.com/Fatennhrb/securelint-demo/pull/2)
  shows it on an old dependency and a Dockerfile.
- The summary counts the files a Trivy report has problems in among the
  files checked.
- The corpus numbers are unchanged (54 reported, 9 missed, 4 reported by
  mistake).

Known limits: SecureLint does not run Trivy itself outside the Action, and
does not scan built container images; a dependency is reported on the line
that names it, or on line 1 when no line does; "found in N files" counts the
files checked, not only those with problems.

## 0.4.0 (2026-11-15)

GitHub integration: findings appear on the lines a pull request changed.

- `--format sarif` writes the result in SARIF 2.1.0, the format GitHub reads
  for security tools, with paths from the top of the project and each
  finding's fingerprint.
- `--changed-since BRANCH` reports only findings on lines the current
  branch added or changed since it left BRANCH, asking Git for those
  lines. Findings elsewhere are counted and listed, not reported.
- `--format github` prints findings as notes GitHub Actions shows on the
  lines of a pull request, and adds a summary table to the job's page.
- The repository is a GitHub Action (`action.yml`): on a pull request it
  reports the findings on the changed lines and fails when something
  blocks. It needs no token and no write permission.
- SecureLint's own CI runs the Action on its code, and a demo repository,
  [securelint-demo](https://github.com/Fatennhrb/securelint-demo), shows it
  on a real pull request.
- The corpus numbers are unchanged (54 reported, 9 missed, 4 reported by
  mistake).

Known limits: the Action does not upload SARIF itself; `--changed-since` needs
the target branch in the local history (`fetch-depth: 0`); a finding is shown
only when its own line changed, even if the change that caused it is on
another line.

## 0.3.0 (2026-11-14)

Policy and configuration: what a team needs to use the scanner every day.

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
- A policy in `[tool.securelint.policy]` sets the severity and confidence
  from which a finding blocks. Findings below it are reported as warnings
  and do not fail the scan. Without a policy, every finding still blocks.
- The corpus numbers are unchanged (54 reported, 9 missed, 4 reported by
  mistake), and the scan is not slower than in 0.2.0 when both are timed
  side by side.

Known limits: `exclude` takes exact paths, not patterns; a silencing comment
must be on the line where the finding is reported; editing a line listed in
the baseline, even its comment, makes its finding new again.

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
