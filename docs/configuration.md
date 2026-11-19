> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> Policies, configuration, targeted suppression comments, baselines and fingerprints.

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
