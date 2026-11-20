> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> These measurements use a project-authored corpus; they must not be interpreted as independent proof of superior real-world accuracy.

## How well does it detect?

The rules are measured against a set of annotated example files in
[tests/corpus](https://github.com/Fatennhrb/SecureLint/blob/main/tests/corpus/README.md). Every dangerous line there is marked,
including the ones SecureLint does not find yet.

| | Count |
|---|---:|
| Dangerous lines reported | 58 |
| Dangerous lines missed | 5 |
| Safe lines reported by mistake | 4 |

The misses are cases the scanner cannot follow yet, such as options passed in
a dictionary (`subprocess.run(command, **options)`) or a short password given
as a default value.
Version 0.1.0 reported 50, missed 13 and had 8 false alarms; before the checks
for `pandas`, shells started by hand and passwords in addresses, 54, 9 and 4. These examples were written for this
project, so the
numbers show what works and what does not today, not results on real projects.

The corpus files contain dangerous code on purpose, so this repository's own
settings leave that folder out of a normal scan.

### Compared with Bandit

[Bandit](https://github.com/PyCQA/bandit) is the best-known security linter
for Python. Both tools were run on the same corpus and scored the same way,
for the five kinds of problems both look for
(`python benchmarks/compare_bandit.py`, with Bandit 1.9.4):

| Kind of problem | Dangerous lines | SecureLint found | missed | false alarms | Bandit found | missed | false alarms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Code execution (eval, exec) | 8 | 8 | 0 | 0 | 5 | 3 | 2 |
| Shell command injection | 13 | 12 | 1 | 1 | 10 | 3 | 6 |
| Unsafe deserialization | 14 | 14 | 0 | 1 | 12 | 2 | 2 |
| Hard-coded secret | 16 | 12 | 4 | 2 | 12 | 4 | 7 |
| SQL injection | 12 | 12 | 0 | 0 | 10 | 2 | 4 |
| **Total** | **63** | **58** | **5** | **4** | **49** | **14** | **21** |

With only its medium and high confidence findings, Bandit finds 46, misses 17
and has 18 false alarms.

How to read these numbers:

- **The corpus favours SecureLint.** It was written while building
  SecureLint's rules, and it decides what counts as dangerous: a fixed
  command or a fixed `eval("2 + 2")` counts as safe. Bandit warns about every
  `os.system` and every `eval` by design, which are false alarms here and a
  deliberate choice there.
- **Both find 12 hard-coded secrets, but not the same ones.** Bandit finds a
  password given as a default value, compared with `==`, and named
  `SESSION_TOKEN`, which SecureLint misses.
- **SecureLint does better where values or functions go through a variable**
  (`run = os.system`, `query = f"..."` then `execute(query)`) and on calls such
  as `builtins.eval` or `yaml.unsafe_load`.
- **One case is scored strictly:** when a query is built on one line and run
  on the next, Bandit reports the line that builds it and the corpus marks the
  line that runs it. Counted as found, Bandit would have 50 found, 13 missed
  and 20 false alarms.
- **Bandit checks far more than these five kinds**; only the shared ones are
  compared. Its checks that make another claim (an import of `pickle`, a
  subprocess without a shell) are left out.

Lines are compared by statement, so a call written over several lines counts
once, whichever of its lines a tool names.

### On real projects

On code it was never written for (the shipped packages of Flask, Requests,
HTTPie and Jinja, at fixed releases), SecureLint reported 6 findings in 146
files: 2 real risks (Jinja loading its bytecode cache with `pickle` and
`marshal`), 3 dangerous-by-design cases worth knowing about, and 1 false
alarm. Bandit, on the same five kinds of problems, reported the same 5 plus
15 false alarms, mostly variables named `token` or `password` set to `None`.
Every finding, the verdict on it and its reason are in
[docs/real-projects.md](https://github.com/Fatennhrb/SecureLint/blob/main/docs/real-projects.md), with what this check cannot
show: it counts false alarms, not misses.
