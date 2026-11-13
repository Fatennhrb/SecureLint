# Annotated corpus

Small example files that SecureLint is measured against. Some lines are
dangerous on purpose: **do not copy code from this folder.**

Each interesting line ends with a comment:

| Comment | Meaning |
|---------|---------|
| `# expect: SL101` | The line is dangerous, and SecureLint reports it. |
| `# missed: SL101` | The line is dangerous, but SecureLint does not report it yet. |
| `# false-alarm: SL101` | The line is safe, but SecureLint reports it anyway. |

A line without a comment must not be reported. A call written on several
lines carries its comment on the first line, where the finding is placed.

[test_corpus.py](../test_corpus.py) scans every file here and fails if the
findings differ from the comments in any way. So when a rule improves, the
test fails until `missed` is changed to `expect`, or `false-alarm` is removed.

## Current numbers

| Rule | Detected | Missed | False alarms |
|------|---------:|-------:|-------------:|
| SL101 | 8 | 0 | 0 |
| SL102 | 11 | 2 | 1 |
| SL103 | 13 | 1 | 1 |
| SL104 | 11 | 5 | 2 |
| SL105 | 11 | 1 | 0 |
| **Total** | **54** | **9** | **4** |

The same numbers are in `TOTALS` in the test, which fails if they stop
being true.

These numbers describe the cases in this folder only. The examples were
written by the project's author, who knows how the rules work, so they say
what SecureLint can and cannot do today, not how it performs on real projects.

## Adding a case

1. Add the code to the file for its rule, in the dangerous or the safe part.
2. Decide what the line *is* (dangerous or safe) before looking at what
   SecureLint says about it, then write the comment.
3. Run `python -m pytest tests/test_corpus.py` and update the numbers.
