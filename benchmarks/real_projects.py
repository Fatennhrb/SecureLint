"""List what SecureLint and Bandit report on real projects, to sort by hand.

Usage::

    python benchmarks/real_projects.py PATH [PATH...]

Each PATH is a folder of Python code, such as the package a project ships.
For each one, the script prints the files scanned, every SecureLint
finding, and every Bandit finding of the five kinds both tools look for
(see ``compare_bandit.py``). Deciding which findings are real is done by a
person reading the code; docs/real-projects.md holds those decisions.

The script only reads and parses the code; it never runs it.
"""

import argparse
import importlib.util
from pathlib import Path
from types import ModuleType

from securelint.engine import scan
from securelint.rules import ALL_RULES


def _compare_bandit() -> ModuleType:
    """Load compare_bandit.py from this folder, for its Bandit mapping."""
    path = Path(__file__).with_name("compare_bandit.py")
    spec = importlib.util.spec_from_file_location("compare_bandit", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report(folder: Path, compare: ModuleType) -> list[str]:
    """Return the findings of both tools in ``folder``, one per line."""
    result = scan(folder, ALL_RULES)
    lines = [f"== {folder} ({result.files_scanned} files)"]
    lines.append(f"SecureLint: {len(result.findings)}")
    lines += [
        f"  {finding.path}:{finding.line}  {finding.rule_id}"
        for finding in result.findings
    ]
    # Bandit's paths include the folder; only the part inside it is shown.
    bandit = sorted(compare.bandit_cases(folder)[0])
    lines.append(f"Bandit (shared kinds): {len(bandit)}")
    lines += [f"  {name}:{line}  {kind}" for name, line, kind in bandit]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="List SecureLint and Bandit findings on real projects."
    )
    parser.add_argument("folders", nargs="+", type=Path, help="folders to scan")
    args = parser.parse_args(argv)

    compare = _compare_bandit()
    for folder in args.folders:
        if not folder.is_dir():
            parser.error(f"not a folder: {folder}")
        print("\n".join(report(folder, compare)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
