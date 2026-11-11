# SecureLint

SecureLint is a security scanner and CI policy gate for Python projects.
It is built step by step, and this README describes only what works today.

**Status:** project skeleton. The command line runs, but it has no security checks yet.

## Requirements

- Python 3.11 or newer

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

## Usage

```bash
securelint --version
```

## License

MIT. See [LICENSE](LICENSE).
