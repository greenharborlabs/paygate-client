# Developer Setup

## Development install

The package supports modern editable installs (`python3 -m pip install -e .`).
Older `pip` versions (for example `pip 21.2.4`) do not support PEP 660 editable
install behavior, so developers should upgrade first:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

## Verification commands

```bash
python3 -m pytest
python3 -m ruff check .
python3 -m ruff format --check .
python3 -m mypy
```
