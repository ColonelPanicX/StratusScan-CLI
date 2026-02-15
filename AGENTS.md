# Repository Guidelines

## Project Structure & Module Organization
Core CLI entry points are at the repo root: `stratusscan.py` (main interface), `configure.py` (setup), and `utils.py` (shared helpers).  
AWS service exporters live in `scripts/` and follow the pattern `*-export.py` (for example, `scripts/ec2-export.py`, `scripts/iam-comprehensive-export.py`).  
Smart Scan logic is in `scripts/smart_scan/` (`analyzer.py`, `executor.py`, `mapping.py`, `selector.py`).  
Tests are in `tests/` with additional Smart Scan-focused tests in `tests/smart_scan/`.  
Policy templates and permission docs are in `policies/`; generated artifacts commonly go to `output/` and logs to `logs/`.

## Build, Test, and Development Commands
- `pip install -e ".[dev]"`: install package plus developer tooling.
- `python stratusscan.py`: launch interactive CLI.
- `python configure.py`: run interactive configuration/validation.
- `pytest`: run full test suite with coverage settings from `pyproject.toml`.
- `pytest -m "not slow"`: skip slower tests when iterating.
- `black .`: format Python code (line length 100).
- `ruff check .`: run lint checks.
- `mypy .`: run static type checks.
- `pre-commit install`: enable local quality/security hooks.

## Coding Style & Naming Conventions
Use Python 3.9+ and 4-space indentation. Keep code Black-formatted and Ruff-clean before opening a PR.  
Module and file names use `snake_case`; exporter scripts use descriptive kebab-style prefixes plus `-export.py`.  
Functions/variables use `snake_case`, classes use `PascalCase`, constants use `UPPER_SNAKE_CASE`.  
Prefer explicit type hints for new/modified functions, especially in shared utilities.

## Testing Guidelines
Pytest is the test framework; test discovery is configured in `pyproject.toml`:
- files: `test_*.py`
- classes: `Test*`
- functions: `test_*`

Add unit tests for new behavior and regression tests for bug fixes. Keep tests deterministic and mock AWS calls (`moto`/mocks) instead of requiring live credentials. Use markers (`slow`, `integration`, `aws`) appropriately.

## Commit & Pull Request Guidelines
Recent history favors short, imperative commit subjects (for example, `Fix ...`, `Implement ...`, `Add ...`). Keep subject lines specific to one logical change.  
For PRs, include:
- clear summary of what changed and why
- linked issue(s) when applicable
- test evidence (command(s) run, key output)
- notes on AWS scope/risk (services, regions, permissions impact)
- sample output/screenshots when CLI behavior or export format changes
