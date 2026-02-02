# Contributing

Thanks for your interest in improving OSINT Source Audit!

## Development setup
1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e .[dev]
   ```
2. Run linting and tests:
   ```bash
   make lint
   make test
   ```

## Pull requests
- Keep changes focused and include tests where possible.
- Update documentation if behavior changes.
- Ensure `make lint` and `make test` pass before requesting review.
