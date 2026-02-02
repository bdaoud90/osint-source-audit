.PHONY: install lint test run

install:
	pip install -e .[dev]

lint:
	ruff check src tests

test:
	pytest

run:
	osint-source-audit audit --config examples/config.yaml --output reports
