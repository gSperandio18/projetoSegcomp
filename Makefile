.PHONY: help install lint format test cov-html docs-build db-init run-demo run-audit clean

PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest
RUFF := ruff
PYLINT := pylint
MKDOCS := mkdocs

help:
	@echo "========================================================================"
	@echo "        SECURE E-VOTING SYSTEM - AUTOMATION MAKEFILE (SEGCOMP 2026)"
	@echo "========================================================================"
	@echo "  make install     : Install main and development dependencies"
	@echo "  make lint        : Run code quality linters (Ruff + Pylint)"
	@echo "  make format      : Automatically format code using Ruff"
	@echo "  make test        : Run pytest suite with 80%+ coverage enforcement"
	@echo "  make cov-html    : Generate HTML coverage report"
	@echo "  make docs-build  : Build technical documentation via MkDocs"
	@echo "  make db-init     : Initialize SQLite schema for election server"
	@echo "  make run-demo    : Run complete CLI election simulation (Interactive)"
	@echo "  make run-audit   : Run independent audit script against public board"
	@echo "  make clean       : Remove temporary cache, coverage, and build artifacts"
	@echo "========================================================================"

install:
	$(PIP) install --upgrade pip
	$(PIP) install -e .[dev]
	pre-commit install

lint:
	$(RUFF) check src tests bin
	$(PYLINT) src/evoting

format:
	$(RUFF) format src tests bin
	$(RUFF) check --fix src tests bin

test:
	$(PYTEST)

cov-html:
	$(PYTEST) --cov-report=html
	@echo "Coverage report rendered at htmlcov/index.html"

docs-build:
	$(MKDOCS) build

db-init:
	$(PYTHON) -c "from evoting.storage.database import init_db; init_db()"
	@echo "Election SQLite database initialized successfully."

run-demo:
	PYTHONPATH=src $(PYTHON) bin/election_cli.py

run-audit:
	PYTHONPATH=src $(PYTHON) bin/audit_cli.py --demo

clean:
	rm -rf build/ dist/ *.egg-info .eggs/
	rm -rf .pytest_cache/ htmlcov/ .coverage coverage.xml
	rm -rf .ruff_cache/
	rm -rf site/
	rm -f election.db audit_report.json
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[cod]" -delete
	@echo "Workspace cleaned successfully."
