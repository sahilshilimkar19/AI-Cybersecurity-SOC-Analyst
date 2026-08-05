# AI Cybersecurity SOC Analyst — developer task runner.
# Usage: `make <target>`. On Windows, run inside Git Bash or WSL, or invoke the
# underlying commands directly (see CONTRIBUTING.md).

.DEFAULT_GOAL := help
.PHONY: help install install-dev fmt lint typecheck test cov check up down clean \
        ui-install ui-dev ui-lint ui-test ui-build ui-check check-all

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime dependencies only
	pip install -e .

install-dev: ## Install runtime + development dependencies and pre-commit hooks
	pip install -e ".[dev]"
	pre-commit install

fmt: ## Auto-format the codebase
	ruff format .
	ruff check . --fix

lint: ## Lint (no changes)
	ruff check .
	ruff format --check .

typecheck: ## Static type checking
	mypy .

test: ## Run the test suite
	pytest

cov: ## Run tests with coverage report
	pytest --cov --cov-report=term-missing

check: lint typecheck test ## Run all backend quality gates (lint + types + tests)

# --- Frontend ---------------------------------------------------------------

ui-install: ## Install frontend dependencies from the lockfile
	cd frontend && npm ci

ui-dev: ## Run the analyst console against a local backend
	cd frontend && npm run dev

ui-lint: ## Lint + type-check the frontend
	cd frontend && npm run lint && npm run typecheck

ui-test: ## Run the frontend test suite
	cd frontend && npm test

ui-build: ## Produce a production bundle
	cd frontend && npm run build

ui-check: ui-lint ui-test ui-build ## Run all frontend quality gates

check-all: check ui-check ## Run every quality gate, backend and frontend

up: ## Start local infrastructure (PostgreSQL + pgvector, Redis, object store)
	docker compose up -d

down: ## Stop local infrastructure
	docker compose down

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
