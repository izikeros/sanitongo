# Makefile for Sanitongo development

.PHONY: help install install-dev test test-cov test-security lint format type-check security-check clean build publish docs setup-dev

# Default target
help:
	@echo "Sanitongo Development Commands"
	@echo "=============================="
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make install          Install package in current environment"
	@echo "  make install-dev      Install package with dev dependencies"
	@echo "  make setup-dev        Full development environment setup"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run all tests"
	@echo "  make test-cov         Run tests with coverage report"
	@echo "  make test-security    Run security-focused tests only"
	@echo "  make test-watch       Run tests in watch mode"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint             Run all linters (ruff)"
	@echo "  make format           Format code with ruff"
	@echo "  make type-check       Run type checking with mypy"
	@echo "  make security-check   Run security checks (bandit, safety)"
	@echo "  make pre-commit       Run all pre-commit hooks"
	@echo ""
	@echo "Development:"
	@echo "  make clean            Clean build artifacts and cache"
	@echo "  make build            Build package for distribution"
	@echo "  make publish          Publish package to PyPI"
	@echo "  make docs             Generate documentation"
	@echo ""
	@echo "Release Management:"
	@echo "  make release-patch    Bump patch version and prepare release"
	@echo "  make release-minor    Bump minor version and prepare release"
	@echo "  make release-major    Bump major version and prepare release"
	@echo "  make update-changelog Generate/update changelog with git-cliff"
	@echo "  make show-version     Show current version"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build     Build Docker image"
	@echo "  make docker-test      Run tests in Docker"

# Setup & Installation
install:
	uv sync

install-dev:
	uv sync --dev

setup-dev: install-dev
	uv run pre-commit install
	@echo "Development environment setup complete with uv!"

# Testing
test:
	uv run pytest

test-cov:
	uv run pytest --cov=src/sanitongo --cov-report=html --cov-report=term-missing --cov-report=xml

test-security:
	uv run pytest tests/test_security.py -m security -v

test-watch:
	uv run pytest-watch

test-integration:
	uv run pytest tests/ -m integration -v

test-benchmark:
	uv run pytest tests/ -k "benchmark" --benchmark-only

# Code Quality
lint:
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

type-check:
	uv run ty check src/sanitongo

security-check:
	uv run bandit -r src/ -f json
	uv pip install pip-audit && uv run pip-audit

pre-commit:
	uv run pre-commit run --all-files

# Development
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	uv run python -m build

publish: build
	uv run twine check dist/*
	uv run twine upload dist/*

publish-test: build
	uv run twine check dist/*
	uv run twine upload --repository testpypi dist/*

# Documentation
docs:
	@echo "Generating documentation..."
	@echo "API documentation would be generated here"

# Docker
docker-build:
	docker build -t sanitongo:latest .

docker-test:
	docker run --rm -v $(PWD):/app -w /app sanitongo:latest make test

# Utilities
check-deps:
	uv run pip-audit

update-deps:
	uv sync --upgrade

# CI/CD helpers
ci-test: test-cov security-check type-check lint

ci-build: clean build
	twine check dist/*

# Development shortcuts
dev-check: lint type-check test-security
	@echo "Development checks passed!"

quick-test:
	uv run pytest tests/test_sanitizer.py -v

# Benchmarking
benchmark:
	uv run pytest tests/ --benchmark-only --benchmark-json=benchmark.json

profile:
	uv run python -m cProfile -s cumulative -m pytest tests/test_sanitizer.py

# Release helpers
version-patch:
	uv run bump-my-version bump patch

version-minor:
	uv run bump-my-version bump minor

version-major:
	uv run bump-my-version bump major

# Release targets
release-patch: clean test-cov security-check lint
	uv run bump-my-version bump patch
	$(MAKE) update-changelog
	git add -A
	git commit -m "chore(release): bump version to $$(uv run bump-my-version show current_version)"
	git tag "v$$(uv run bump-my-version show current_version)"
	@echo "Release prepared! Push with: git push origin main --tags"

release-minor: clean test-cov security-check lint
	uv run bump-my-version bump minor
	$(MAKE) update-changelog
	git add -A
	git commit -m "chore(release): bump version to $$(uv run bump-my-version show current_version)"
	git tag "v$$(uv run bump-my-version show current_version)"
	@echo "Release prepared! Push with: git push origin main --tags"

release-major: clean test-cov security-check lint
	uv run bump-my-version bump major
	$(MAKE) update-changelog
	git add -A
	git commit -m "chore(release): bump version to $$(uv run bump-my-version show current_version)"
	git tag "v$$(uv run bump-my-version show current_version)"
	@echo "Release prepared! Push with: git push origin main --tags"

update-changelog:
	uv run git-cliff --output CHANGELOG.md

show-version:
	@uv run bump-my-version show current_version

# Environment info
env-info:
	@echo "Python version: $(shell uv run python --version)"
	@echo "UV version: $(shell uv --version)"
	@echo "Virtual environment: $(shell uv python version)"
	@echo "Current directory: $(PWD)"

# Package info
pkg-info:
	uv show sanitongo

# Interactive development
shell:
	uv run python -i -c "from sanitongo import *; print('Sanitongo loaded and ready!')"

# Example usage
example:
	uv run python -c "from sanitongo import create_sanitizer; sanitizer = create_sanitizer(strict_mode=True); query = {'name': 'John', 'age': {'$$gte': 18}}; print('Sanitized:', sanitizer.sanitize_query(query) if sanitizer.is_query_safe(query) else 'Query blocked')"

# Configuration
config-example:
	uv run python -c "from sanitongo.config import generate_config_file; generate_config_file('example-config.json'); print('Example configuration generated: example-config.json')"

# UV-specific targets
uv-sync:
	uv sync

uv-sync-dev:
	uv sync --dev

uv-lock:
	uv lock

uv-add:
	@echo "Usage: make uv-add PKG=package_name"
	@if [ -n "$(PKG)" ]; then uv add $(PKG); else echo "Please specify PKG=package_name"; fi

uv-add-dev:
	@echo "Usage: make uv-add-dev PKG=package_name"
	@if [ -n "$(PKG)" ]; then uv add --dev $(PKG); else echo "Please specify PKG=package_name"; fi

uv-remove:
	@echo "Usage: make uv-remove PKG=package_name"
	@if [ -n "$(PKG)" ]; then uv remove $(PKG); else echo "Please specify PKG=package_name"; fi

uv-tree:
	uv tree

uv-outdated:
	uv sync --upgrade --dry-run