# AI Agent Instructions

## Project Overview

Modern MongoDB query sanitizer with layered security protection.

## Development Commands

```bash
make dev          # Set up development environment
make test         # Run tests
make test-cov     # Run tests with coverage
make lint         # Check code style
make format       # Auto-format code
make type-check   # Run type checker
make security     # Run security checks
make docs         # Build documentation
make serve-docs   # Serve docs locally
```

## Code Style

- Follow existing patterns in codebase
- Use type hints for all public functions
- Docstrings: Google style
- Line length: 88 (Ruff/Black default)
- Imports: sorted by Ruff (isort rules)

## Classifiers

When setting up or updating `pyproject.toml`:
1. Choose appropriate Development Status (Alpha/Beta/Production)
2. Uncomment relevant Intended Audience entries
3. Add Environment classifier if CLI tool (`Environment :: Console`)
4. Add `Typing :: Typed` if package has type hints
5. Select relevant Topic classifiers for discoverability

## Testing Requirements

- All new features require tests
- Maintain >80% coverage
- Run `make test-cov` before PR
- Security tests are critical for this project

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

| Type | Description |
|------|-------------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation changes |
| `refactor:` | Code refactoring |
| `test:` | Adding/updating tests |
| `chore:` | Maintenance tasks |
| `perf:` | Performance improvements |

**Important**: Never add `Co-authored-by` lines to commit messages.

## Security

- Never commit secrets/keys
- Run `make security` before PR
- Check bandit findings for issues
- This is a security library - extra scrutiny required

## Project Structure

```
sanitongo/
├── src/sanitongo/    # Source code
├── tests/            # Test files
├── docs/             # Documentation
├── pyproject.toml    # Project configuration
├── Makefile          # Development commands
└── README.md         # Project readme
```

## Release Process

One-command fully automated release:

```bash
make release-patch  # 0.1.0 → 0.1.1 (full release including GitHub release)
make release-minor  # 0.1.0 → 0.2.0
make release-major  # 0.1.0 → 1.0.0
```

This runs tests, bumps version, updates changelog, commits, tags, pushes, and creates GitHub release.
PyPI publication happens automatically via GitHub Actions.

See [docs/RELEASE.md](docs/RELEASE.md) for full details.

## Changes in Python Version

When changing the Python version in `pyproject.toml`, ensure to also update:
- the python version in the GitHub workflows located in `.github/workflows/`
- target python version in ruff.toml located in the project root

## GitHub Workflows

The project has four workflows in `.github/workflows/`:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push/PR to main/develop | Tests, linting, type checking |
| `security.yml` | push to main, PRs, weekly schedule | Security scans (bandit, pip-audit) |
| `docs.yml` | push to main | Build and deploy documentation |
| `release.yml` | tag push (v*) | Build and publish to PyPI |

All workflows use `uv` with caching enabled for faster builds.

## Documentation

When creating or updating documentation, ensure to:
- keep the documentation in the `docs/` folder up to date.
- if applicable, update the `README.md` file in the project root.
- for the mkdocs based documentation, ensure that:
    - it contains my real name: Krystian Safjan
    - links to my personal website: https://safjan.com
