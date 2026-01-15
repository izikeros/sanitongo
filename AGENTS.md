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

```bash
make release-patch  # 0.1.0 → 0.1.1
make release-minor  # 0.1.0 → 0.2.0
make release-major  # 0.1.0 → 1.0.0
```
