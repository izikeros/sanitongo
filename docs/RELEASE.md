# Release Guide

## Quick Reference

```bash
# One-command release (does everything)
make release-patch   # 0.1.0 → 0.1.1
make release-minor   # 0.1.0 → 0.2.0
make release-major   # 0.1.0 → 1.0.0
```

Each command automatically:
1. Runs tests with coverage
2. Runs security checks (bandit, pip-audit)
3. Runs linting
4. Bumps version
5. Updates CHANGELOG.md
6. Commits with message `chore(release): bump version to X.Y.Z`
7. Creates git tag `vX.Y.Z`
8. Pushes to origin with tags
9. Creates GitHub release with extracted release notes
10. PyPI publication happens automatically via GitHub Actions

## Prerequisites

### One-Time Setup

1. **PyPI API Token** (required for automated publishing):
   - Generate at: https://pypi.org/manage/account/token/
   - Add to GitHub secrets: https://github.com/izikeros/sanitongo/settings/secrets/actions
   - Name: `PYPI_API_TOKEN`

2. **GitHub CLI Authentication**:
   ```bash
   gh auth login
   # If needed for workflow scope:
   gh auth refresh -h github.com -s workflow
   ```

3. **Install Dependencies**:
   ```bash
   uv sync --group dev
   ```

## Version Bumping Guidelines

Choose the appropriate version bump based on [Semantic Versioning](https://semver.org/):

| Bump Type | When to Use | Example |
|-----------|-------------|---------|
| `patch` | Bug fixes, minor improvements | 0.1.0 → 0.1.1 |
| `minor` | New features, backward compatible | 0.1.0 → 0.2.0 |
| `major` | Breaking changes | 0.1.0 → 1.0.0 |

## Pre-Release Checklist

Before running a release:

- [ ] All changes merged into `main` branch
- [ ] All tests passing (`make test`)
- [ ] Clean working directory (`git status`)
- [ ] On the `main` branch (`git checkout main && git pull`)

## Useful Commands

```bash
# Show current version
make show-version

# Preview release notes for current version
make preview-release-notes

# Update changelog without releasing
make update-changelog

# Bump version only (no commit/tag/push)
make version-patch
make version-minor
make version-major
```

## Post-Release Verification

After release completes:

1. **Monitor GitHub Actions**: https://github.com/izikeros/sanitongo/actions
2. **Check PyPI**: https://pypi.org/project/sanitongo/
3. **Test installation**:
   ```bash
   pip install --upgrade sanitongo
   python -c "import sanitongo; print(sanitongo.__version__)"
   ```

## Rollback Procedure

If issues are discovered after release:

```bash
# Delete local tag
git tag -d v{VERSION}

# Delete remote tag
git push origin --delete v{VERSION}

# Delete GitHub release
gh release delete v{VERSION} --yes
```

Note: PyPI doesn't allow deleting releases. You can:
- Release a new patch version with fixes
- Mark the problematic version as yanked (for critical issues)

## Configuration Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Version config in `[tool.bumpversion]` section |
| `cliff.toml` | Changelog generation config for git-cliff |
| `.github/workflows/release.yml` | PyPI publishing on tag push |

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| Version bump fails | Check `pyproject.toml` and `src/sanitongo/__init__.py` exist |
| Git tag already exists | Delete existing tag or use different version |
| PyPI upload fails | Verify `PYPI_API_TOKEN` secret is set |
| gh release fails | Run `gh auth refresh -h github.com -s workflow` |

### Debug Commands

```bash
# Check current version
make show-version

# Dry run version bump
uv run bump-my-version bump --dry-run patch

# Validate package build
make build
uv run twine check dist/*

# Check git status
git status --porcelain
```

## Release Process Details

The `make release-*` targets execute these steps in order:

```
clean           → Remove build artifacts
test-cov        → Run tests with coverage
security-check  → Run bandit and pip-audit
lint            → Check code style with ruff
bump-my-version → Update version in pyproject.toml and __init__.py
git-cliff       → Generate/update CHANGELOG.md
extract notes   → Extract current version's changelog section
git add -A      → Stage all changes
git commit      → Commit with release message
git tag         → Create version tag
git push        → Push commits and tags to origin
gh release      → Create GitHub release with release notes
```

After the local release completes, GitHub Actions automatically:
- Builds the package
- Publishes to PyPI

---

*Author: [Krystian Safjan](https://safjan.com)*
