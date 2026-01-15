# Quick Release Reference

## One-Command Release

```bash
# For patch release (0.1.0 → 0.1.1)
make release-patch

# For minor release (0.1.0 → 0.2.0)  
make release-minor

# For major release (0.1.0 → 1.0.0)
make release-major
```

**Each `make release-*` command automatically:**

1. Cleans build artifacts
2. Runs tests with coverage
3. Runs security checks
4. Checks code style (lint)
5. Bumps version number
6. Updates CHANGELOG.md using git-cliff
7. Stages all changes (`git add -A`)
8. Commits with message `chore(release): bump version to X.Y.Z`
9. Creates git tag `vX.Y.Z`
10. Displays push instructions

## Manual Push (after make release-*)

```bash
git push origin main --tags
```

## Verify Release

1. Check GitHub Actions: https://github.com/izikeros/sanitongo/actions
2. Check PyPI: https://pypi.org/project/sanitongo/
3. Test installation: `pip install --upgrade sanitongo`

## Emergency Rollback

```bash
# Delete local tag
git tag -d v{VERSION}

# Delete remote tag  
git push origin --delete v{VERSION}

# Delete GitHub release (via web interface or gh CLI)
gh release delete v{VERSION} --yes
```

## Required Setup (One-time)

### 1. Add PyPI API Token to GitHub Secrets

**Required for automated publishing to PyPI via GitHub Actions.**

- Generate token at: https://pypi.org/manage/account/token/
- Add to repository secrets: https://github.com/izikeros/sanitongo/settings/secrets/actions
- Secret name: `PYPI_API_TOKEN`
- Secret value: Your PyPI token (starts with `pypi-`)

### 2. Ensure Conventional Commits

All contributors must use [conventional commits](https://www.conventionalcommits.org/) for proper changelog generation.

### 3. Install Dependencies

```bash
uv add --dev bump-my-version git-cliff
```

## Available Make Targets

- `make show-version` - Show current version
- `make update-changelog` - Generate changelog using `uv run git-cliff --output CHANGELOG.md`
- `make version-patch/minor/major` - Bump version only (no commit/tag)