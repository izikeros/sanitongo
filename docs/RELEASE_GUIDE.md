# Release Guide for Sanitongo

This document provides a comprehensive step-by-step guide for releasing new versions of Sanitongo.

## Prerequisites

Before starting the release process, ensure you have:

- [ ] All changes merged into the `main` branch
- [ ] All tests passing locally and in CI
- [ ] Clean working directory (no uncommitted changes)
- [ ] Admin access to the GitHub repository
- [ ] PyPI credentials configured for publishing
- [ ] All required tools installed (see [Dependencies](#dependencies))

## Dependencies

Ensure the following tools are installed and configured:

```bash
# Install release dependencies
uv add --dev bump-my-version git-cliff

# Verify installations
bump-my-version --version
git-cliff --version
```

## Release Process

### 1. Pre-Release Checks

```bash
# Ensure you're on the main branch and it's up to date
git checkout main
git pull origin main

# Verify clean working directory
git status

# Run full test suite
make ci-test

# Check for security vulnerabilities
make security-check
```

### 2. Version Bumping

Choose the appropriate version bump based on [Semantic Versioning](https://semver.org/):

- **Patch** (x.y.Z): Bug fixes, minor improvements
- **Minor** (x.Y.z): New features, backward compatible
- **Major** (X.y.z): Breaking changes

```bash
# For patch release (e.g., 0.1.0 → 0.1.1)
make release-patch

# For minor release (e.g., 0.1.0 → 0.2.0)
make release-minor

# For major release (e.g., 0.1.0 → 1.0.0)
make release-major
```

### 3. Update Changelog

Generate and review the changelog:

```bash
# Generate changelog
make update-changelog

# Review the generated CHANGELOG.md
git diff CHANGELOG.md
```

### 4. Commit Version Changes

```bash
# Add and commit version changes
git add -A
git commit -m "chore(release): bump version to $(bump-my-version show current_version)"

# Create and push tag (this is optional, adding tag is handled by bump-my-version if configured)
git tag "v$(bump-my-version show current_version)"
git push origin main --tags
```

### 5. GitHub Release

Create a GitHub release:

> NOTE: To create release, "workflow" scope may be required. To request it, run:
> `gh auth refresh -h github.com -s workflow`

```bash
# Option 1: Using GitHub CLI (if installed)
gh release create "v$(bump-my-version show current_version)" \
  --title "Release v$(bump-my-version show current_version)" \
  --notes-file CHANGELOG.md \
  --latest

# Option 2: Manual process (if gh CLI not available)
# 1. Go to https://github.com/izikeros/sanitongo/releases/new
# 2. Select the tag you just pushed
# 3. Set release title: "Release v{VERSION}"
# 4. Copy relevant changelog section to release notes
# 5. Mark as "Latest release"
# 6. Click "Publish release"
```

### 6. PyPI Publication

The package will be automatically published to PyPI via GitHub Actions when a release is created. Monitor the "Publish to PyPI" workflow in the Actions tab.

If manual publication is needed:

```bash
# Build and publish (use with caution)
make publish
```

For testing purposes, you can publish to Test PyPI first:

```bash
# Publish to Test PyPI
make publish-test
```

### 7. Post-Release Verification

```bash
# Verify package is available on PyPI
pip install --upgrade sanitongo

# Test installation in a clean environment
python -c "import sanitongo; print(f'Installed version: {sanitongo.__version__}')"

# Verify GitHub release
gh release view "v$(bump-my-version show current_version)"
```

### 8. Communication

- [ ] Update project README if needed
- [ ] Announce release in relevant channels (if applicable)
- [ ] Update documentation (if applicable)

## Rollback Procedure

If issues are discovered after release:

### For PyPI

PyPI doesn't allow deleting releases, but you can:

1. Release a new patch version with fixes
2. Mark the problematic version as yanked (if critical issues exist)

### For GitHub

```bash
# Delete tag locally and remotely
git tag -d v{VERSION}
git push origin --delete v{VERSION}

# Delete GitHub release via web interface or CLI
gh release delete v{VERSION} --yes
```

## Makefile Targets

The following Makefile targets support the release process:

| Target | Description |
|--------|-------------|
| `make release-patch` | Bump patch version, update changelog, commit and tag |
| `make release-minor` | Bump minor version, update changelog, commit and tag |
| `make release-major` | Bump major version, update changelog, commit and tag |
| `make update-changelog` | Generate/update CHANGELOG.md using git-cliff |
| `make publish` | Build and publish to PyPI |
| `make publish-test` | Build and publish to Test PyPI |
| `make build` | Build distribution packages |
| `make clean` | Clean build artifacts |

## Configuration Files

### bump-my-version Configuration

Create `.bumpversion.cfg` for version management:

```ini
[bumpversion]
current_version = 0.1.0
commit = False
tag = False
parse = (?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)
serialize = {major}.{minor}.{patch}

[bumpversion:file:pyproject.toml]
search = version = "{current_version}"
replace = version = "{new_version}"

[bumpversion:file:src/sanitongo/__init__.py]
search = __version__ = "{current_version}"
replace = __version__ = "{new_version}"
```

### git-cliff Configuration

Your `cliff.toml` is already configured. Key features:
- Conventional commits parsing
- Automatic grouping by commit type
- Clean changelog formatting

## Environment Variables

For automated releases, set these secrets in GitHub repository settings:

- `PYPI_API_TOKEN`: PyPI API token for package publishing
- `TEST_PYPI_API_TOKEN`: Test PyPI API token (optional, for testing)

## Troubleshooting

### Common Issues

1. **Version bump fails**: Check that all files referenced in `.bumpversion.cfg` exist
2. **PyPI upload fails**: Verify API token and package name availability
3. **Git tag already exists**: Delete existing tag or use different version
4. **CI/CD fails**: Check GitHub Actions logs for specific errors

### Debug Commands

```bash
# Check current version
bump-my-version show current_version

# Dry run version bump
bump-my-version bump --dry-run patch

# Check git status
git status --porcelain

# Validate package build
make build
twine check dist/*
```

## Security Considerations

- Never commit API tokens to version control
- Use GitHub encrypted secrets for sensitive data
- Review changelog before public release
- Test releases in isolated environments first

---

*This guide should be reviewed and updated with each major release to reflect any process changes.*