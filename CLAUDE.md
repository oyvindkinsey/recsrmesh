# recsrmesh

CSRMesh protocol library for Python.

## Release Process

Releases are fully automated via GitHub Actions. Pushing a version tag triggers:

1. Build wheel and source tarball
2. Publish to PyPI (trusted publishing)
3. Create GitHub release with attached artifacts

### Steps

1. Bump version in `pyproject.toml`
2. Commit: `git commit -am "Bump to v0.X.0"`
3. Tag and push: `git tag v0.X.0 && git push && git push --tags`

The workflow `.github/workflows/workflow.yml` runs on `push: tags: ['v*']`.

### Project-Specific

- **Single module**: `from recsrmesh import CSRMesh`
- **Async context manager**: `async with CSRMesh(client, passphrase) as mesh:`
- **Bridge required**: Association must be routed through an existing mesh device
- **Replay testing**: Use `_fake_client.py` with captured transcripts

## Code Style

- Ruff for linting/formatting (`ruff check --fix src/`)
- mypy for type checking (`mypy src/`)
- Pre-commit: `ruff format` + `mypy` before committing
