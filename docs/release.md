# Release and Nightly Builds

GitHub Actions runs tests, builds the scanner container, smoke-tests `/health`,
and publishes container images for release and nightly channels.

## Continuous Integration

Pull requests to `main` or `devel` run:

- Python tests on 3.10, 3.11, and 3.12
- Container build
- Container smoke test against `GET /health`

Pushes to `main`, `devel`, and `feature/**` run the same checks. Only eligible
branches and tags publish images.

## Releases

Create a version tag to publish a release:

```sh
git tag v0.1.0
git push origin v0.1.0
```

For `v*` tags, the workflow:

- runs the full test matrix
- builds and smoke-tests the container
- publishes semantic container tags to GHCR
- creates a GitHub Release with generated release notes

Pre-release tags such as `v0.2.0-rc.1` are marked as GitHub pre-releases.

## Nightlies

The scheduled workflow runs once per day on the default branch and publishes:

```text
ghcr.io/clawosiris/openvas-mock-scanner:nightly
```

Nightly builds use the same test and container smoke-test gates as releases.
If tests or the container health probe fail, the nightly image is not published.
