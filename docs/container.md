# Container Usage

The container is built to run as a scanner replacement fixture in local,
integration, and CI environments.

## Build

```sh
docker build -t openvas-mock-scanner:local .
```

## Run

```sh
docker run --rm --name openvas-mock-scanner \
  -p 8080:8080 \
  -e MOCK_SCENARIO=success-basic \
  openvas-mock-scanner:local
```

The image listens on `0.0.0.0:8080`, runs as the non-root `mockscanner` user,
and exposes `GET /health` as the Docker healthcheck.

## Published Images

Images are published to:

```text
ghcr.io/clawosiris/openvas-mock-scanner
```

Common tags:

- `latest` from `main`
- `devel` from `devel`
- `nightly` from the scheduled nightly workflow
- `vX.Y.Z`, `X.Y`, and commit SHA tags from release tags

## Replacement Pattern

Point manager integration tests at the mock scanner base URL instead of a real
OpenVAS scanner URL. The mock is deterministic and process-local; restart the
container between test cases when test isolation requires fresh scan ids and
counters.

Example:

```sh
docker run --rm -p 18080:8080 \
  -e MOCK_SCENARIO=success-large-report \
  -e MOCK_SEED=gvmd-compat \
  ghcr.io/clawosiris/openvas-mock-scanner:nightly
```
