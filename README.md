# OpenVAS Mock Scanner

A deterministic HTTP JSON compatibility mock for OpenVAS/openvasd and
Greenbone manager integration tests.

The mock is intended to stand in for the HTTP openvasd scanner surface in
manager integration tests. It does not execute vulnerability tests; it provides
stable scanner lifecycle behavior, result payloads, paging, preferences, and
failure scenarios that gvmd-compatible clients can use as a repeatable fixture.

## Documentation

- [Container usage](docs/container.md)
- [HTTP API](docs/api.md)
- [Release and nightly builds](docs/release.md)
- [Compatibility mock contract](spec/compatibility-mock-server.md)
- [Implementation spec](spec/implementation-spec.md)
- [Test plan](spec/test-plan.md)

## Run

Requires Python 3.10+ and no third-party packages.

```sh
python3 -m openvas_mock_scanner
```

By default the service listens on `127.0.0.1:8080`.

Runtime configuration is read from environment variables:

| Variable | Default |
| --- | --- |
| `MOCK_HOST` | `127.0.0.1` |
| `MOCK_PORT` | `8080` |
| `LISTENING` | unset; openvasd-compatible `host:port` alias |
| `MOCK_SCENARIO` | `success-basic` |
| `MOCK_PAGE_SIZE` | `100` |
| `MOCK_FAILURE_AT` | unset |
| `MOCK_CLOCK_START` | `2026-01-01T00:00:00Z` |
| `MOCK_LATENCY_MS` | `0` |
| `MOCK_RESULT_COUNT` | scenario-specific |
| `MOCK_HOST_COUNT` | scenario-specific |
| `MOCK_SEED` | `compat` |

Example scenario selection:

```sh
MOCK_SCENARIO=success-large-report MOCK_PORT=8081 python3 -m openvas_mock_scanner
```

## Container

Build the local container image:

```sh
docker build -t openvas-mock-scanner:local .
```

Run it as a drop-in mock scanner service:

```sh
docker run --rm -p 8080:80 \
  -e MOCK_SCENARIO=success-basic \
  openvas-mock-scanner:local
```

The container listens on `0.0.0.0:80` by default via the openvasd-compatible
`LISTENING=0.0.0.0:80` variable and exposes `GET /health/alive` as its
healthcheck endpoint. `MOCK_HOST` and `MOCK_PORT` can override the bind address
for local test runs.

CI publishes successful `main`, `devel`, and `v*` tag builds to:

```text
ghcr.io/clawosiris/openvas-mock-scanner
```

Release tags publish semantic image tags and create GitHub releases. The
scheduled nightly workflow builds and publishes `ghcr.io/clawosiris/openvas-mock-scanner:nightly`.

Supported scenarios:

`success-basic`, `success-large-report`, `empty-report`, `delayed-findings`,
`stop-running`, `scanner-failure`, `malformed-results`,
`transient-results-error`, `delete-refused`, and `duplicate-result-page`.

`MOCK_FAILURE_AT` accepts lifecycle points such as `create`, `start`,
`status:3`, `results:2`, and `delete`.

## Test

```sh
python3 -m unittest discover
```

The test suite uses only local in-process HTTP servers and requires no external
services.

## Curl Examples

```sh
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/capabilities
curl -s http://127.0.0.1:8080/scans/preferences
```

Create and start a scan:

```sh
curl -s -X POST http://127.0.0.1:8080/scans \
  -H 'Content-Type: application/json' \
  -d '{"scan_id":"scan-0001","target":{"hosts":["192.0.2.10"],"ports":[]},"vts":[]}'

curl -i -X POST http://127.0.0.1:8080/scans/scan-0001 \
  -H 'Content-Type: application/json' \
  -d '{"action":"start"}'
```

Check status and page through results:

```sh
curl -s http://127.0.0.1:8080/scans/scan-0001/status
curl -s 'http://127.0.0.1:8080/scans/scan-0001/results?range=0-4'
```

Stop or delete a scan:

```sh
curl -i -X POST http://127.0.0.1:8080/scans/scan-0001 \
  -H 'Content-Type: application/json' \
  -d '{"action":"stop"}'
curl -i -X DELETE http://127.0.0.1:8080/scans/scan-0001
```

Normal success scenarios return `204` for delete. Deleted scans are no longer
queryable and return `404` from scan-specific endpoints.

## License

This project is licensed under the GNU Affero General Public License v3.0 or
later. See `LICENSE` for the full license text.

SPDX-License-Identifier: AGPL-3.0-or-later
