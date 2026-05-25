# OpenVAS Mock Scanner

A deterministic HTTP JSON compatibility mock for OpenVAS/Greenbone manager
integration tests. Compatibility mode is the default behavior on `devel`.

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
docker run --rm -p 8080:8080 \
  -e MOCK_SCENARIO=success-basic \
  openvas-mock-scanner:local
```

The container listens on `0.0.0.0:8080` by default and exposes `GET /health`
as its healthcheck endpoint. All runtime environment variables listed above are
supported in the container.

CI publishes successful `main`, `devel`, and `v*` tag builds to:

```text
ghcr.io/clawosiris/openvas-mock-scanner
```

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
curl -s http://127.0.0.1:8080/preferences
```

Create and start a scan:

```sh
curl -s -X POST http://127.0.0.1:8080/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.0.2.10","profile":"compat"}'

curl -i -X POST http://127.0.0.1:8080/scans/scan-0001/start
```

Check status and page through results:

```sh
curl -s http://127.0.0.1:8080/scans/scan-0001/status
curl -s 'http://127.0.0.1:8080/scans/scan-0001/results?offset=0&limit=5'
curl -s 'http://127.0.0.1:8080/scans/scan-0001/results?page=2&page_size=5'
```

Stop or delete a scan:

```sh
curl -i -X POST http://127.0.0.1:8080/scans/scan-0001/stop
curl -i -X DELETE http://127.0.0.1:8080/scans/scan-0001
```

Normal success scenarios return `204` for delete. Deleted scans are no longer
queryable and return `404` from scan-specific endpoints.

## License

This project is licensed under the GNU Affero General Public License v3.0 or
later. See `LICENSE` for the full license text.

SPDX-License-Identifier: AGPL-3.0-or-later
