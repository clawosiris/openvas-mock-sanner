# Compatibility Mock Scanner Implementation Spec

## Purpose

Implement the compatibility mock scanner described in
`spec/compatibility-mock-server.md` as a deterministic HTTP JSON service that
can be used by automated gvmd and gvmd-ng integration tests.

This document narrows the implementation target. If this document conflicts
with `compatibility-mock-server.md`, treat this document as the more concrete
implementation contract and update both files in the same pull request.

## Product Shape

The repository must produce a runnable mock scanner service with:

- a documented local development command
- a documented test command
- a compatibility mode enabled by default on the `devel` branch
- HTTP endpoints matching the compatibility contract
- deterministic scenario behavior
- enough tests to catch protocol regressions before gvmd integration tests run

The implementation language and framework are not prescribed. Prefer the
simplest maintainable stack already present in the repository. If the repository
has no implementation yet, choose a small, conventional HTTP stack with fast
tests and minimal operational dependencies.

## Runtime Configuration

The service must read configuration from environment variables.

Required variables:

- `MOCK_HOST`
  - default: `127.0.0.1`
- `MOCK_PORT`
  - default: `8080`
- `MOCK_SCENARIO`
  - default: `success-basic`
- `MOCK_PAGE_SIZE`
  - default: `100`
- `MOCK_FAILURE_AT`
  - optional
- `MOCK_CLOCK_START`
  - default: `2026-01-01T00:00:00Z`
- `MOCK_LATENCY_MS`
  - default: `0`
- `MOCK_RESULT_COUNT`
  - default scenario-specific, but overrideable for success scenarios
- `MOCK_HOST_COUNT`
  - default scenario-specific, but overrideable for success scenarios
- `MOCK_SEED`
  - default: `compat`
- `MOCK_VT_METADATA_PATH`
  - optional path to feed `vt-metadata.json`
  - when set and valid, result generation uses loaded feed OIDs and VT names
- `MOCK_TARGET_PROFILE`
  - optional path to a target/service/package fixture
- `MOCK_FEED_STRICT`
  - default: `false`
  - when `true`, configured feed/profile files must be readable and valid

Startup must fail with a non-zero exit code for invalid configuration. The
error must identify the invalid variable.

## HTTP Contract

All JSON responses must set `Content-Type: application/json`.

Required endpoints:

- `GET /health`
- `GET /capabilities`
- `GET /preferences`
- `POST /scans`
- `POST /scans/{scan_id}/start`
- `POST /scans/{scan_id}/stop`
- `GET /scans/{scan_id}/status`
- `GET /scans/{scan_id}/results`
- `DELETE /scans/{scan_id}`

Common error behavior:

- unknown routes return `404`
- invalid JSON request bodies return `400`
- unknown scan ids return `404`
- unsupported transitions return a deterministic `409`
- injected failures use the status code documented by the scenario
- every error body contains `error.code` and `error.message`

## State Model

The service is in-memory by default. Persistence across process restarts is not
required.

Scan ids must be stable and monotonic within a process:

- first created scan: `scan-0001`
- second created scan: `scan-0002`

The scan record must retain:

- scan id
- create payload
- scenario
- lifecycle status
- status poll count
- start count
- stop count
- delete state
- deterministic generated results
- optional feed metadata and target profile diagnostics
- deterministic timestamps
- any injected failure bookkeeping

Status vocabulary:

- `created`
- `queued`
- `stored`
- `requested`
- `running`
- `succeeded`
- `stopped`
- `failed`
- `error`

Progress must be deterministic for each scenario. Normal progress is an integer
from `0` through `100`. Scenarios may intentionally omit or corrupt progress
only when documented by that scenario.

## Result Generation

Results must be generated from deterministic inputs:

- scenario
- scan id
- `MOCK_SEED`
- `MOCK_CLOCK_START`
- `MOCK_RESULT_COUNT`
- `MOCK_HOST_COUNT`

The same inputs must produce byte-stable JSON except for explicitly documented
volatile fields. The default implementation should avoid volatile fields.

Public `/scans/{scan_id}/results` responses must match the raw openvasd scanner
shape. Minimum public result fields:

- `id`
- `type`
- `ip_address`
- `hostname`
- `port`
- `protocol`
- `oid`
- `message`

The public scanner result payload must not include manager/report enrichment
fields such as:

- `cve`
- `cpe`
- `cvss_base`
- `cvss_vector`
- `references`
- `tags`

Internal fixture generation may keep richer source data for deterministic
scenario construction, and `/vts` or future VT metadata endpoints may expose
feed-backed VT details keyed by OID.

Severity/threat mapping must be stable:

- `severity >= 9.0` -> `Critical`
- `severity >= 7.0` -> `High`
- `severity >= 4.0` -> `Medium`
- `severity > 0.0` -> `Low`
- `severity == 0.0` -> `Log`

## Result Retrieval

`GET /scans/{scan_id}/results` must support offset/limit retrieval.

Required query parameters:

- `offset`
- `limit`

Optional accepted aliases:

- `page`
- `page_size`
- `since`

Response fields:

- `scan_id`
- `offset`
- `limit`
- `total`
- `next_offset`
- `results`

`next_offset` must be `null` when no more results are available.

Invalid paging parameters must return `400` with a stable error code.

## Required Scenarios

### `success-basic`

- create returns `201`
- start returns `204`
- first status poll after start returns `running`
- later status polls progress to `succeeded`
- results are available after start
- delete returns `204`

Default data:

- `MOCK_RESULT_COUNT=12`
- `MOCK_HOST_COUNT=3`

### `success-large-report`

Same as `success-basic`, but must force multiple result requests with the
default page size.

Default data:

- `MOCK_RESULT_COUNT=250`
- `MOCK_HOST_COUNT=25`

### `empty-report`

- scan succeeds
- result total is `0`
- result array is empty

### `delayed-findings`

- initial result requests return an empty result set while status is running
- later requests return deterministic findings
- status eventually succeeds

### `stop-running`

- stop before terminal status returns `204`
- later status is `stopped`
- delete returns `204`

### `scanner-failure`

- status eventually becomes `failed` or `error`
- status body includes a stable machine-readable scanner error
- result retrieval after failure is deterministic and documented

### `malformed-results`

- configured result request returns malformed JSON or a schema-invalid payload
- the failure is deterministic for `MOCK_FAILURE_AT=results:<n>`

### `transient-results-error`

- one configured result request returns retryable `5xx`
- the next identical request succeeds

### `delete-refused`

- delete while active returns deterministic `409`
- status remains accessible afterward

### `duplicate-result-page`

- one configured page is repeated once
- subsequent requests resume normal paging

## Documentation Requirements

The implementation pull request must update `README.md` with:

- how to run the service
- how to select a scenario
- how to run tests
- example `curl` commands for create, start, status, results, and delete

The implementation pull request must update `spec/README.md` if files are added,
renamed, or retired.

## Non-Goals

- authentication
- TLS
- real scanning
- database persistence
- full OpenVAS API parity
- UI
