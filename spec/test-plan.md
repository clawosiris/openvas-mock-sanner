# Compatibility Mock Scanner Test Plan

## Purpose

Define the tests required before the compatibility mock scanner can be used as
gvmd or gvmd-ng automated integration infrastructure.

The plan covers the mock service itself. Manager-side integration tests belong
in gvmd/gvmd-ng repositories and should consume this service as a black box.

## Test Strategy

Use three layers:

1. Unit tests for configuration, state transitions, result generation, and
   paging calculations.
2. HTTP contract tests that start the service and exercise endpoints through a
   real HTTP client.
3. Determinism tests that compare generated responses across repeated runs with
   identical configuration.
4. Cross-repository validation against `scan-examples` enrichment when
   `SCAN_EXAMPLES_PATH` points to a checked-out `scan-examples` repository.

Every test must run locally without a real OpenVAS scanner, database, network
target, or external service.

## Required Test Commands

The repository must document one primary command that runs the full test suite.

Examples:

- `cargo test`
- `go test ./...`
- `npm test`
- `pytest`

The repository may also document focused commands for contract tests and
formatting/linting.

## Unit Test Coverage

### Configuration

Verify:

- defaults are applied when variables are absent
- valid environment overrides are accepted
- invalid `MOCK_PORT` fails
- invalid `MOCK_PAGE_SIZE` fails
- invalid `MOCK_CLOCK_START` fails
- invalid `MOCK_LATENCY_MS` fails
- unknown `MOCK_SCENARIO` fails
- `MOCK_FAILURE_AT` parses supported lifecycle points
- feed-backed fixture paths and `MOCK_FEED_STRICT` parse consistently

### State Transitions

Verify:

- created scan starts in `created`
- `start` moves the scan into the scenario's active path
- repeated `start` behavior is deterministic
- `stop` on active scans moves to `stopped`
- `stop` on terminal scans returns the documented response
- `delete` marks scans as deleted
- requests for deleted or unknown scans return deterministic responses
- unsupported transitions return `409`

### Result Generation

Verify:

- internal fixture rows have stable ids
- internal ordinals are stable and sequential
- internal host distribution is stable for a given host count
- severity/threat mapping is stable for fixture and VT metadata generation
- internal fixture rows keep enough rich source data to derive raw scanner
  messages and future VT metadata
- generated timestamps are based on `MOCK_CLOCK_START`
- no generated fixture includes real credentials or customer data
- public `/scans/{id}/results` projections expose only raw scanner result
  fields, not the richer internal fixture fields
- feed-backed mode uses selected feed OIDs when they intersect loaded metadata
- missing selected OIDs fall back deterministically
- optional target profiles influence host and service selection
- `GET /vts/{oid}` exposes loaded VT metadata outside the scanner result
  payload

### scan-examples Enrichment Validation

Verify:

- CI checks out `clawosiris/scan-examples` and sets `SCAN_EXAMPLES_PATH`
- feed-backed mock scanner results remain raw openvasd-shaped before enrichment
- raw result OIDs enrich through `scan_examples.enrichment.enrich_results_from_files`
- enriched records report `vt-metadata-status: matched`
- CVE metadata joins through the same `scan-examples` SCAP path
- the validation uses the real `scan-examples` Python enrichment code, not a
  duplicate mock-side implementation

### Paging

Verify:

- offset `0` returns the first page
- non-zero offsets return the correct slice
- final page returns `next_offset: null`
- empty reports return `total: 0` and `results: []`
- invalid offset returns `400`
- invalid limit returns `400`
- limit greater than total is handled correctly

## HTTP Contract Test Coverage

For each test, start the service on an ephemeral local port and make real HTTP
requests.

### Common Behavior

Verify:

- `GET /health` returns `200`
- unknown route returns `404`
- invalid JSON request body returns `400`
- all JSON responses use `application/json`
- error responses include `error.code` and `error.message`

### Capabilities and Preferences

Verify:

- `GET /capabilities` returns `200`
- capabilities include `api_version`, `scanner_name`, and feature flags
- `GET /preferences` returns `200`
- every preference includes `id`, `name`, `type`, `default`, and `required`
- responses are stable across repeated calls

### Scan Lifecycle

Verify:

- `POST /scans` returns `201`
- response includes id matching `scan-[0-9]{4}`
- `POST /scans/{id}/start` returns `204`
- `GET /scans/{id}/status` returns `200`
- `POST /scans/{id}/stop` returns `204` for active scans
- `GET /scans/{id}/results` returns `200`
- each public result object has exactly raw openvasd scanner fields:
  `id`, `type`, `ip_address`, `hostname`, `oid`, `port`, `protocol`, and
  `message`
- public result objects do not include CVE, CPE, CVSS, references, tags,
  severity, threat, family, QoD, NVT name, solution, or detection fields
- `DELETE /scans/{id}` returns `204`
- unknown scan id on lifecycle endpoints returns `404`

## Scenario Acceptance Tests

### `success-basic`

Expected:

- scan reaches `succeeded`
- progress reaches `100`
- default result total is `12`
- every result has required fields
- delete succeeds

### `success-large-report`

Expected:

- default result total is `250`
- default page size requires at least three result requests
- collecting all pages returns exactly `250` unique result ids
- no result id is missing or duplicated

### `empty-report`

Expected:

- scan reaches `succeeded`
- result total is `0`
- results array is empty

### `delayed-findings`

Expected:

- early result request returns no findings
- later result request returns findings
- final status is `succeeded`

### `stop-running`

Expected:

- scan can be stopped while active
- final status is `stopped`
- delete succeeds

### `scanner-failure`

Expected:

- scan reaches `failed` or `error`
- status response includes stable scanner error code
- repeated status calls return stable terminal state

### `malformed-results`

Expected:

- configured result request returns malformed JSON or schema-invalid JSON
- repeated runs fail at the same request number
- non-failing requests behave normally

### `transient-results-error`

Expected:

- configured request returns retryable `5xx`
- immediate retry succeeds
- failure happens only once per scan unless configured otherwise

### `delete-refused`

Expected:

- delete while active returns `409`
- error code is stable
- scan remains queryable
- delete after terminal status follows documented behavior

### `duplicate-result-page`

Expected:

- configured page repeats once
- client-side collection can detect duplicate ids
- subsequent pages resume normal ordering

## Determinism Tests

For at least `success-basic`, `success-large-report`, and `scanner-failure`:

- run the same scenario twice in fresh processes
- create one scan in each process
- collect capabilities, preferences, statuses, and all result pages
- normalize no fields unless explicitly documented as volatile
- assert byte-for-byte equality

## gvmd/Gvmd-ng Readiness Gate

The mock is ready for manager integration only when:

- all unit tests pass
- all HTTP contract tests pass
- all scenario acceptance tests pass
- determinism tests pass
- README contains run/test instructions
- compatibility spec and implementation behavior agree

Missing tests must be tracked as explicit follow-up issues before any gvmd or
gvmd-ng compatibility claim is made from the mock.
