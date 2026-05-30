# Compatibility Mock Scanner Spec

## Purpose

Define a stricter mock scanner contract for automated compatibility testing of
OpenVAS/Greenbone manager integrations.

The existing `mock-server.md` is a fair coding benchmark. This document is a
separate contract for manager-facing test infrastructure. It intentionally
covers protocol edge cases, deterministic report content, failure injection,
and lifecycle behavior that are needed to validate scanner orchestration and
report ingestion automatically.

## Scope

The compatibility mock must emulate enough of a scanner-facing HTTP JSON API to
exercise manager behavior without requiring a real scanner installation.

In scope:

- deterministic scan lifecycle behavior
- create, start, stop, status, results, capabilities, preferences, and delete
  flows
- paginated or ranged result retrieval
- raw openvasd-shaped scanner result rows for report ingestion tests, with
  richer VT/feed metadata exposed separately
- scripted success, stop, failure, timeout, malformed response, and retry
  scenarios
- stable fixture data that can be compared in automated tests

Out of scope:

- real vulnerability detection
- real network scanning
- persistence across restarts unless explicitly configured for a scenario
- authentication unless a harness scenario explicitly enables it
- exact parity with every scanner API field

## Compatibility Mode

The repository now implements this compatibility contract as the default
service behavior. No `MOCK_COMPATIBILITY_MODE` flag is required. Legacy helper
endpoints may remain available for older mock clients, but the openvasd-shaped
paths described here are the primary contract.

## Required Configuration

The compatibility mock must support all configuration variables from
`mock-server.md`, plus these variables.

- `MOCK_SCENARIO`
  - string
  - default: `success-basic`
  - meaning: named deterministic scenario to execute
- `MOCK_PAGE_SIZE`
  - integer
  - default: `100`
  - meaning: default maximum number of results returned per page or range
- `MOCK_FAILURE_AT`
  - optional string
  - examples: `create`, `start`, `status:3`, `results:2`, `delete`
  - meaning: inject a scenario-specific failure at a lifecycle point
- `MOCK_CLOCK_START`
  - RFC 3339 timestamp
  - default: `2026-01-01T00:00:00Z`
  - meaning: deterministic base timestamp for generated scan and result data
- `MOCK_LATENCY_MS`
  - integer
  - default: `0`
  - meaning: artificial response latency for timeout and retry tests

Invalid configuration must fail fast at startup with a useful error message.

## HTTP Behavior

### Common Requirements

- JSON responses must use `application/json`.
- Empty successful responses may use no body.
- Unknown routes must return `404`.
- Invalid JSON request bodies must return `400`.
- Unknown scan ids on scan-specific endpoints must return `404`.
- Unsupported state transitions must return a deterministic `4xx` response.
- Error responses must include a stable machine-readable error code.

Example error response:

```json
{
  "error": {
    "code": "scan_not_found",
    "message": "scan id does not exist"
  }
}
```

## Required Endpoints

### `GET /capabilities`

Return scanner capabilities used by manager-side feature negotiation.

Response:

- HTTP `200`
- JSON object

Minimum fields:

```json
{
  "api_version": "compat-1",
  "scanner_name": "openvas-mock-sanner",
  "features": {
    "start": true,
    "stop": true,
    "delete": true,
    "result_paging": true,
    "preferences": true
  }
}
```

### `GET /preferences` and `GET /scans/preferences`

Return deterministic scanner preferences. `GET /preferences` returns the
legacy wrapper object used by older mock clients. `GET /scans/preferences`
returns the openvasd-shaped preference list used by manager integrations.

Response:

- HTTP `200`
- JSON object with a `preferences` array for `/preferences`
- JSON array for `/scans/preferences`

Each preference must include:

- `id`
- `name`
- `type`
- `default`
- `required`

### `POST /scans`

Create a scan.

Request:

- Accept any valid JSON object.
- Retain the full create payload in memory for later scenario decisions.

Response:

- HTTP `201`
- JSON string containing the stable scan id

Example:

```json
"scan-0001"
```

If the request body contains `scan_id`, the mock uses it as the scanner id.
This matches gvmd/openvasd integration paths that pass the report id through to
the scanner. Otherwise the mock allocates `scan-0001`, `scan-0002`, and so on.

### `POST /scans/{scan_id}`

Perform an openvasd-style scan action.

Request:

```json
{"action":"start"}
```

or:

```json
{"action":"stop"}
```

Response:

- HTTP `204`
- no body

### `POST /scans/{scan_id}/start`

Start a created, stored, requested, stopped, or failed scan when the active
scenario allows restart.

Response:

- HTTP `204`
- no body

Repeated start requests must be deterministic. They may be idempotent or return
a documented `4xx` error, but must not change behavior between runs.

This endpoint is a legacy alias. Prefer `POST /scans/{scan_id}` with an action
body for drop-in openvasd compatibility.

### `POST /scans/{scan_id}/stop`

Stop a running, queued, requested, or stored scan.

Response:

- HTTP `204`
- no body

Stopping an already terminal scan must return a deterministic documented
response.

This endpoint is a legacy alias. Prefer `POST /scans/{scan_id}` with an action
body for drop-in openvasd compatibility.

### `GET /scans/{scan_id}/status`

Return current scan status.

Response:

- HTTP `200`
- JSON object

Allowed statuses:

- `created`
- `queued`
- `stored`
- `requested`
- `running`
- `succeeded`
- `stopped`
- `failed`
- `error`

Example:

```json
{
  "id": "scan-0001",
  "status": "running",
  "progress": 50,
  "poll_count": 3
}
```

Status behavior must be deterministic for a given scenario. The mock should
support scenarios where:

- status remains non-terminal for several polls
- progress moves forward normally
- the scan succeeds
- the scan is stopped
- the scan fails with a scanner error

### `GET /scans/{scan_id}/results`

Return generated synthetic results.

The endpoint must support either page-style or range-style retrieval. If both
are implemented, behavior must be documented.

Supported query parameters:

- `range=START-END`
- `offset`
- `limit`
- `page`
- `page_size`

Response:

- HTTP `200`
- JSON object

Example:

```json
{
  "scan_id": "scan-0001",
  "offset": 0,
  "limit": 2,
  "total": 50,
  "next_offset": 2,
  "results": [
    {
      "id": 0,
      "type": "alarm",
      "ip_address": "10.42.0.1",
      "hostname": "synthetic-host-0001.lab",
      "oid": "1.3.6.1.4.1.25623.1.0.147696",
      "port": 443,
      "protocol": "tcp",
      "message": "Deterministic synthetic finding for compatibility tests."
    }
  ]
}
```

The result set must be stable for the same scenario, seed, scan id, host count,
and result count. `items` and `results` must contain the same raw scanner
result objects.

### `DELETE /scans/{scan_id}`

Delete a scan.

Response:

- HTTP `204`
- no body

Repeated deletes for an already deleted scan must return a deterministic
documented response. Compatibility scenarios should include both successful
delete and scanner-refused delete behavior.

In the current implementation, the `delete-refused` scenario returns HTTP
`406` while the scan is still active and a later delete succeeds after the scan
reaches a terminal state.

## Result Data Requirements

Each public scanner result must match actual openvasd scanner behavior. It
should be raw result data, not manager-side report enrichment.

Minimum public scanner result fields:

- stable zero-based result id
- result type
- host IP address
- hostname
- NVT/OID
- port
- protocol
- scanner message

Fields that belong to VT metadata or manager/report enrichment, not public
scanner results:

- CVEs
- CPEs
- CVSS base score
- CVSS vector
- tags
- references
- severity/threat
- QoD
- NVT name/family
- remediation or detection text beyond the raw scanner message
- vulnerability publication date
- certificate metadata for TLS-related scenarios
- application/product metadata for service scenarios

The mock may use richer internal fixture data to choose deterministic OIDs and
messages, but it must not expose that enrichment directly from
`/scans/{scan_id}/results`.

Synthetic data must be safe to publish and must not include real secrets,
credentials, or customer data.

## Required Scenarios

The mock must define named scenarios. At minimum:

- `success-basic`
  - create, start, run, return deterministic results, succeed, delete
- `success-large-report`
  - same as success, but with enough results to force paging/range handling
- `empty-report`
  - succeeds with zero findings
- `delayed-findings`
  - status progresses before findings become visible
- `stop-running`
  - scan is stopped before completion
- `scanner-failure`
  - scan enters `failed` or `error` with a stable error payload
- `malformed-results`
  - returns malformed result payload at a configured poll for parser tests
- `transient-results-error`
  - returns one retryable `5xx` response before succeeding
- `delete-refused`
  - delete returns a deterministic refusal response while the scan is active
- `duplicate-result-page`
  - repeats a page once to test de-duplication behavior

Scenario behavior must be documented well enough for a black-box harness to
assert expected manager behavior.

## Acceptance Criteria

A compatibility harness must be able to verify:

1. Capabilities and preferences are stable across runs.
2. Create returns `201` and a stable scan id shape.
3. Start returns `204` and transitions the scan according to the active
   scenario.
4. Status exposes the required status vocabulary and deterministic progress.
5. Results can be consumed by page or range without missing or duplicating
   records in the normal success scenario.
6. Public result records include only the raw scanner result shape: stable
   zero-based id, type, host identity, OID, port/protocol, and scanner message.
   Severity, QoD, VT metadata, timestamps, and remediation fields are reserved
   for VT metadata or manager/report enrichment keyed by OID.
7. Large reports force multiple result fetches.
8. Empty reports are represented without special-case crashes.
9. Stop, failure, malformed response, transient error, delete refusal, and
   duplicate-page scenarios are deterministic.
10. Delete returns `204` on normal success and deleted scans are no longer
    accessible.
11. The same seed and scenario produce byte-stable JSON after normalizing
    explicitly documented volatile fields.
12. Invalid configuration fails at startup.

## Relationship To The Benchmark Spec

This document should not replace `mock-server.md`.

The benchmark spec remains intentionally small so coding-model comparisons stay
fair. This compatibility spec is for automated integration test infrastructure
where fidelity and failure coverage matter more than benchmark simplicity.
