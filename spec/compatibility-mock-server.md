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
- rich synthetic result data for report ingestion tests
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

Implementations may keep the benchmark API from `mock-server.md` as the default
mode. The stricter contract should be enabled explicitly, for example with:

- `MOCK_COMPATIBILITY_MODE=1`
- a compatibility-specific binary or command
- a compatibility-specific config file

The chosen activation mechanism must be documented by the implementation.

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

### `GET /preferences`

Return deterministic scanner preferences.

Response:

- HTTP `200`
- JSON object with a `preferences` array

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
- JSON object containing a stable scan id

Example:

```json
{
  "id": "scan-0001"
}
```

### `POST /scans/{scan_id}/start`

Start a created, stored, requested, stopped, or failed scan when the active
scenario allows restart.

Response:

- HTTP `204`
- no body

Repeated start requests must be deterministic. They may be idempotent or return
a documented `4xx` error, but must not change behavior between runs.

### `POST /scans/{scan_id}/stop`

Stop a running, queued, requested, or stored scan.

Response:

- HTTP `204`
- no body

Stopping an already terminal scan must return a deterministic documented
response.

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
- progress is missing
- progress is temporarily invalid
- the scan succeeds
- the scan is stopped
- the scan fails with a scanner error

### `GET /scans/{scan_id}/results`

Return generated synthetic results.

The endpoint must support either page-style or range-style retrieval. If both
are implemented, behavior must be documented.

Supported query parameters:

- `offset`
- `limit`
- `page`
- `page_size`
- `since`

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
      "id": "result-000001",
      "ordinal": 1,
      "type": "alarm",
      "ip_address": "10.42.0.1",
      "hostname": "synthetic-host-0001.lab",
      "port": 443,
      "protocol": "tcp",
      "service": "https",
      "oid": "1.3.6.1.4.1.25623.1.0.147696",
      "nvt_name": "Synthetic TLS Certificate Finding",
      "family": "SSL and TLS",
      "cve": ["CVE-2024-0001"],
      "cpe": ["cpe:/a:synthetic:service:1.0"],
      "cvss_base": 7.5,
      "severity": 7.5,
      "threat": "High",
      "qod": 80,
      "solution_type": "Mitigation",
      "solution": "Replace the synthetic certificate.",
      "description": "Deterministic synthetic finding for compatibility tests.",
      "detection": "The mock scanner generated this result from fixture data.",
      "created_at": "2026-01-01T00:00:10Z",
      "updated_at": "2026-01-01T00:00:10Z"
    }
  ]
}
```

The result set must be stable for the same scenario, seed, scan id, host count,
and result count.

### `DELETE /scans/{scan_id}`

Delete a scan.

Response:

- HTTP `204`
- no body

Repeated deletes for an already deleted scan must return a deterministic
documented response. Compatibility scenarios should include both successful
delete and scanner-refused delete behavior.

## Result Data Requirements

Each generated result must include enough data for manager-side report and
asset ingestion tests.

Minimum fields:

- stable external result id
- stable ordinal
- result type
- host IP address
- hostname
- port
- protocol
- service name
- NVT/OID
- NVT name
- NVT family
- severity
- threat level
- QoD
- description
- detection detail
- solution
- solution type
- created timestamp
- updated timestamp

Recommended fields:

- CVEs
- CPEs
- CVSS vector
- tags
- references
- vulnerability publication date
- certificate metadata for TLS-related scenarios
- application/product metadata for service scenarios

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
6. Result records include severity, QoD, NVT metadata, host/service identity,
   timestamps, and remediation fields.
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
