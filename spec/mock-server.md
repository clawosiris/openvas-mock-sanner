# OpenVAS Scanner REST API Mock Server Spec

## Purpose

Define a fair, black-box implementation task for coding LLMs: build a mock server that imitates a small, testable subset of the OpenVAS Scanner REST API and returns generated synthetic results for automated testing.

The benchmark goal is not protocol-perfect emulation. The goal is consistent lifecycle behavior, predictable generated data, and a configurable result volume.

## Shared constraints

All implementations must satisfy this spec using only the shared benchmark inputs.

- The mock server must expose HTTP JSON endpoints.
- The mock server must run as a standalone process.
- The mock server must not require a real OpenVAS or Greenbone backend.
- The mock server must generate synthetic scan results in-process or from bundled code.
- The number of generated results returned by the server must be configurable by server configuration.
- Generated results must be deterministic for a given configuration and scan id.

## Required configuration

The server must support these configuration inputs.

### Required server configuration variables

- `MOCK_RESULT_COUNT`
  - integer
  - default: `100`
  - meaning: number of generated result objects returned by `GET /scans/{scan_id}/results`
- `MOCK_FINDINGS_DELAY_POLLS`
  - integer
  - default: `0`
  - meaning: number of result-poll requests that should return zero findings before findings appear
- `MOCK_SCAN_COMPLETE_POLLS`
  - integer
  - default: `1`
  - meaning: minimum number of status polls after scan start before the scan becomes `succeeded`
- `MOCK_HOST_COUNT`
  - integer
  - default: `10`
  - meaning: number of distinct synthetic hosts across generated results
- `MOCK_SEED`
  - string or integer
  - default: `openvas-mock-sanner`
  - meaning: deterministic seed material for generation

### Configuration behavior

- Invalid configuration must fail fast at startup with a useful error.
- `MOCK_RESULT_COUNT` must accept `0` and positive integers.
- If `MOCK_RESULT_COUNT` is `0`, the results endpoint must return an empty result list.
- Implementations may support additional configuration, but the harness will only rely on the variables above.

## HTTP API contract

### Common behavior

- Content type for JSON responses: `application/json`
- Unknown routes must return `404`
- Invalid JSON request bodies must return `400`
- Using a non-existent `scan_id` on scan-specific endpoints must return `404`

## Endpoints

### `POST /scans`

Create a mock scan.

#### Request body

The request body must accept any valid JSON object. The mock server does not need to fully validate OpenVAS payload semantics.

Minimum expectation:

```json
{
  "target": {},
  "vts": []
}
```

#### Response

- HTTP `201`
- JSON object containing a scan identifier

Example:

```json
{
  "id": "scan-0001"
}
```

#### Behavior

- The server must persist enough per-scan state to support start, stop, status, results, and delete.
- Scan ids must be unique within a server process.
- The server must retain the original create payload for that scan in memory, even if it is not exposed.

### `POST /scans/{scan_id}`

Perform a scan action.

#### Request body

```json
{
  "action": "start"
}
```

or

```json
{
  "action": "stop"
}
```

#### Response

- HTTP `200`
- JSON object describing current state

Example:

```json
{
  "id": "scan-0001",
  "status": "running"
}
```

#### Behavior

- `start` transitions a created or stopped scan to `running`.
- `stop` transitions a running scan to `stopped`.
- Repeated `start` or `stop` calls may be idempotent, but must not crash.
- Unknown actions must return `400`.

### `GET /scans/{scan_id}/status`

Get current scan status.

#### Response

- HTTP `200`
- JSON object

Example:

```json
{
  "id": "scan-0001",
  "status": "running"
}
```

#### Allowed statuses

- `created`
- `running`
- `stopped`
- `succeeded`
- `deleted` must not be returned because deleted scans must return `404`

#### Behavior

- A scan becomes `running` only after `start`.
- A running scan becomes `succeeded` after the configured number of status polls defined by `MOCK_SCAN_COMPLETE_POLLS`, unless it is stopped first.

### `GET /scans/{scan_id}/results`

Return generated synthetic results for a scan.

#### Response

- HTTP `200`
- JSON object with a `results` array

Example:

```json
{
  "scan_id": "scan-0001",
  "results": [
    {
      "id": 1,
      "type": "alarm",
      "ip_address": "10.42.0.1",
      "hostname": "synthetic-host-0001.lab",
      "oid": "1.3.6.1.4.1.25623.1.0.147696",
      "port": 22,
      "protocol": "tcp",
      "message": "Synthetic finding text"
    }
  ]
}
```

#### Behavior

- Before a scan has been started, the endpoint may either:
  - return an empty `results` array, or
  - return generated results immediately.

To keep the benchmark stable, the preferred behavior is:
- before `start`: empty `results`
- after `start`: results appear according to `MOCK_FINDINGS_DELAY_POLLS`

- While the scan is running, the server must count per-scan result polls.
- For the first `MOCK_FINDINGS_DELAY_POLLS` requests after scan start, the endpoint must return an empty results list.
- After that threshold, the endpoint must return exactly `MOCK_RESULT_COUNT` generated results.
- Returned result data must be deterministic for a given scan id, seed, host count, and result count.
- The same scan queried multiple times after findings appear must return the same result objects in the same order.

## Generated result shape

Each generated result object must include at least:

- `id` — integer, unique within the result set, starting at `1`
- `type` — string, usually `alarm` or `log`
- `ip_address` — string
- `hostname` — string
- `oid` — string
- `port` — integer
- `protocol` — string
- `message` — string

### Generated data expectations

- Results should be spread across `MOCK_HOST_COUNT` synthetic hosts when possible.
- If `MOCK_RESULT_COUNT` is smaller than `MOCK_HOST_COUNT`, implementations may use fewer hosts.
- At least three distinct OIDs should be cycled when the result count is large enough.
- Messages should look plausibly scanner-like, but do not need to match real Greenbone output exactly.
- Data must be synthetic and safe to publish.

## `DELETE /scans/{scan_id}`

Delete a mock scan.

### Response

- HTTP `200` or `204`

### Behavior

- After deletion, subsequent status, results, action, or delete requests for that scan id must return `404`.

## Non-functional requirements

- The implementation must start locally with a documented command.
- The implementation must be self-contained enough for black-box automated testing.
- The implementation must not require network access after dependencies are installed.
- The implementation should start in less than 10 seconds on a normal developer machine.

## Acceptance criteria

A black-box harness should be able to verify all of the following.

1. Server starts successfully with default configuration.
2. `POST /scans` returns `201` and a scan id.
3. `GET /scans/{scan_id}/status` returns `created` before start.
4. `POST /scans/{scan_id}` with `{"action":"start"}` transitions the scan to `running`.
5. `GET /scans/{scan_id}/results` returns zero findings until the configured delay threshold is crossed.
6. After the threshold, `GET /scans/{scan_id}/results` returns exactly `MOCK_RESULT_COUNT` results.
7. Result ids are unique and stable.
8. Repeated result fetches after findings appear return the same ordered data.
9. After enough status polls, `GET /scans/{scan_id}/status` returns `succeeded` unless the scan was stopped.
10. `POST /scans/{scan_id}` with `{"action":"stop"}` transitions the scan to `stopped`.
11. `DELETE /scans/{scan_id}` removes the scan.
12. Further requests for that scan id return `404`.
13. Invalid action requests return `400`.
14. Invalid startup configuration fails fast.

## Out of scope

- Real OpenVAS compatibility beyond this narrow contract
- Authentication and authorization
- Persistence across restarts
- Real scan execution
- Full OpenAPI parity
- Streaming or websocket updates

## Notes for benchmark design

To keep the benchmark fair:

- freeze this spec before generation begins
- freeze the acceptance harness separately
- do not expose sibling implementations during generation
- score correctness first, then code quality and iteration count
