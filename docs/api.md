# HTTP API

The mock scanner exposes the HTTP subset of the openvasd scanner API used by
gvmd's HTTP scanner connector. Responses are deterministic for a given
scenario, seed, and scan id. Legacy helper endpoints from the first mock
version are still available, but the openvasd-compatible paths are the primary
contract.

## Health and Discovery

`GET /health`

Returns process health and the active scenario.

```json
{"scenario":"success-basic","status":"ok"}
```

`GET /capabilities`

Returns the fixture API version and supported lifecycle features.

`HEAD /scans`, `HEAD /vts`, `HEAD /health`

Return openvasd-style metadata headers: `api-version`, `feed-version`, and
`authentication`.

`GET /health/alive`, `GET /health/ready`, `GET /health/started`

Return process health for openvasd-style container probes.

`GET /scans/preferences`

Returns synthetic scanner preferences such as port range, alive test, and
maximum checks. Manager tests can use this endpoint to validate preference
discovery without depending on a real scanner feed.

`GET /vts`

Returns a deterministic list of VT OIDs so managers can exercise feed/NVT
discovery paths without mounting a real feed. When `MOCK_VT_METADATA_PATH` or
`MOCK_NOTUS_ADVISORIES_PATH` is configured, this list comes from the loaded VT
metadata and package-advisory fixtures.

`GET /vts/{oid}`

Returns VT metadata for a loaded feed-backed OID, including fields such as
name, family, severity, CVEs, references, tags, QoD, and solution data when the
fixture provides them. SCAP/CVE metadata from `MOCK_SCAP_METADATA_PATH` may
fill advisory severity, CVSS vector, references, and summary fields. This
metadata is intentionally separate from raw scanner results.

## Scan Lifecycle

`POST /scans`

Creates a scan and returns a deterministic scan id.

```json
"scan-0001"
```

The request body must be a JSON object. If the body contains `scan_id`, the
mock uses that id; this matches gvmd's current openvasd payload builder, which
passes the report id through to the scanner. Otherwise the mock allocates
`scan-0001`, `scan-0002`, and so on. The mock stores the payload for
traceability and uses target hosts, ports, selected `vts[].oid`, and scan
preferences as deterministic hints for feed-backed result generation when that
mode is enabled.

`GET /scans/{id}`

Returns the stored scan configuration plus `scan_id`.

`POST /scans/{id}`

Performs an openvasd scan action. The body must be `{"action":"start"}` or
`{"action":"stop"}`. Successful actions return `204`.

`GET /scans/{id}/status`

Returns status, progress, and poll count. Polling advances deterministic
scenario state, so tests do not need sleeps to make scans complete.

`GET /scans/{id}/results`

Returns paged result data. The openvasd `range=0-12` query form is supported.
For compatibility with existing mock clients, `offset`/`limit` and
`page`/`page_size` are also accepted. The response contains openvasd-compatible
`items` and `results` fields with the same raw scanner result objects. Scanner
results intentionally contain only the result id/type, host, OID, port/protocol,
and message; CVE, CVSS, references, tags, and other VT details belong to
`/vts` or manager-side report enrichment.

`GET /scans/{id}/results/{rid}`

Returns a single result by zero-based openvasd result id.

`POST /scans/{id}/start` and `POST /scans/{id}/stop`

Legacy aliases for older mock clients. Prefer `POST /scans/{id}` with an
action body for drop-in openvasd compatibility.

`DELETE /scans/{id}`

Deletes a scan. Deleted scans return `404` from scan-specific endpoints.

## Errors

Errors use a stable JSON envelope:

```json
{"error":{"code":"scan_not_found","message":"scan id does not exist"}}
```

Fault scenarios and `MOCK_FAILURE_AT` use the same envelope so manager tests can
exercise retry, import, and cleanup behavior.
