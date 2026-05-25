# HTTP API

The mock scanner exposes a compact JSON API for gvmd and gvmd-ng compatibility
tests. Responses are deterministic for a given scenario, seed, and scan id.

## Health and Discovery

`GET /health`

Returns process health and the active scenario.

```json
{"scenario":"success-basic","status":"ok"}
```

`GET /capabilities`

Returns the fixture API version and supported lifecycle features.

`GET /preferences`

Returns synthetic scanner preferences such as port range, alive test, and
maximum checks. Manager tests can use this endpoint to validate preference
discovery without depending on a real scanner feed.

## Scan Lifecycle

`POST /scans`

Creates a scan and returns a deterministic scan id.

```json
{"id":"scan-0001"}
```

The request body must be a JSON object. The mock stores it for traceability but
does not validate Greenbone target semantics.

`POST /scans/{id}/start`

Starts or restarts a scan. Successful starts return `204`.

`POST /scans/{id}/stop`

Stops a non-terminal scan. Successful stops return `204`.

`GET /scans/{id}/status`

Returns status, progress, and poll count. Polling advances deterministic
scenario state, so tests do not need sleeps to make scans complete.

`GET /scans/{id}/results`

Returns paged result data. Both `offset`/`limit` and `page`/`page_size` are
accepted.

`DELETE /scans/{id}`

Deletes a scan. Deleted scans return `404` from scan-specific endpoints.

## Errors

Errors use a stable JSON envelope:

```json
{"error":{"code":"scan_not_found","message":"scan id does not exist"}}
```

Fault scenarios and `MOCK_FAILURE_AT` use the same envelope so manager tests can
exercise retry, import, and cleanup behavior.
