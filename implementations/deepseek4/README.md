# OpenVAS Mock Server — deepseek4

Rust implementation of the OpenVAS Scanner REST API mock server using actix-web.

## Endpoints

- `POST /scans` — Create a mock scan
- `POST /scans/{scan_id}` — Start or stop a scan
- `GET /scans/{scan_id}/status` — Get current scan status
- `GET /scans/{scan_id}/results` — Get synthetic scan results
- `DELETE /scans/{scan_id}` — Delete a scan

## Configuration

| Variable | Type | Default | Description |
|---|---|---|---|
| `PORT` | integer | (required) | HTTP listen port |
| `MOCK_RESULT_COUNT` | integer | 100 | Number of generated results |
| `MOCK_FINDINGS_DELAY_POLLS` | integer | 0 | Result polls before findings appear |
| `MOCK_SCAN_COMPLETE_POLLS` | integer | 1 | Status polls before scan succeeds |
| `MOCK_HOST_COUNT` | integer | 10 | Number of synthetic hosts |
| `MOCK_SEED` | string | openvas-mock-sanner | Deterministic seed |

## Running

```bash
PORT=8080 cargo run --quiet
```

## Building

```bash
cargo build --release
PORT=8080 ./target/release/openvas-mock-server
```
