# OpenVAS Mock Server - qwencoder Implementation

This is a Rust implementation of the OpenVAS Scanner REST API mock server for benchmarking purposes.

## Requirements

- Rust and Cargo installed

## Configuration

The server supports the following environment variables:

- `PORT` - HTTP listen port (required)
- `MOCK_RESULT_COUNT` - Number of generated results (default: 100)
- `MOCK_FINDINGS_DELAY_POLLS` - Delay before returning results (default: 0)
- `MOCK_SCAN_COMPLETE_POLLS` - Polls before scan completion (default: 1)
- `MOCK_HOST_COUNT` - Number of synthetic hosts (default: 10)
- `MOCK_SEED` - Seed for deterministic generation (default: "openvas-mock-sanner")

## Running

```bash
PORT=8080 cargo run
```

## API Endpoints

- `POST /scans` - Create a new scan
- `POST /scans/{scan_id}` - Start/stop a scan
- `GET /scans/{scan_id}/status` - Get scan status
- `GET /scans/{scan_id}/results` - Get scan results
- `DELETE /scans/{scan_id}` - Delete a scan

See `spec/mock-server.md` for detailed API specification.