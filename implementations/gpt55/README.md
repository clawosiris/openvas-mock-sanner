# gpt55 Rust OpenVAS mock server

Standalone Rust mock server for the benchmark contract.

## Run

```sh
PORT=8080 cargo run --quiet
```

The server binds to `127.0.0.1:$PORT` and stays in the foreground.

## Configuration

Environment variables:

- `MOCK_RESULT_COUNT` (default `100`, accepts `0`)
- `MOCK_FINDINGS_DELAY_POLLS` (default `0`)
- `MOCK_SCAN_COMPLETE_POLLS` (default `1`)
- `MOCK_HOST_COUNT` (default `10`, must be greater than `0`)
- `MOCK_SEED` (default `openvas-mock-sanner`)

Invalid numeric configuration exits non-zero at startup.
