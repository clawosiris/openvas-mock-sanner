# gpt54 OpenVAS mock server

Rust implementation of the benchmark OpenVAS Scanner REST API mock server.

## Run

```bash
PORT=3000 cargo run --quiet
```

Optional environment variables:

- `MOCK_RESULT_COUNT` (default `100`)
- `MOCK_FINDINGS_DELAY_POLLS` (default `0`)
- `MOCK_SCAN_COMPLETE_POLLS` (default `1`)
- `MOCK_HOST_COUNT` (default `10`)
- `MOCK_SEED` (default `openvas-mock-sanner`)

The server binds to `127.0.0.1:$PORT` and exits non-zero on invalid startup configuration.
