# deepseek4-flash

OpenVAS Scanner REST API mock server implementation for the mock-server benchmark.

Built with Rust, tiny_http, serde, and ChaCha-based deterministic pseudorandom generation.

## Run locally

```bash
PORT=8080 cargo run --quiet
```

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | HTTP listen port |
| `MOCK_RESULT_COUNT` | `100` | Number of results to generate |
| `MOCK_FINDINGS_DELAY_POLLS` | `0` | Empty result polls before findings appear |
| `MOCK_SCAN_COMPLETE_POLLS` | `1` | Status polls before scan auto-completes |
| `MOCK_HOST_COUNT` | `10` | Distinct synthetic hosts |
| `MOCK_SEED` | `openvas-mock-sanner` | Determinism seed |
