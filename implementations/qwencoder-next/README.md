# qwencoder-next

Implementation of the OpenVAS mock-server benchmark in Rust.

## Run locally

```bash
PORT=8080 cargo run --quiet
```

Optional environment variables:

- `MOCK_RESULT_COUNT`
- `MOCK_FINDINGS_DELAY_POLLS`
- `MOCK_SCAN_COMPLETE_POLLS`
- `MOCK_HOST_COUNT`
- `MOCK_SEED`

## Notes

- Deterministic per scan id and seed
- Uses minimal dependencies (tiny_http, serde, serde_json)
