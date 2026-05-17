# Implementation Contract

Every benchmark implementation must provide a `benchmark.json` file at the root of its implementation directory.

Example:

```json
{
  "name": "baseline-rust",
  "start_command": ["cargo", "run", "--quiet"],
  "port_env": "PORT",
  "env": {
    "MOCK_RESULT_COUNT": "7",
    "MOCK_FINDINGS_DELAY_POLLS": "2",
    "MOCK_SCAN_COMPLETE_POLLS": "3",
    "MOCK_HOST_COUNT": "3",
    "MOCK_SEED": "benchmark-seed"
  }
}
```

Required fields:

- `name` — implementation label
- `start_command` — JSON array command used to start the server
- `port_env` — environment variable name the harness uses to inject the HTTP listen port

Optional fields:

- `env` — extra environment variables for a normal benchmark run
- `cwd` — relative working directory inside the implementation directory; default is `.`

Runtime expectations:

- The process must bind on `127.0.0.1` using the port from `port_env`.
- The process must remain in the foreground until terminated.
- The process must implement the contract in `spec/mock-server.md`.
- The process must exit non-zero on invalid startup configuration.
