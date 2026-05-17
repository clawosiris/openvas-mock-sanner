# Track 1 — Spec Only

You are implementing a standalone mock server for benchmark purposes.

Read and follow:

- `spec/mock-server.md`

Constraints:

- Work only inside your assigned implementation directory.
- Do not read sibling implementation directories.
- You may create any files needed inside your implementation directory.
- Use Rust for the implementation.
- Prefer minimal dependencies.
- The server must bind on `127.0.0.1` and honor the port provided by the `PORT` environment variable.

Deliverables:

1. A runnable implementation of the mock server.
2. A `benchmark.json` file matching `harness/IMPLEMENTATION_CONTRACT.md`.
3. A short `README.md` explaining how to run it.

Definition of done:

- The implementation satisfies `spec/mock-server.md`.
- The implementation starts locally and serves the required endpoints.
- Invalid startup configuration fails fast with a non-zero exit code.
