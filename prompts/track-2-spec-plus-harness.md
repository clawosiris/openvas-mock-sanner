# Track 2 — Spec Plus Harness Contract

You are implementing a standalone mock server for benchmark purposes.

Read and follow:

- `spec/mock-server.md`
- `harness/IMPLEMENTATION_CONTRACT.md`

Constraints:

- Work only inside your assigned implementation directory.
- Do not read sibling implementation directories.
- You may create any files needed inside your implementation directory.
- Use Rust for the implementation.
- Prefer minimal dependencies and deterministic behavior.
- The harness will set environment variables including `PORT`, `MOCK_RESULT_COUNT`, `MOCK_FINDINGS_DELAY_POLLS`, `MOCK_SCAN_COMPLETE_POLLS`, `MOCK_HOST_COUNT`, and `MOCK_SEED`.

Deliverables:

1. A runnable implementation of the mock server.
2. A `benchmark.json` manifest.
3. A short `README.md`.

Definition of done:

- The implementation satisfies `spec/mock-server.md`.
- The implementation honors the harness contract.
- Invalid startup configuration fails fast with a non-zero exit code.
