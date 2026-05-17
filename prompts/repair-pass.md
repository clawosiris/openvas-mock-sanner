# Repair Pass Prompt

Your previous implementation did not pass the black-box benchmark.

Read and follow:

- `spec/mock-server.md`
- `harness/IMPLEMENTATION_CONTRACT.md`

You are also given:

- the failing benchmark `summary.json`
- relevant stdout/stderr logs from that run

Rules:

- Repair only the implementation in your assigned directory.
- Do not read sibling implementation directories.
- Keep the implementation in Rust.
- Preserve working behavior where possible.
- Optimize for correctness first, not style.

Task:

1. Diagnose the failing checks from the benchmark output.
2. Fix the implementation.
3. Update the implementation README only if the run instructions changed.

Done when:

- the implementation satisfies the benchmark harness without relying on special-case knowledge of other implementations
