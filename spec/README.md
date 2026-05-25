# Spec

This directory is the shared source of truth for all benchmark implementations.

Current documents:

- `mock-server.md` — contract for the OpenVAS Scanner REST API mock server benchmark
- `compatibility-mock-server.md` — stricter mock scanner contract for automated manager compatibility tests
- `implementation-spec.md` — concrete implementation contract for the compatibility mock scanner service
- `test-plan.md` — verification plan and readiness gate for the compatibility mock scanner

Rules:

- Freeze spec changes before comparing model runs.
- Treat everything here as shared allowed context.
- Do not let one implementation read another implementation's code.
