# Spec

This directory is the shared source of truth for all benchmark implementations.

Current documents:

- `mock-server.md` — contract for the OpenVAS Scanner REST API mock server benchmark
- `compatibility-mock-server.md` — stricter mock scanner contract for automated manager compatibility tests

Rules:

- Freeze spec changes before comparing model runs.
- Treat everything here as shared allowed context.
- Do not let one implementation read another implementation's code.
