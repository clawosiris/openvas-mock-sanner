# openvas-mock-sanner

Benchmark repo for comparing coding LLM implementations of the same OpenVAS Scanner REST API mock server task.

## Layout

- `spec/` — shared source of truth for the task, API contract, and acceptance criteria
- `harness/` — shared black-box runner contract and future benchmark scripts
- `implementations/` — isolated per-model implementations
- `fixtures/` — shared non-code fixtures allowed for all implementations
- `results/` — benchmark outputs, logs, and scores

## Isolation rules

Each implementation should only receive shared context from:

- `spec/`
- `fixtures/`
- `harness/`

Implementations should not read sibling implementation directories during generation or repair if you want apples-to-apples comparisons.

## Intended workflow

1. Freeze the spec in `spec/`.
2. Freeze the harness expectations in `harness/`.
3. Create one isolated implementation per model under `implementations/`.
4. Run the same black-box harness against each implementation.
5. Store logs and scores in `results/`.

## Suggested implementation directories

- `implementations/baseline/`
- `implementations/model-a/`
- `implementations/model-b/`
- `implementations/model-c/`

## License

AGPL-3.0-only. See `LICENSE`.

## Status

Initial repo scaffold and first draft mock-server spec created.
