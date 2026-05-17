# Harness

This directory is for the shared black-box benchmark runner.

## Intended contract

The harness should:

1. Start an implementation as an isolated process or container.
2. Discover its base URL from a documented contract.
3. Run the same lifecycle checks for every implementation.
4. Record pass/fail, logs, timings, and artifact paths.
5. Avoid reading implementation internals when scoring correctness.

## Suggested future files

- `run_benchmark.py` or `run_benchmark.sh`
- `acceptance/` for black-box lifecycle tests
- `score.py` for metric aggregation
- `artifacts/` for temporary runner outputs
