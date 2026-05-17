# Harness

This directory is for the shared black-box benchmark runner.

## Intended contract

The harness should:

1. Start an implementation as an isolated process or container.
2. Discover its base URL from a documented contract.
3. Run the same lifecycle checks for every implementation.
4. Record pass/fail, logs, timings, and artifact paths.
5. Avoid reading implementation internals when scoring correctness.

## Included files

- `run_benchmark.py` — black-box acceptance runner
- `score.py` — aggregate repeated benchmark runs into per-implementation score summaries
- `quality_score.py` — score implementations on correctness, static quality, maintainability, and optional reviewer findings
- `combined_leaderboard.py` — combine correctness, quality, and generation time into one leaderboard
- `IMPLEMENTATION_CONTRACT.md` — required manifest contract for each implementation

## Suggested future files

- `run_benchmark.py` or `run_benchmark.sh`
- `acceptance/` for black-box lifecycle tests
- `score.py` for metric aggregation
- `artifacts/` for temporary runner outputs

## Aggregation

Example:

```bash
python3 harness/score.py
python3 harness/score.py --implementation baseline-rust --format markdown
python3 harness/score.py --write-json results/scoreboard.json --write-markdown results/scoreboard.md
```

## Code quality scoring

Example:

```bash
python3 harness/quality_score.py
python3 harness/quality_score.py --implementation gpt55 --format markdown
python3 harness/quality_score.py --reviews-root reviews --write-json results/quality-scoreboard.json --write-markdown results/quality-scoreboard.md
python3 harness/combined_leaderboard.py --write-json results/combined-leaderboard.json --write-markdown results/combined-leaderboard.md
```

The quality scorer combines:

- latest benchmark correctness from `results/*/*/summary.json`
- `cargo check`
- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- lightweight maintainability heuristics (Rust LOC, longest Rust file, dependency count)
- optional reviewer findings loaded from `reviews/<implementation>.json`

Reviewer findings are optional so you can layer in GitHub Copilot review later without blocking local runs.
