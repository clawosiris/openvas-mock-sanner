# Quality Scoreboard

- Reviews root: `reviews`
- Generation times source: `results/model-generation-times.json`

| Implementation | Correctness | Static | Maintainability | Reviewer | Generation time | Total (no review) | Total (with review) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline-rust | 50.0 | 10.0 | 6.0 | n/a | - | 66.0 | n/a |
| deepseek4 | 50.0 | 15.0 | 4.0 | n/a | 5m30s | 69.0 | n/a |
| deepseek4-flash | 50.0 | 5.0 | 4.0 | n/a | 12m37s | 59.0 | n/a |
| gpt54 | 50.0 | 15.0 | 4.0 | n/a | 7m21s | 69.0 | n/a |
| gpt55 | 50.0 | 10.0 | 4.0 | n/a | 4m24s | 64.0 | n/a |
| qwencoder | 0.0 | 5.0 | 4.0 | n/a | 7m41s | 9.0 | n/a |
| qwencoder-next | 50.0 | 10.0 | 6.0 | n/a | 1m58s | 66.0 | n/a |

## baseline-rust

- Latest benchmark: `results/baseline-rust/20260517-130903/summary.json`
- Generation time: none
- Rust LOC: 339
- Longest Rust file: 366 lines
- Dependency count: 16
- Maintainability notes:
  - large Rust file: 366 lines
  - moderate dependency count: 16
- Reviewer findings source: none

## deepseek4

- Latest benchmark: `results/deepseek4/20260517-132835/summary.json`
- Generation time: 5m30s via `ollama/deepseek-v4-pro` (completed)
- Rust LOC: 343
- Longest Rust file: 425 lines
- Dependency count: 187
- Maintainability notes:
  - large Rust file: 425 lines
  - high dependency count: 187
- Reviewer findings source: none

## deepseek4-flash

- Latest benchmark: `results/deepseek4-flash/20260517-132835/summary.json`
- Generation time: 12m37s via `ollama/deepseek-v4-flash` (completed)
- Rust LOC: 325
- Longest Rust file: 409 lines
- Dependency count: 26
- Maintainability notes:
  - large Rust file: 409 lines
  - high dependency count: 26
- Reviewer findings source: none

## gpt54

- Latest benchmark: `results/gpt54/20260517-132836/summary.json`
- Generation time: 7m21s via `gpt54` (completed)
- Rust LOC: 323
- Longest Rust file: 365 lines
- Dependency count: 56
- Maintainability notes:
  - large Rust file: 365 lines
  - high dependency count: 56
- Reviewer findings source: none

## gpt55

- Latest benchmark: `results/gpt55/20260517-132836/summary.json`
- Generation time: 4m24s via `gpt55` (completed)
- Rust LOC: 347
- Longest Rust file: 390 lines
- Dependency count: 54
- Maintainability notes:
  - large Rust file: 390 lines
  - high dependency count: 54
- Reviewer findings source: none

## qwencoder

- Latest benchmark: `results/qwencoder/20260517-150430/summary.json`
- Generation time: 7m41s via `ollama/qwen3-coder:480b-cloud` (completed_but_failed_harness)
- Rust LOC: 288
- Longest Rust file: 374 lines
- Dependency count: 185
- Maintainability notes:
  - large Rust file: 374 lines
  - high dependency count: 185
- Reviewer findings source: none

## qwencoder-next

- Latest benchmark: `results/qwencoder-next/20260517-141738/summary.json`
- Generation time: 1m58s via `ollama/qwen3-coder-next` (completed)
- Rust LOC: 339
- Longest Rust file: 366 lines
- Dependency count: 16
- Maintainability notes:
  - large Rust file: 366 lines
  - moderate dependency count: 16
- Reviewer findings source: none
