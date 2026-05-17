# Benchmark Scoreboard

- Results root: `results`
- Implementations: 7
- Total runs: 8
- Passed runs: 6
- Overall pass rate: 75.0%
- Generation times source: `results/model-generation-times.json`

## Per implementation

| Implementation | Runs | Passed | Failed | Pass rate | Avg passed checks | Generation time | Latest run | Latest status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| baseline-rust | 1 | 1 | 0 | 100.0% | 21.0/21.0 | - | 20260517-130903 | pass |
| deepseek4 | 1 | 1 | 0 | 100.0% | 21.0/21.0 | 5m30s | 20260517-132835 | pass |
| deepseek4-flash | 1 | 1 | 0 | 100.0% | 21.0/21.0 | 12m37s | 20260517-132835 | pass |
| gpt54 | 1 | 1 | 0 | 100.0% | 21.0/21.0 | 7m21s | 20260517-132836 | pass |
| gpt55 | 1 | 1 | 0 | 100.0% | 21.0/21.0 | 4m24s | 20260517-132836 | pass |
| qwencoder | 2 | 0 | 2 | 0.0% | 0.0/0.5 | 7m41s | 20260517-150430 | fail |
| qwencoder-next | 1 | 1 | 0 | 100.0% | 21.0/21.0 | 1m58s | 20260517-141738 | pass |

### baseline-rust

- Runs: 1
- Pass rate: 100.0%
- Latest run: `results/baseline-rust/20260517-130903/summary.json`
- Failing checks seen: none 🎉

### deepseek4

- Runs: 1
- Pass rate: 100.0%
- Latest run: `results/deepseek4/20260517-132835/summary.json`
- Generation time: 5m30s via `ollama/deepseek-v4-pro` (completed)
- Failing checks seen: none 🎉

### deepseek4-flash

- Runs: 1
- Pass rate: 100.0%
- Latest run: `results/deepseek4-flash/20260517-132835/summary.json`
- Generation time: 12m37s via `ollama/deepseek-v4-flash` (completed)
- Failing checks seen: none 🎉

### gpt54

- Runs: 1
- Pass rate: 100.0%
- Latest run: `results/gpt54/20260517-132836/summary.json`
- Generation time: 7m21s via `gpt54` (completed)
- Failing checks seen: none 🎉

### gpt55

- Runs: 1
- Pass rate: 100.0%
- Latest run: `results/gpt55/20260517-132836/summary.json`
- Generation time: 4m24s via `gpt55` (completed)
- Failing checks seen: none 🎉

### qwencoder

- Runs: 2
- Pass rate: 0.0%
- Latest run: `results/qwencoder/20260517-150430/summary.json`
- Generation time: 7m41s via `ollama/qwen3-coder:480b-cloud` (completed_but_failed_harness)
- Failing checks seen:
  - `results_delay_poll_1`: 1 time(s)

### qwencoder-next

- Runs: 1
- Pass rate: 100.0%
- Latest run: `results/qwencoder-next/20260517-141738/summary.json`
- Generation time: 1m58s via `ollama/qwen3-coder-next` (completed)
- Failing checks seen: none 🎉
