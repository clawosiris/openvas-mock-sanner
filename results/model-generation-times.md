# Model Generation Times

These durations are the observed implementation-generation times from the isolated model runs.
They are **not** the shared harness execution times.

| Implementation | Model | Status | Duration |
| --- | --- | --- | ---: |
| deepseek4 | `ollama/deepseek-v4-pro` | completed | 5m30s |
| deepseek4-flash | `ollama/deepseek-v4-flash` | completed | 12m37s |
| gpt54 | `gpt54` | completed | 7m21s |
| gpt55 | `gpt55` | completed | 4m24s |
| qwencoder | `ollama/qwen3-coder` | failed_model_not_found | 16s |
| qwencoder | `ollama/qwen3-coder:480b-cloud` | incomplete_attempt | 2m11s |
| qwencoder | `ollama/qwen3-coder:480b-cloud` | completed_but_failed_harness | 7m41s |
| qwencoder-next | `ollama/qwen3-coder-next` | completed | 1m58s |

## Fastest completed implementation runs

1. `ollama/qwen3-coder-next` — 1m58s
2. `gpt55` — 4m24s
3. `ollama/deepseek-v4-pro` — 5m30s
4. `gpt54` — 7m21s
5. `ollama/deepseek-v4-flash` — 12m37s

## Notes

- `ollama/qwen3-coder:480b-cloud` had one early incomplete attempt and one later attempt that produced code but failed the shared harness.
- `ollama/qwen3-coder` without the explicit suffix failed immediately because the model was not available.
