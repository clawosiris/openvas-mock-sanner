# Combined Leaderboard

- Generation times source: `results/model-generation-times.json`
- Reviews root: `reviews`
- Quality score = correctness + static quality + maintainability, with reviewer points added only when a human review exists.
- In this table, "no review" means "no human review".

| Rank | Implementation | Latest benchmark | Pass rate | Quality (no review) | Quality (with review) | Generation time |
| ---: | --- | --- | ---: | ---: | ---: | ---: |
| 1 | deepseek4 | pass | 100.0% | 69.0 | n/a | 5m30s |
| 2 | gpt54 | pass | 100.0% | 69.0 | n/a | 7m21s |
| 3 | qwencoder-next | pass | 100.0% | 66.0 | n/a | 1m58s |
| 4 | baseline-rust | pass | 100.0% | 66.0 | n/a | - |
| 5 | gpt55 | pass | 100.0% | 64.0 | n/a | 4m24s |
| 6 | deepseek4-flash | pass | 100.0% | 59.0 | n/a | 12m37s |
| 7 | qwencoder | fail | 0.0% | 9.0 | n/a | 7m41s |
