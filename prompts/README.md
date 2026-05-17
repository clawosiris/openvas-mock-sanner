# Prompt Pack

This directory contains standardized prompts for comparing coding LLMs on the same task.

## Included prompts

- `track-1-spec-only.md` — give the model only the spec and repo layout goal
- `track-2-spec-plus-harness.md` — give the model the spec plus the harness contract
- `repair-pass.md` — use after a failed benchmark run with attached failure output

## Usage rules

- Freeze the prompt text before comparing runs.
- Do not include sibling implementation code in the model context.
- For a strict comparison, reset to a clean implementation directory before each run.
- Store the exact prompt, model id, and output artifacts under `results/`.
