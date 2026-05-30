# Upstream OpenVAS Watch

The scheduled upstream watcher checks `greenbone/openvas-scanner` once per day
and opens a repository issue when upstream behavior appears relevant to this
mock scanner.

The watcher deliberately uses two gates:

1. A deterministic file/path/keyword prefilter narrows the upstream diff to
   scanner surfaces this project can plausibly emulate: openvasd HTTP behavior,
   scan/result/status JSON, VT/feed handling, Notus/SCAP behavior, scanner
   lifecycle, and error semantics.
2. Ollama Cloud classifies only that compact diff summary. The default model is
   `qwen2.5-coder:7b`; the workflow escalates to `qwen2.5-coder:14b` only when
   the 7B pass returns `needs-human-review` or confidence below the configured
   threshold.

The classifier decisions are:

- `ignore` — no issue is filed and the last-seen upstream commit is advanced.
- `replicate` — an issue is filed with the upstream range, candidate files,
  model reasoning, and suggested mock-scanner changes.
- `needs-human-review` — an issue is filed with a review label because the
  change may matter but the model did not classify it cleanly.

State is stored in the repository Actions variable
`OPENVAS_SCANNER_LAST_SEEN` when GitHub permits the workflow token to write it.
If that write is blocked, the watcher falls back to a closed issue named
`Upstream OpenVAS watcher state` with a machine-readable state marker. On the
first run, the workflow initializes state to the current upstream head and exits
without filing a replication issue.

## Required Secrets

- `OLLAMA_CLOUD_BASE_URL` — Ollama Cloud API base URL.
- `OLLAMA_API_KEY` — Ollama Cloud API key.

The workflow uses `GITHUB_TOKEN` to read and update the Actions variable and to
open issues.

## Manual Run

Use the `Upstream OpenVAS Watch` workflow dispatch input `base_ref` to force a
specific upstream comparison base. Set `dry_run` to classify the range without
filing an issue or updating `OPENVAS_SCANNER_LAST_SEEN`.
