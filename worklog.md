# Worklog

## 2026-05-26 Issue #9 Raw Result Test Alignment

- Branch: `issue9-raw-results-tests`
- Mission: align issue #9 tests/specs with the raw openvasd scanner result
  boundary introduced by PR #11.
- Progress:
  - Created a fresh checkout from `main` because the older local checkout has
    divergent local history.
  - Created branch `issue9-raw-results-tests` from commit `9ae0bd6`.
  - Attempted to delegate implementation through Codex CLI. The OpenClaw Codex
    home failed with missing bearer/basic auth; `/home/node/.codex` failed with
    an expired/reused refresh token. Codex CLI needs re-login before it can run
    in this environment.
  - Added HTTP contract assertions that public result pages and single-result
    lookups expose exactly raw openvasd scanner fields.
  - Updated compatibility and test-plan wording so severity, QoD, VT metadata,
    timestamps, and remediation are reserved for VT metadata or manager/report
    enrichment rather than public `/scans/{id}/results`.
- Verification:
  - `python3 -m unittest discover` passed: 25 tests in 9.768s.
  - `git diff --check` passed.
- Next:
  - Rebase, push branch, open PR.

## 2026-05-26 Feed-Backed Results Spec

- Branch: `spec/feed-backed-results`
- Mission: create an implementation-facing spec for feed-backed realistic scan result generation from issue #9.
- Progress:
  - Reviewed issue #9 and the current spec structure.
  - Added `spec/feed-backed-results.md`.
  - Updated `spec/README.md` so the new spec is discoverable.
  - Verified `git diff --check` and `python3 -m unittest discover`.
  - Investigated PR #10 CI after the initial container job failed in `actions/checkout`.
  - Reran the failed workflow job; the rerun stayed queued without materializing jobs.
  - Rechecked local unit coverage on the PR worktree: 24 tests passed.
  - Validated the PR branch on the Hetzner Docker host: unit tests, image build, health readiness, and scan lifecycle smoke all passed.
- Current state:
  - The new spec defines feed metadata loading, scan intent extraction, target profile fixtures, deterministic candidate ranking, result field mapping, feed-aware scenarios, validation through `scan-examples`, and phased implementation steps.
  - The original failed container job did not reach Docker. Checkout failed with GitHub 403 and the message "Your account is suspended"; the Python matrix passed on the same commit.
- Key learnings:
  - Current result generation is isolated in `openvas_mock_scanner/results.py`, making feed-backed generation a separable mode rather than a rewrite of HTTP lifecycle behavior.
  - Synthetic mode should remain default because existing compatibility tests and CI rely on fixture-light deterministic output.
  - The observed PR #10 failure is CI infrastructure/auth related, not a container behavior failure in this branch.
- Test results:
  - Local: `python3 -m unittest discover` passed: 24 tests in 8.728s.
  - Remote Hetzner Docker host `65.21.192.17`: cloned `spec/feed-backed-results`, `python3 -m unittest discover` passed 24 tests in 9.155s, `docker build -t openvas-mock-scanner:pr10 .` succeeded, and a container on host port `18083` passed `/health/alive`, scan create/start/status, and `results?range=0-1` smoke checks.
- Next:
  - Wait for GitHub Actions to recover or be rerun successfully; the branch-level code and container validation is clean.

## 2026-05-25

- Branch: `feature/compatibility-mock-scanner`
- Start point: `origin/devel` at `86b57a4`
- Decision: use Python stdlib only (`http.server`, `unittest`) because the repo
  was empty and the spec asks for a minimal, conventional stack with fast local
  tests and no external services.
- Progress:
  - Added deterministic runtime configuration parsing and validation.
  - Added in-memory scan lifecycle state.
  - Added deterministic synthetic result generation.
  - Added HTTP JSON endpoints required by the implementation spec.
  - Added unit, HTTP contract, scenario acceptance, and determinism tests.
  - Updated `README.md` with run/test instructions and curl examples.
  - Rebased on latest `origin/devel`; branch was already up to date.
  - Added AGPL-3.0-or-later licensing.
  - Added Dockerfile, .dockerignore, GitHub Actions CI, container smoke test,
    and GHCR publishing for `main`, `devel`, and `v*` tags.
  - Started manual Docker verification on Hetzner host `65.21.192.17` as
    `dev-gea`; remote Docker is available and the user is in the `docker`
    group.
  - Adding docstrings, explanatory comments, README/docs, release automation,
    nightly container builds, and final squash merge path to `main`.
  - Added `docs/api.md`, `docs/container.md`, and `docs/release.md`.
  - Updated CI to build the container for scheduled nightlies and `v*` release
    tags; publish `nightly`, `latest`, branch, semver, and SHA image tags; and
    create GitHub releases for `v*` tags after the container job succeeds.
- Failures/workarounds:
  - The command sandbox could not start because `bubblewrap` is unavailable, so
    repository commands were run with explicit elevated approval.
- Test results:
  - `python -m unittest discover` failed because this environment does not
    provide a `python` executable.
  - `python3 -m unittest discover` initially failed because the test harness
    passed `MOCK_PORT=0` through strict runtime config validation; fixed the
    harness to bind an ephemeral port directly.
  - `python3 -m unittest discover` passed: 22 tests in 8.698s.
  - Final pre-commit run: `python3 -m unittest discover` passed: 22 tests in
    9.333s.
  - Post-rebase run: `python3 -m unittest discover` passed: 22 tests in
    9.271s.
  - CI/container update run: `python3 -m unittest discover` passed: 22 tests
    in 9.258s.
  - Local Docker build could not be run because this runtime does not provide a
    `docker` executable; GitHub Actions will run the container build and smoke
    test after push.
  - Initial GitHub Actions run failed before jobs started because the workflow
    YAML heredoc health probe was invalid; replaced it with a YAML-safe
    single-line Python health probe.
  - Hetzner manual run on `65.21.192.17`: `python3 -m unittest discover`
    passed 22 tests in 9.160s; `docker build -t openvas-mock-scanner:manual-pr3
    .` succeeded; container `openvas-mock-scanner-manual` started on
    host port `18080`; `/health`, `/capabilities`, create/start/status/results,
    and delete smoke calls returned expected HTTP statuses; Docker health
    reached `healthy`; container runs as `mockscanner`.
- PR URL:
  - PR creation blocked in this environment:
    - GitHub connector returned `403 Resource not accessible by integration`.
    - `gh` CLI is not installed.
    - `GITHUB_TOKEN` and `GH_TOKEN` were not available.
  - Pushed branch compare/new PR URL:
    `https://github.com/clawosiris/openvas-mock-sanner/pull/new/feature/compatibility-mock-scanner`

## 2026-05-25 HTTP Drop-In Compatibility

- Branch: `feature/openvasd-http-compat`
- Mission: make the mock useful as an HTTP openvasd drop-in replacement, without taking on the old OSP Unix socket surface.
- Progress:
  - Verified real Greenbone container wiring uses openvasd HTTP plus `LISTENING=0.0.0.0:80`.
  - Added openvasd-compatible health, metadata, scan lifecycle, status, result range, preferences, and VT endpoints.
  - Added `LISTENING` env alias and non-root port-80 container support.
  - Updated README/container/API docs and unit tests.
  - Local `python3 -m unittest discover` passed: 24 tests in 8.713s.
- Key learnings:
  - gvmd's `gvm-libs/http_scanner` expects `POST /scans` to return a JSON string scan id, then uses `POST /scans/{id}` with `{"action":"start"}` or `{"action":"stop"}`.
  - gvmd's openvasd payload builder includes `scan_id`; honoring it avoids report/scanner id drift.
  - libgvm currently has a path that can emit `?range0-12`; the mock accepts both that and the documented `?range=0-12` spelling.
- Next:
  - Run remote Docker build/smoke validation on Hetzner.
  - Rebase, push branch, open PR.
