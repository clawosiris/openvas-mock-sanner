# Worklog

## 2026-05-29 Issue #9 Feed-Aware Fault Scenarios

- Branch: `issue9-feed-aware-fault-scenarios`
- Mission: finish the remaining issue #9 slice for feed-aware fault scenarios.
- Progress:
  - Created a fresh checkout from current `origin/main`; the older default
    checkout is on divergent benchmark history.
  - Confirmed issue #9 remains open and prior comments identify missing/stale/
    incomplete feed data plus strict/permissive behavior as the remaining
    scope after PR #15.
  - Inspecting existing config, feed loading, result generation, and scenario
    tests before patching.
  - Added `auth-missing`, `dependency-missing`, `port-closed`, `vt-timeout`,
    and `partial-feed-results` as feed-aware runtime scenarios.
  - Added `GET /feed/diagnostics` for permissive-mode feed/profile/Notus/SCAP
    load diagnostics and fixture counts.
  - Added unit and HTTP contract coverage for strict/permissive behavior and
    the new scenarios.
  - Updated README, API/container docs, and feed-backed spec.
- Current state:
  - Local verification passed.
- Verification:
  - `python3 -m unittest discover` passed: 49 tests, 2 skipped.
  - `SCAN_EXAMPLES_PATH=/home/node/.openclaw/workspace-dev-gea/tmp/scan-examples-plan python3 -m unittest discover` passed: 49 tests.
  - `git diff --check` passed.
- Next:
  - Rebase, push, and open PR.

## 2026-05-26 Issue #9 Notus/SCAP Runtime Fixtures

- Branch: `issue9-notus-scap-fixtures`
- Started from `origin/main` at PR #14 merge commit `46b86bb`.
- Goal:
  - Add opt-in runtime fixture inputs for Notus/package advisories and SCAP CVE metadata.
  - Let target package facts influence feed-backed realistic findings.
  - Preserve raw openvasd-shaped public scanner result responses.
  - Cover the behavior in unit/HTTP tests and docs.

### Progress

- Created branch from current `origin/main`.
- Added `MOCK_NOTUS_ADVISORIES_PATH` and `MOCK_SCAP_METADATA_PATH` config.
- Added Notus advisory and SCAP CVE loaders to feed context.
- Normalized target-profile package fixtures and use package facts in
  feed-backed candidate ranking.
- Merge Notus advisories into VT metadata by OID; synthesize VT metadata when
  an advisory has no separate VT metadata entry.
- Preserve raw HTTP result projection; Notus/SCAP details are visible through
  `/vts/{oid}` and through `scan-examples` enrichment after exporting VT
  metadata.
- Updated README, API/container docs, implementation spec, feed-backed spec,
  and test plan.

### Verification

- `python3 -m unittest discover` passed: 41 tests, 2 skipped
  (`scan-examples` optional validation skipped without `SCAN_EXAMPLES_PATH`).
- `SCAN_EXAMPLES_PATH=/home/node/.openclaw/workspace-dev-gea/tmp/scan-examples-plan python3 -m unittest discover` passed: 41 tests.
- `git diff --check` passed.

### Key Learnings

- `scan-examples` extracts CVE IDs from VT metadata references, so synthesized
  Notus VT metadata must expose CVEs both as `cves` and as `{"class":"cve",
  "id":"..."}` references.

## 2026-05-26 Issue #9 Feed-Backed Generation

- Branch: `issue9-feed-backed-generation`
- Mission: implement the first feed-backed realistic generation slice for
  issue #9 while preserving raw openvasd public result payloads.
- Progress:
  - Created a fresh checkout from remote `main` because the older local
    checkout has stale divergent benchmark history.
  - Created branch `issue9-feed-backed-generation` from commit `4397b83`.
  - Scoped the implementation to opt-in VT metadata loading, scan payload OID
    and target extraction, optional target profile matching, deterministic
    feed-backed internal result generation, and raw public result projection.
  - Added `MOCK_VT_METADATA_PATH`, `MOCK_TARGET_PROFILE`, and
    `MOCK_FEED_STRICT` config.
  - Added a tolerant VT metadata and target profile loader.
  - Added feed-backed result generation when usable VT metadata is configured.
  - Added `GET /vts/{oid}` so rich VT metadata is available outside raw
    scanner result payloads.
  - Updated README, API/container docs, implementation spec, and test plan.
- Current state:
  - Local tests pass with 30 tests.
  - `git diff --check` passes.
  - Opened PR `https://github.com/clawosiris/openvas-mock-sanner/pull/13`.
  - PR CI passed Python 3.10/3.11/3.12 and container build/smoke; release
    job skipped as expected for a PR.
- Next:
  - Review and merge PR #13, then decide whether to implement the next issue
    #9 slice: Notus/SCAP fixture inputs or scan-examples enrichment validation.

## 2026-05-26 Issue #9 scan-examples Enrichment Validation

- Branch: `issue9-scan-examples-validation`
- Mission: make the issue #9 scan-examples validation executable instead of
  only documented.
- Progress:
  - Created branch from current `origin/main` after PR #13 was merged.
  - Added a cross-repo test that starts the mock scanner in feed-backed mode,
    collects raw openvasd-shaped `/scans/{id}/results`, and passes those
    results through `scan_examples.enrichment.enrich_results_from_files`.
  - Updated CI to check out `clawosiris/scan-examples` beside the mock scanner
    repo and set `SCAN_EXAMPLES_PATH` so the test uses the real enrichment
    implementation.
- Current state:
  - Edits are in progress and not yet verified.
- Next:
  - Run local unit tests with `SCAN_EXAMPLES_PATH`.
  - Rebase before push, open PR, and verify GitHub CI.

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
