# Worklog

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
