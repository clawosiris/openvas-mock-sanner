# Container Usage

The container is built to run as a scanner replacement fixture in local,
integration, and CI environments.

## Build

```sh
docker build -t openvas-mock-scanner:local .
```

## Run

```sh
docker run --rm --name openvas-mock-scanner \
  -p 8080:80 \
  -e MOCK_SCENARIO=success-basic \
  openvas-mock-scanner:local
```

The image listens on `0.0.0.0:80` by default using openvasd's
`LISTENING=0.0.0.0:80` convention, runs as the non-root `mockscanner` user,
and exposes `GET /health/alive` as the Docker healthcheck. The image grants
the Python interpreter `CAP_NET_BIND_SERVICE` so the non-root process can bind
to port 80.

For local-only runs that should avoid privileged ports, override the mock bind
settings:

```sh
docker run --rm --name openvas-mock-scanner \
  -p 8080:8080 \
  -e MOCK_HOST=0.0.0.0 \
  -e MOCK_PORT=8080 \
  openvas-mock-scanner:local
```

The container tolerates openvasd compose variables such as `OPENVASD_MODE` and
`GNUPGHOME`; they are not required by the mock but do not prevent startup.

## Published Images

Images are published to:

```text
ghcr.io/clawosiris/openvas-mock-scanner
```

Common tags:

- `latest` from `main`
- `devel` from `devel`
- `nightly` from the scheduled nightly workflow
- `vX.Y.Z`, `X.Y`, and commit SHA tags from release tags

## Replacement Pattern

Point manager integration tests at the mock scanner base URL instead of a real
openvasd URL. The mock is deterministic and process-local; restart the
container between test cases when test isolation requires fresh scan ids and
counters.

Example:

```sh
docker run --rm -p 18080:80 \
  -e MOCK_SCENARIO=success-large-report \
  -e MOCK_SEED=gvmd-compat \
  ghcr.io/clawosiris/openvas-mock-scanner:nightly
```

For a compose replacement of the Greenbone `openvasd` service, keep
`LISTENING=0.0.0.0:80` and replace only the image name.

## Feed-Backed Fixtures

Mount VT metadata and optional target profiles into the container to generate
results from real feed OIDs while keeping the public scanner result payload raw:

```sh
docker run --rm -p 18080:80 \
  -v "$PWD/fixtures:/fixtures:ro" \
  -e MOCK_VT_METADATA_PATH=/fixtures/vt-metadata.json \
  -e MOCK_TARGET_PROFILE=/fixtures/target-profile.json \
  -e MOCK_NOTUS_ADVISORIES_PATH=/fixtures/notus-advisories.json \
  -e MOCK_SCAP_METADATA_PATH=/fixtures/scap-cves.json \
  ghcr.io/clawosiris/openvas-mock-scanner:nightly
```

`MOCK_NOTUS_ADVISORIES_PATH` is useful for package-based local security checks:
installed packages from `MOCK_TARGET_PROFILE` are matched against advisory
fixtures, while `MOCK_SCAP_METADATA_PATH` supplies CVE summaries and CVSS data
for the VT metadata endpoint and downstream enrichment.

Set `MOCK_FEED_STRICT=true` when test startup should fail if a configured feed
or profile file is missing or invalid. With the default `false`, invalid
optional files are skipped and synthetic generation remains available.
`GET /feed/diagnostics` exposes the skipped input diagnostics and loaded feed
fixture counts for debugging container-mounted fixtures.
