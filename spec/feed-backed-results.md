# Feed-Backed Result Generation Spec

## Purpose

Implement issue #9: add an opt-in result generation mode that uses real
Greenbone feed vulnerability test metadata while preserving the mock scanner's
deterministic CI fixture behavior.

This is not a NASL executor, scanner engine, or full dependency resolver. The
goal is compatibility-test realism: gvmd and gvmd-ng should receive scanner
results whose OIDs and messages line up with realistic feed-backed VT metadata,
while the public scanner result payload stays as thin as real openvasd output.
Names, families, CVEs, severities, references, and selected tags should live in
VT metadata or downstream enrichment keyed by OID.

## Non-Goals

- executing NASL scripts
- reproducing OpenVAS dependency resolution exactly
- treating feed metadata as evidence that a target is vulnerable
- adding persistent storage
- replacing explicit runtime fault scenarios with feed metadata
- making synthetic mode depend on feed files

## Runtime Configuration

Add these optional environment variables:

- `MOCK_VT_METADATA_PATH`
  - path to a `vt-metadata.json` file
  - when unset, current synthetic result generation remains the default
- `MOCK_TARGET_PROFILE`
  - path to a target profile JSON fixture
  - optional in phase 1; recommended for realistic matching
- `MOCK_NOTUS_PATH`
  - optional advisory/package enrichment input
  - may be ignored until a later phase if no local fixture format is available
- `MOCK_SCAP_PATH`
  - optional CVE/CPE enrichment input
  - may be ignored until a later phase if no local fixture format is available
- `MOCK_FEED_STRICT`
  - default: `false`
  - when `true`, startup fails if configured feed/profile paths are unreadable
    or invalid
  - when `false`, invalid optional files are reported in diagnostics and the
    affected enrichment layer is skipped

Existing variables continue to apply:

- `MOCK_SCENARIO`
- `MOCK_RESULT_COUNT`
- `MOCK_HOST_COUNT`
- `MOCK_SEED`
- `MOCK_CLOCK_START`
- `MOCK_PAGE_SIZE`

Determinism key:

```text
MOCK_SEED
scan_id
scan payload
scenario
feed metadata content
target profile content
clock start
result count / host count overrides
```

The same determinism key must produce stable result ordering and stable JSON
values.

## Feed Metadata Input

The first supported feed input is the `vt-metadata.json` shape already used by
the `scan-examples` enrichment flow.

The loader must build an OID-indexed structure. Required usable fields are:

- OID
- VT name
- family

Optional fields, when present, should enrich generated VT metadata and internal
fixture selection:

- severity / CVSS base score
- CVSS vector
- CVEs
- CPEs
- references
- tags
- summary
- insight
- affected
- impact
- detection method
- solution
- solution type
- QoD type/value
- VT creation/modification timestamps

The implementation must tolerate missing optional fields. Missing required
fields make that VT unusable for feed-backed generation.

## Scan Payload Extraction

On `POST /scans`, retain the raw payload as today, and additionally derive a
normalized scan intent object from it.

The extractor should support the openvasd-style fields already accepted by the
mock:

- `target.hosts`
- excluded hosts
- port list / port range information
- credentials, including whether usable auth exists
- alive-test fields
- `vts[].oid`
- `vts[].parameters`
- `scan_preferences`

The extractor must be defensive: malformed or unknown fields should not crash
the server unless the existing HTTP contract already treats the request as
invalid.

If the payload contains selected VT OIDs, candidate feed VTs are restricted to
that selected set. If it does not, candidate feed VTs may come from all loaded
metadata.

## Target Profile Fixture

`MOCK_TARGET_PROFILE` points to a JSON document that describes target reality.
The schema is intentionally small and fixture-oriented.

Required top-level shape:

```json
{
  "hosts": [
    {
      "host": "192.0.2.10",
      "hostname": "web-01.example.test",
      "os": {
        "name": "Debian GNU/Linux",
        "version": "11",
        "cpe": "cpe:/o:debian:debian_linux:11"
      },
      "services": [
        {
          "port": 80,
          "protocol": "tcp",
          "name": "http",
          "product": "Apache httpd",
          "version": "2.4.49",
          "cpe": "cpe:/a:apache:http_server:2.4.49"
        }
      ],
      "packages": [
        {
          "name": "openssl",
          "version": "1.1.1n",
          "cpe": "cpe:/a:openssl:openssl:1.1.1n"
        }
      ],
      "web_apps": [
        {
          "path": "/",
          "name": "example-app",
          "version": "1.0.0"
        }
      ],
      "auth": {
        "ssh": "success",
        "smb": "missing"
      }
    }
  ]
}
```

Host entries may omit optional sections, but each host must provide at least
`host`. Services must provide `port`, `protocol`, and `name`.

If no target profile is configured, feed-backed mode still works, but matching
falls back to scan payload ports, VT families, and deterministic ranking.

## Candidate Ranking

Candidate selection is a deterministic scoring problem, not a vulnerability
truth engine.

Inputs:

- selected OIDs from the scan payload
- loaded feed metadata
- target profile hosts/services/packages
- scan ports
- credentials/auth capability
- scenario
- `MOCK_RESULT_COUNT`
- `MOCK_SEED`

Hard filters:

- OIDs selected by the scan config, when selection exists
- OIDs present in loaded feed metadata
- target hosts not excluded by the scan config

Soft ranking signals:

- VT family matches target service class
- VT name/tags/references mention service product, package, CPE, or CVE
- VT appears Notus/package-oriented and target package inventory exists
- VT appears web-oriented and target profile has HTTP services/web apps
- VT appears credentialed/local and matching auth is available
- VT QoD/severity fields are present
- scan ports include the service port

Tie-breaking must be deterministic. Use a stable hash over seed, scan id, OID,
host, and service rather than process iteration order.

The generator must include a mix of result types when possible:

- alarm findings for non-zero severities
- log/info findings for discovery and informational VTs
- host/service observations if the selected feed set does not contain enough
  alarms

## Result Mapping

Feed-backed mode must not enrich the public `/scans/{id}/results` scanner
payload with feed metadata. The scanner endpoint should remain openvasd-shaped
raw result data, with feed-backed metadata used to choose realistic OIDs and to
populate VT metadata exposed outside the result payload.

Public scanner result field mapping:

- `oid` -> feed OID
- `message` -> deterministic scanner finding text derived from feed/profile
  context
- `type` -> openvasd result type selected from severity/result intent
- `ip_address`, `hostname`, `port`, `protocol` -> deterministic target profile
  assignment
- `id` -> deterministic zero-based scanner result id

VT metadata mapping, outside `/scans/{id}/results`:

- VT name -> feed VT name
- family -> feed family
- severity -> feed severity or deterministic fallback
- threat -> existing severity bucket mapping
- QoD -> feed QoD value or deterministic fallback
- description/detection/solution/solution type -> feed summary, impact,
  detection method, and solution fields with deterministic fallbacks
- CVEs/CPEs/CVSS/references/tags -> feed/profile metadata keyed by OID

Generated result IDs, host assignment, and ordering must remain deterministic.

## Scenarios

Existing scenarios keep their current behavior in synthetic and feed-backed
modes:

- `success-basic`
- `success-large-report`
- `empty-report`
- `delayed-findings`
- `stop-running`
- `scanner-failure`
- `malformed-results`
- `transient-results-error`
- `delete-refused`
- `duplicate-result-page`

Add feed-aware scenarios only after baseline feed-backed success is stable:

- `auth-missing`
  - credentialed/local VTs are deprioritized or reported as log findings
- `dependency-missing`
  - dependent-looking VTs are omitted or converted into logs
- `port-closed`
  - VTs requiring a closed service are omitted or logged
- `vt-timeout`
  - selected VTs are partially omitted with deterministic error/log output
- `partial-feed-results`
  - only a deterministic subset of selected OIDs produce findings

Runtime scanner failures remain scenario behavior. They must not be inferred
solely from feed metadata.

## Validation Path

The primary validation loop is:

1. Produce or obtain a scan config via `scannerctl scan-config` in the
   `scan-examples` workflow.
2. Submit that config to the mock.
3. Retrieve generated results.
4. Feed those results back through `scan-examples` enrichment.
5. Assert that most generated findings have `vt-metadata-status: matched`.

This validation may start as an integration script outside normal unit tests if
the feed fixture is too large for CI. Unit tests should use small committed
fixtures.

## Test Requirements

Unit tests:

- synthetic mode still works with no feed env vars
- valid `MOCK_VT_METADATA_PATH` loads a small fixture
- invalid feed path behavior respects `MOCK_FEED_STRICT`
- selected scan OIDs intersect feed metadata
- selected scan OIDs missing from feed metadata fall back deterministically
- no selected OIDs uses all loaded feed metadata
- target profile service/port matching affects ranking
- target profile auth/package/web fields affect ranking where implemented
- fixed `MOCK_SEED` produces stable feed-backed output
- changing `MOCK_SEED` changes deterministic tie-breaking
- existing scenarios keep their expected HTTP behavior

Integration tests, where practical:

- run a small `scan-examples` converted config through the mock
- verify enrichment marks generated OIDs as matched
- verify severity/family/result-type counts remain stable

## Implementation Plan

### Phase 1: Loader and Feed-Backed Baseline

- extend `Config` with feed/profile path settings
- add a feed metadata loader module
- add small test fixtures under `tests/fixtures/`
- add a result generator path selected when feed metadata is configured
- preserve existing synthetic generator as the default

### Phase 2: Scan Intent Extraction

- normalize selected OIDs, target hosts, excluded hosts, ports, credentials,
  VT parameters, and preferences from `POST /scans`
- store normalized intent on the scan record
- restrict feed candidates by selected OIDs when present

### Phase 3: Target Profile Matching

- add the target profile parser
- add deterministic candidate scoring
- assign findings to profile hosts/services/packages
- keep graceful fallback behavior for partial profiles

### Phase 4: Feed-Aware Scenarios and Validation

- add feed-aware scenarios
- add small integration validation against `scan-examples` enrichment
- document fixture format and operational usage

## Acceptance Criteria

- Existing synthetic mode remains the default.
- Feed-backed mode is opt-in.
- Existing HTTP consumers continue to receive valid result payloads.
- Existing tests continue to pass.
- Feed-backed scanner output uses real feed OIDs and realistic messages while
  exposing names, families, CVEs, references, severities, and tags through VT
  metadata or downstream enrichment keyed by OID.
- Result generation is deterministic for the same scan payload, feed metadata,
  target profile, scenario, clock, counts, and seed.
- Missing optional feed/profile fields degrade gracefully.
- Strict mode fails fast on invalid configured files.
- Non-strict mode records diagnostics and falls back where possible.
- Documentation explains how to run synthetic mode, feed-backed mode, and the
  small fixture validation path.

## Open Questions

- Which exact `vt-metadata.json` schema variant should be treated as canonical:
  the current `scan-examples` output, the feed container path, or both?
- Should large real feed fixtures remain external to the repository, with only
  minimized fixtures committed for tests?
- Should diagnostics be exposed through `/capabilities`, `/health`, or only
  logs?
- Should feed-backed mode cap result count by selected OID count, or may it
  reuse a VT across multiple hosts/services to satisfy `MOCK_RESULT_COUNT`?
