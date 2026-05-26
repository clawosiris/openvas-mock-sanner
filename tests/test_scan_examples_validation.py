import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from tests.test_http_contract import HttpContractTests, Service
from tests.test_feed_backed_results import VT_NOTUS, fixture_paths


VT_HTTP = "1.3.6.1.4.1.25623.1.0.990001"
VT_SSH = "1.3.6.1.4.1.25623.1.0.990002"


def _scan_examples_src() -> Path | None:
    root = os.environ.get("SCAN_EXAMPLES_PATH")
    if not root:
        return None
    src = Path(root) / "src"
    if (src / "scan_examples" / "enrichment.py").is_file():
        return src
    return None


@unittest.skipUnless(
    _scan_examples_src() is not None,
    "set SCAN_EXAMPLES_PATH to a scan-examples checkout to run cross-repo enrichment validation",
)
class ScanExamplesEnrichmentValidationTests(unittest.TestCase):
    def test_feed_backed_raw_results_enrich_with_scan_examples_pipeline(self):
        sys.path.insert(0, str(_scan_examples_src()))
        from scan_examples.enrichment import enrich_results_from_files

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vt_metadata_path = root / "vt-metadata.json"
            target_profile_path = root / "target-profile.json"
            scap_path = root / "scap.json"
            results_path = root / "raw-results.json"

            vt_metadata_path.write_text(json.dumps(_vt_metadata()), encoding="utf-8")
            target_profile_path.write_text(json.dumps(_target_profile()), encoding="utf-8")
            scap_path.write_text(json.dumps(_scap_metadata()), encoding="utf-8")

            with Service(
                {
                    "MOCK_VT_METADATA_PATH": str(vt_metadata_path),
                    "MOCK_TARGET_PROFILE": str(target_profile_path),
                    "MOCK_RESULT_COUNT": "2",
                    "MOCK_SEED": "scan-examples-validation",
                }
            ) as service:
                scan_id = service.request(
                    "POST",
                    "/scans",
                    {
                        "scan_id": "scan-examples-validation",
                        "target": {"hosts": ["192.0.2.10"], "ports": ["T:80,22"]},
                        "vts": [{"oid": VT_HTTP}, {"oid": VT_SSH}],
                    },
                )[2]
                self.assertEqual(scan_id, "scan-examples-validation")
                self.assertEqual(service.request("POST", f"/scans/{scan_id}", {"action": "start"})[0], 204)

                page = service.request("GET", f"/scans/{scan_id}/results?range=0-1")[2]

            raw_results = page["results"]
            self.assertEqual(len(raw_results), 2)
            self.assertEqual({row["oid"] for row in raw_results}, {VT_HTTP, VT_SSH})
            for result in raw_results:
                self.assertEqual(set(result), HttpContractTests.RAW_RESULT_KEYS)
                self.assertTrue(HttpContractTests.ENRICHED_RESULT_KEYS.isdisjoint(result))

            results_path.write_text(
                json.dumps({"scan_id": scan_id, "results": raw_results}),
                encoding="utf-8",
            )
            enriched = enrich_results_from_files(
                results_path=results_path,
                vt_metadata_path=vt_metadata_path,
                scap_path=scap_path,
                engine="python",
            )

        self.assertEqual(len(enriched), 2)
        self.assertTrue(all(row["vt-metadata-status"] == "matched" for row in enriched))
        self.assertEqual({row["feed-metadata-source"] for row in enriched}, {"vt"})
        self.assertEqual(
            {row["vt-metadata"]["name"] for row in enriched},
            {"Apache httpd Path Traversal Vulnerability", "OpenSSH Weak Algorithm Detection"},
        )
        self.assertEqual(
            {cve for row in enriched for cve in row["cve-ids"]},
            {"CVE-2021-41773", "CVE-2026-0002"},
        )
        self.assertTrue(all(row["cve-metadata-status"] == "matched" for row in enriched))

    def test_notus_scap_backed_raw_results_enrich_after_vt_metadata_export(self):
        sys.path.insert(0, str(_scan_examples_src()))
        from scan_examples.enrichment import enrich_results_from_files

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vt_metadata_path = root / "vt-metadata.json"
            scap_path = root / "scap.json"
            results_path = root / "raw-results.json"

            with fixture_paths() as paths:
                with Service(
                    {
                        "MOCK_TARGET_PROFILE": paths["profile"],
                        "MOCK_NOTUS_ADVISORIES_PATH": paths["notus"],
                        "MOCK_SCAP_METADATA_PATH": paths["scap"],
                        "MOCK_RESULT_COUNT": "1",
                    }
                ) as service:
                    vt_metadata = service.request("GET", f"/vts/{VT_NOTUS}")[2]
                    scan_id = service.request(
                        "POST",
                        "/scans",
                        {
                            "scan_id": "notus-scap-validation",
                            "target": {"hosts": ["192.0.2.10"], "ports": ["T:80"]},
                            "vts": [{"oid": VT_NOTUS}],
                        },
                    )[2]
                    self.assertEqual(service.request("POST", f"/scans/{scan_id}", {"action": "start"})[0], 204)
                    raw_results = service.request("GET", f"/scans/{scan_id}/results?range=0-0")[2]["results"]

                scap_path.write_text(Path(paths["scap"]).read_text(encoding="utf-8"), encoding="utf-8")

            self.assertEqual(len(raw_results), 1)
            self.assertEqual(set(raw_results[0]), HttpContractTests.RAW_RESULT_KEYS)
            self.assertTrue(HttpContractTests.ENRICHED_RESULT_KEYS.isdisjoint(raw_results[0]))

            vt_metadata_path.write_text(json.dumps([vt_metadata]), encoding="utf-8")
            results_path.write_text(json.dumps({"scan_id": scan_id, "results": raw_results}), encoding="utf-8")
            enriched = enrich_results_from_files(
                results_path=results_path,
                vt_metadata_path=vt_metadata_path,
                scap_path=scap_path,
                engine="python",
            )

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]["vt-metadata-status"], "matched")
        self.assertEqual(enriched[0]["cve-ids"], ["CVE-2024-5535"])
        self.assertEqual(enriched[0]["cve-metadata-status"], "matched")


def _vt_metadata():
    return [
        {
            "oid": VT_HTTP,
            "name": "Apache httpd Path Traversal Vulnerability",
            "filename": "apache_path_traversal.nasl",
            "family": "Web application abuses",
            "category": "remote_vul",
            "severity": 9.8,
            "references": [{"class": "cve", "id": "CVE-2021-41773"}],
            "tag": {"summary": "Apache httpd 2.4.49 path traversal check."},
        },
        {
            "oid": VT_SSH,
            "name": "OpenSSH Weak Algorithm Detection",
            "filename": "openssh_weak_algorithms.nasl",
            "family": "General",
            "category": "remote_vul",
            "severity": 2.1,
            "references": [{"class": "cve", "id": "CVE-2026-0002"}],
            "tag": {"summary": "SSH service exposes weak algorithms."},
        },
    ]


def _target_profile():
    return {
        "hosts": [
            {
                "host": "192.0.2.10",
                "hostname": "web-01.example.test",
                "services": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "name": "http",
                        "product": "Apache httpd",
                        "version": "2.4.49",
                        "cpe": "cpe:/a:apache:http_server:2.4.49",
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "name": "ssh",
                        "product": "OpenSSH",
                        "version": "8.4",
                        "cpe": "cpe:/a:openbsd:openssh:8.4",
                    },
                ],
            }
        ]
    }


def _scap_metadata():
    return [
        {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "en", "value": "Apache path traversal"}],
        },
        {
            "id": "CVE-2026-0002",
            "descriptions": [{"lang": "en", "value": "OpenSSH weak algorithm"}],
        },
    ]


if __name__ == "__main__":
    unittest.main()
