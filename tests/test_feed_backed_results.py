import json
from pathlib import Path
import tempfile
import unittest

from openvas_mock_scanner.config import ConfigError, load_config
from openvas_mock_scanner.results import generate_results
from openvas_mock_scanner.state import AppState


VT_HTTP = "1.3.6.1.4.1.25623.1.0.900001"
VT_SSH = "1.3.6.1.4.1.25623.1.0.900002"
VT_UNUSED = "1.3.6.1.4.1.25623.1.0.900003"


class FeedBackedResultTests(unittest.TestCase):
    def test_feed_metadata_selected_oids_drive_results(self):
        with fixture_paths() as paths:
            config = load_config({"MOCK_VT_METADATA_PATH": paths["metadata"], "MOCK_RESULT_COUNT": "2"})
            payload = {
                "target": {"hosts": ["192.0.2.10"], "ports": ["T:80,22"]},
                "vts": [{"oid": VT_HTTP}, {"oid": VT_SSH}],
            }
            first = generate_results(config, "scan-feed", payload)
            second = generate_results(config, "scan-feed", payload)

        self.assertEqual(first, second)
        self.assertEqual({row["oid"] for row in first}, {VT_HTTP, VT_SSH})
        self.assertTrue(all(row["description"].startswith("Apache httpd") or row["description"].startswith("OpenSSH") for row in first))
        self.assertNotIn(VT_UNUSED, {row["oid"] for row in first})

    def test_target_profile_matches_host_and_service(self):
        with fixture_paths() as paths:
            config = load_config({"MOCK_VT_METADATA_PATH": paths["metadata"], "MOCK_TARGET_PROFILE": paths["profile"], "MOCK_RESULT_COUNT": "1"})
            scan = AppState(config).create_scan(
                {
                    "target": {"hosts": ["192.0.2.10"], "ports": ["T:80"]},
                    "vts": [{"oid": VT_HTTP}, {"oid": VT_SSH}],
                }
            )

        self.assertEqual(scan.results[0]["oid"], VT_HTTP)
        self.assertEqual(scan.results[0]["ip_address"], "192.0.2.10")
        self.assertEqual(scan.results[0]["hostname"], "web-01.example.test")
        self.assertEqual(scan.results[0]["port"], 80)
        self.assertEqual(scan.results[0]["service"], "http")

    def test_missing_selected_feed_oids_fall_back_to_synthetic(self):
        with fixture_paths() as paths:
            config = load_config({"MOCK_VT_METADATA_PATH": paths["metadata"], "MOCK_RESULT_COUNT": "1"})
            results = generate_results(config, "scan-feed", {"vts": [{"oid": "1.2.3.4"}]})

        self.assertEqual(results[0]["oid"], "1.3.6.1.4.1.25623.1.0.100001")
        self.assertEqual(results[0]["family"], "Synthetic Compatibility")

    def test_strict_invalid_metadata_fails_state_startup(self):
        config = load_config({"MOCK_VT_METADATA_PATH": "/does/not/exist.json", "MOCK_FEED_STRICT": "true"})
        with self.assertRaises(ConfigError):
            AppState(config)

    def test_scan_examples_vt_metadata_shape_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            metadata_path = Path(tmp) / "vt-metadata.json"
            metadata_path.write_text(
                json.dumps(
                    [
                        {
                            "oid": "1.2.3",
                            "name": "Example VT",
                            "family": "General",
                            "references": [{"class": "cve", "id": "CVE-2026-0001"}],
                            "tag": {"summary": "Example VT summary"},
                        }
                    ]
                ),
                encoding="utf-8",
            )
            config = load_config({"MOCK_VT_METADATA_PATH": str(metadata_path), "MOCK_RESULT_COUNT": "1"})
            results = generate_results(config, "scan-feed", {"vts": [{"oid": "1.2.3"}]})

        self.assertEqual(results[0]["oid"], "1.2.3")
        self.assertEqual(results[0]["cve"], ["CVE-2026-0001"])
        self.assertIn("Example VT summary", results[0]["description"])


def fixture_paths():
    return FeedFixture()


class FeedFixture:
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        metadata = [
            {
                "oid": VT_HTTP,
                "name": "Apache httpd Path Traversal Vulnerability",
                "family": "Web application abuses",
                "severity": 9.8,
                "cves": ["CVE-2021-41773"],
                "references": [{"type": "cve", "id": "CVE-2021-41773"}],
                "summary": "Apache httpd 2.4.49 path traversal check.",
                "solution": "Upgrade Apache httpd.",
                "qod": 80,
            },
            {
                "oid": VT_SSH,
                "name": "OpenSSH Weak Algorithm Detection",
                "family": "General",
                "severity": 2.1,
                "summary": "SSH service exposes weak algorithms.",
            },
            {
                "oid": VT_UNUSED,
                "name": "PostgreSQL Default Credential Check",
                "family": "Databases",
                "severity": 7.5,
            },
        ]
        profile = {
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
                        }
                    ],
                    "web_apps": [{"path": "/", "name": "demo"}],
                }
            ]
        }
        metadata_path = root / "vt-metadata.json"
        profile_path = root / "target-profile.json"
        metadata_path.write_text(json.dumps({"vts": metadata}), encoding="utf-8")
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        return {"metadata": str(metadata_path), "profile": str(profile_path)}

    def __exit__(self, exc_type, exc, tb):
        self.tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
