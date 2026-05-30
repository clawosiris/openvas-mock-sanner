from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import threading
import unittest

from openvas_mock_scanner.config import load_config
from openvas_mock_scanner.server import make_handler
from openvas_mock_scanner.state import AppState
from tests.test_feed_backed_results import VT_HTTP, VT_NOTUS, fixture_paths


class Service:
    def __init__(self, env=None):
        self.config = load_config(env or {})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(AppState(self.config)))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    @property
    def port(self):
        return self.httpd.server_address[1]

    def request(self, method, path, body=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = None if body is None else json.dumps(body)
        conn.request(method, path, body=payload, headers={"Content-Type": "application/json"} if payload else {})
        response = conn.getresponse()
        raw = response.read()
        headers = dict(response.getheaders())
        conn.close()
        parsed = json.loads(raw) if raw else None
        return response.status, headers, parsed

    def raw_request(self, method, path, raw):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=raw, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, json.loads(data)


class HttpContractTests(unittest.TestCase):
    RAW_RESULT_KEYS = {
        "id",
        "type",
        "ip_address",
        "hostname",
        "oid",
        "port",
        "protocol",
        "message",
    }
    ENRICHED_RESULT_KEYS = {
        "cve",
        "cpe",
        "cvss_base",
        "cvss_vector",
        "description",
        "detection",
        "family",
        "nvt_name",
        "qod",
        "references",
        "severity",
        "solution",
        "solution_type",
        "tags",
        "threat",
    }

    def test_common_capabilities_preferences_and_lifecycle(self):
        with Service() as service:
            status, headers, body = service.request("GET", "/health")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(body["status"], "ok")
            self.assertEqual(service.request("GET", "/health/alive")[0], 200)
            self.assertEqual(service.request("HEAD", "/scans")[0], 204)
            self.assertEqual(service.request("HEAD", "/feed/diagnostics")[0], 200)

            self.assertEqual(service.request("GET", "/missing")[0], 404)
            status, body = service.raw_request("POST", "/scans", "{")
            self.assertEqual(status, 400)
            self.assertIn("code", body["error"])

            caps1 = service.request("GET", "/capabilities")[2]
            caps2 = service.request("GET", "/capabilities")[2]
            self.assertEqual(caps1, caps2)
            self.assertEqual(caps1["api_version"], "compat-1")
            self.assertTrue(caps1["features"]["result_paging"])

            prefs = service.request("GET", "/preferences")[2]["preferences"]
            self.assertTrue(all({"id", "name", "type", "default", "required"}.issubset(p) for p in prefs))
            openvasd_prefs = service.request("GET", "/scans/preferences")[2]
            self.assertIsInstance(openvasd_prefs, list)
            self.assertTrue(all({"id", "name", "type", "default"}.issubset(p) for p in openvasd_prefs))
            self.assertGreater(len(service.request("GET", "/vts")[2]), 0)

            status, _, created = service.request("POST", "/scans", {"scan_id": "report-uuid", "target": {"hosts": ["example.test"], "ports": []}, "vts": []})
            self.assertEqual(status, 201)
            self.assertEqual(created, "report-uuid")
            scan_id = created
            self.assertEqual(service.request("GET", f"/scans/{scan_id}")[2]["scan_id"], scan_id)
            self.assertEqual(service.request("POST", f"/scans/{scan_id}", {"action": "start"})[0], 204)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[0], 200)
            status, _, results = service.request("GET", f"/scans/{scan_id}/results?range=0-1")
            self.assertEqual(status, 200)
            self.assertIn("items", results)
            self.assertEqual(results["items"], results["results"])
            self.assertEqual(set(results["items"][0]), self.RAW_RESULT_KEYS)
            self.assertTrue(self.ENRICHED_RESULT_KEYS.isdisjoint(results["items"][0]))
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/results/0")[0], 200)
            self.assertEqual(service.request("DELETE", f"/scans/{scan_id}")[0], 204)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[0], 404)
            self.assertEqual(service.request("POST", "/scans/nope/start")[0], 404)

    def test_feed_diagnostics_endpoint_reports_permissive_skips(self):
        with Service({"MOCK_VT_METADATA_PATH": "/does/not/exist.json"}) as service:
            status, _, body = service.request("GET", "/feed/diagnostics")

        self.assertEqual(status, 200)
        self.assertFalse(body["feed_strict"])
        self.assertEqual(body["metadata_count"], 0)
        self.assertTrue(any("skipped VT metadata" in item for item in body["diagnostics"]))

    def test_openvasd_results_expose_only_raw_scanner_fields(self):
        with Service() as service:
            scan_id = service.request("POST", "/scans", {"target": {"hosts": ["example.test"]}})[2]
            service.request("POST", f"/scans/{scan_id}", {"action": "start"})

            status, _, page = service.request("GET", f"/scans/{scan_id}/results?range=0-0")
            self.assertEqual(status, 200)
            self.assertEqual(len(page["items"]), 1)
            self.assertEqual(page["items"], page["results"])
            result = page["items"][0]
            self.assertEqual(set(result), self.RAW_RESULT_KEYS)
            self.assertTrue(self.ENRICHED_RESULT_KEYS.isdisjoint(result))

            status, _, single = service.request("GET", f"/scans/{scan_id}/results/{result['id']}")
            self.assertEqual(status, 200)
            self.assertEqual(single, result)

    def test_feed_backed_http_results_stay_raw_and_vts_expose_metadata(self):
        with fixture_paths() as paths:
            with Service({"MOCK_VT_METADATA_PATH": paths["metadata"], "MOCK_TARGET_PROFILE": paths["profile"], "MOCK_RESULT_COUNT": "1"}) as service:
                self.assertIn(VT_HTTP, service.request("GET", "/vts")[2])
                vt = service.request("GET", f"/vts/{VT_HTTP}")[2]
                self.assertEqual(vt["name"], "Apache httpd Path Traversal Vulnerability")
                self.assertEqual(vt["cves"], ["CVE-2021-41773"])

                scan_id = service.request(
                    "POST",
                    "/scans",
                    {
                        "target": {"hosts": ["192.0.2.10"], "ports": ["T:80"]},
                        "vts": [{"oid": VT_HTTP}],
                    },
                )[2]
                service.request("POST", f"/scans/{scan_id}", {"action": "start"})
                page = service.request("GET", f"/scans/{scan_id}/results?range=0-0")[2]

        result = page["items"][0]
        self.assertEqual(result["oid"], VT_HTTP)
        self.assertEqual(set(result), self.RAW_RESULT_KEYS)
        self.assertTrue(self.ENRICHED_RESULT_KEYS.isdisjoint(result))

    def test_notus_package_backed_http_results_stay_raw(self):
        with fixture_paths() as paths:
            with Service(
                {
                    "MOCK_TARGET_PROFILE": paths["profile"],
                    "MOCK_NOTUS_ADVISORIES_PATH": paths["notus"],
                    "MOCK_SCAP_METADATA_PATH": paths["scap"],
                    "MOCK_RESULT_COUNT": "1",
                }
            ) as service:
                vt = service.request("GET", f"/vts/{VT_NOTUS}")[2]
                self.assertEqual(vt["family"], "Linux Local Security Checks")
                self.assertEqual(vt["cves"], ["CVE-2024-5535"])

                scan_id = service.request(
                    "POST",
                    "/scans",
                    {
                        "target": {"hosts": ["192.0.2.10"], "ports": ["T:80"]},
                        "vts": [{"oid": VT_NOTUS}],
                    },
                )[2]
                service.request("POST", f"/scans/{scan_id}", {"action": "start"})
                page = service.request("GET", f"/scans/{scan_id}/results?range=0-0")[2]

        result = page["items"][0]
        self.assertEqual(result["oid"], VT_NOTUS)
        self.assertEqual(set(result), self.RAW_RESULT_KEYS)
        self.assertTrue(self.ENRICHED_RESULT_KEYS.isdisjoint(result))

    def test_invalid_paging(self):
        with Service() as service:
            scan_id = service.request("POST", "/scans", {})[2]
            status, _, body = service.request("GET", f"/scans/{scan_id}/results?offset=-1&limit=1")
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_paging")


if __name__ == "__main__":
    unittest.main()
