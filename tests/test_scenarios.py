import unittest

from tests.test_http_contract import Service


REQUIRED_FIELDS = {
    "id",
    "ordinal",
    "type",
    "ip_address",
    "hostname",
    "port",
    "protocol",
    "service",
    "oid",
    "nvt_name",
    "family",
    "severity",
    "threat",
    "qod",
    "description",
    "detection",
    "solution",
    "solution_type",
    "created_at",
    "updated_at",
}


class ScenarioTests(unittest.TestCase):
    def create_started(self, service):
        scan_id = service.request("POST", "/scans", {"target": "example.test"})[2]["id"]
        self.assertEqual(service.request("POST", f"/scans/{scan_id}/start")[0], 204)
        return scan_id

    def test_success_basic(self):
        with Service({"MOCK_SCENARIO": "success-basic"}) as service:
            scan_id = self.create_started(service)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[2]["status"], "running")
            terminal = service.request("GET", f"/scans/{scan_id}/status")[2]
            self.assertEqual(terminal["status"], "succeeded")
            self.assertEqual(terminal["progress"], 100)
            results = service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=100")[2]
            self.assertEqual(results["total"], 12)
            self.assertTrue(REQUIRED_FIELDS.issubset(results["results"][0]))
            self.assertEqual(service.request("DELETE", f"/scans/{scan_id}")[0], 204)

    def test_success_large_report(self):
        with Service({"MOCK_SCENARIO": "success-large-report"}) as service:
            scan_id = self.create_started(service)
            ids = []
            offset = 0
            requests = 0
            while offset is not None:
                page = service.request("GET", f"/scans/{scan_id}/results?offset={offset}&limit=100")[2]
                ids.extend(row["id"] for row in page["results"])
                offset = page["next_offset"]
                requests += 1
            self.assertEqual(page["total"], 250)
            self.assertGreaterEqual(requests, 3)
            self.assertEqual(len(ids), 250)
            self.assertEqual(len(set(ids)), 250)

    def test_empty_report(self):
        with Service({"MOCK_SCENARIO": "empty-report"}) as service:
            scan_id = self.create_started(service)
            service.request("GET", f"/scans/{scan_id}/status")
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[2]["status"], "succeeded")
            page = service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=100")[2]
            self.assertEqual(page["total"], 0)
            self.assertEqual(page["results"], [])

    def test_delayed_findings(self):
        with Service({"MOCK_SCENARIO": "delayed-findings"}) as service:
            scan_id = self.create_started(service)
            early = service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=100")[2]
            self.assertEqual(early["total"], 0)
            later = service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=100")[2]
            self.assertEqual(later["total"], 12)
            for _ in range(3):
                final = service.request("GET", f"/scans/{scan_id}/status")[2]
            self.assertEqual(final["status"], "succeeded")

    def test_stop_running(self):
        with Service({"MOCK_SCENARIO": "stop-running"}) as service:
            scan_id = self.create_started(service)
            self.assertEqual(service.request("POST", f"/scans/{scan_id}/stop")[0], 204)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[2]["status"], "stopped")
            self.assertEqual(service.request("DELETE", f"/scans/{scan_id}")[0], 204)

    def test_scanner_failure(self):
        with Service({"MOCK_SCENARIO": "scanner-failure"}) as service:
            scan_id = self.create_started(service)
            service.request("GET", f"/scans/{scan_id}/status")
            failed = service.request("GET", f"/scans/{scan_id}/status")[2]
            again = service.request("GET", f"/scans/{scan_id}/status")[2]
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(again["status"], "failed")
            self.assertEqual(failed["scanner_error"]["code"], "scanner_fixture_failure")

    def test_malformed_results(self):
        with Service({"MOCK_SCENARIO": "malformed-results", "MOCK_FAILURE_AT": "results:2"}) as service:
            scan_id = self.create_started(service)
            self.assertIsInstance(service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=2")[2]["results"], list)
            invalid = service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=2")[2]
            self.assertEqual(invalid["results"], "schema-invalid")

    def test_transient_results_error(self):
        with Service({"MOCK_SCENARIO": "transient-results-error", "MOCK_FAILURE_AT": "results:1"}) as service:
            scan_id = self.create_started(service)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=2")[0], 503)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=2")[0], 200)

    def test_delete_refused(self):
        with Service({"MOCK_SCENARIO": "delete-refused"}) as service:
            scan_id = self.create_started(service)
            status, _, body = service.request("DELETE", f"/scans/{scan_id}")
            self.assertEqual(status, 409)
            self.assertEqual(body["error"]["code"], "delete_refused")
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[0], 200)
            service.request("GET", f"/scans/{scan_id}/status")
            service.request("GET", f"/scans/{scan_id}/status")
            self.assertEqual(service.request("DELETE", f"/scans/{scan_id}")[0], 204)

    def test_duplicate_result_page(self):
        with Service({"MOCK_SCENARIO": "duplicate-result-page", "MOCK_RESULT_COUNT": "6"}) as service:
            scan_id = self.create_started(service)
            first = service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=2")[2]
            duplicate = service.request("GET", f"/scans/{scan_id}/results?offset=2&limit=2")[2]
            resumed = service.request("GET", f"/scans/{scan_id}/results?offset=4&limit=2")[2]
            self.assertEqual([r["id"] for r in first["results"]], [r["id"] for r in duplicate["results"]])
            self.assertEqual([r["ordinal"] for r in resumed["results"]], [5, 6])


if __name__ == "__main__":
    unittest.main()
