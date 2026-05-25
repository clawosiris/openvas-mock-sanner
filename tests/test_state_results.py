import unittest

from openvas_mock_scanner.config import load_config
from openvas_mock_scanner.results import generate_results, threat_for_severity
from openvas_mock_scanner.state import AppState, delete_scan, page_results, start_scan, status_for, stop_scan


class StateAndResultTests(unittest.TestCase):
    def test_lifecycle_transitions(self):
        state = AppState(load_config({}))
        scan = state.create_scan({"target": "example.test"})
        self.assertEqual(scan.status, "created")
        self.assertEqual(start_scan(scan), (204, None))
        self.assertEqual(start_scan(scan)[0], 409)
        self.assertEqual(status_for(scan)["status"], "running")
        self.assertEqual(status_for(scan)["status"], "succeeded")
        self.assertEqual(stop_scan(scan)[0], 409)
        self.assertEqual(delete_scan(scan), (204, None))
        self.assertIsNone(state.get_scan(scan.id))

    def test_stop_active_scan(self):
        state = AppState(load_config({}))
        scan = state.create_scan({})
        start_scan(scan)
        self.assertEqual(stop_scan(scan), (204, None))
        self.assertEqual(status_for(scan)["status"], "stopped")

    def test_generated_results_are_stable_and_complete(self):
        config = load_config({})
        first = generate_results(config, "scan-0001")
        second = generate_results(config, "scan-0001")
        self.assertEqual(first, second)
        self.assertEqual([r["ordinal"] for r in first], list(range(1, 13)))
        self.assertEqual(first[0]["created_at"], "2026-01-01T00:00:10Z")
        required = {
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
        self.assertTrue(required.issubset(first[0]))
        self.assertNotIn("password", str(first).lower())

    def test_threat_mapping(self):
        self.assertEqual(threat_for_severity(9.0), "Critical")
        self.assertEqual(threat_for_severity(7.0), "High")
        self.assertEqual(threat_for_severity(4.0), "Medium")
        self.assertEqual(threat_for_severity(0.1), "Low")
        self.assertEqual(threat_for_severity(0.0), "Log")

    def test_paging(self):
        state = AppState(load_config({"MOCK_RESULT_COUNT": "5"}))
        scan = state.create_scan({})
        self.assertEqual([r["ordinal"] for r in page_results(scan, 0, 2)["results"]], [1, 2])
        self.assertEqual(page_results(scan, 0, 2)["next_offset"], 2)
        self.assertEqual([r["ordinal"] for r in page_results(scan, 2, 2)["results"]], [3, 4])
        self.assertIsNone(page_results(scan, 4, 2)["next_offset"])

    def test_empty_report(self):
        state = AppState(load_config({"MOCK_SCENARIO": "empty-report"}))
        scan = state.create_scan({})
        page = page_results(scan, 0, 100)
        self.assertEqual(page["total"], 0)
        self.assertEqual(page["results"], [])


if __name__ == "__main__":
    unittest.main()
