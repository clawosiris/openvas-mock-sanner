import json
import unittest

from tests.test_http_contract import Service


def collect(env):
    with Service(env) as service:
        data = {
            "capabilities": service.request("GET", "/capabilities")[2],
            "preferences": service.request("GET", "/preferences")[2],
        }
        scan_id = service.request("POST", "/scans", {"target": {"hosts": ["example.test"], "ports": []}, "vts": []})[2]
        service.request("POST", f"/scans/{scan_id}", {"action": "start"})
        statuses = []
        for _ in range(3):
            statuses.append(service.request("GET", f"/scans/{scan_id}/status")[2])
        pages = []
        offset = 0
        while offset is not None:
            page = service.request("GET", f"/scans/{scan_id}/results?offset={offset}&limit=100")[2]
            pages.append(page)
            offset = page.get("next_offset")
        data["statuses"] = statuses
        data["pages"] = pages
        return json.dumps(data, sort_keys=True, separators=(",", ":"))


class DeterminismTests(unittest.TestCase):
    def test_deterministic_scenarios(self):
        for scenario in ["success-basic", "success-large-report", "scanner-failure"]:
            with self.subTest(scenario=scenario):
                env = {"MOCK_SCENARIO": scenario}
                self.assertEqual(collect(env), collect(env))


if __name__ == "__main__":
    unittest.main()
