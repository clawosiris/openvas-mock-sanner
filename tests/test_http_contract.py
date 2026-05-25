from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import threading
import unittest

from openvas_mock_scanner.config import load_config
from openvas_mock_scanner.server import make_handler
from openvas_mock_scanner.state import AppState


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
    def test_common_capabilities_preferences_and_lifecycle(self):
        with Service() as service:
            status, headers, body = service.request("GET", "/health")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(body["status"], "ok")

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

            status, _, created = service.request("POST", "/scans", {"target": "example.test"})
            self.assertEqual(status, 201)
            self.assertRegex(created["id"], r"^scan-[0-9]{4}$")
            scan_id = created["id"]
            self.assertEqual(service.request("POST", f"/scans/{scan_id}/start")[0], 204)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[0], 200)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/results?offset=0&limit=2")[0], 200)
            self.assertEqual(service.request("DELETE", f"/scans/{scan_id}")[0], 204)
            self.assertEqual(service.request("GET", f"/scans/{scan_id}/status")[0], 404)
            self.assertEqual(service.request("POST", "/scans/nope/start")[0], 404)

    def test_invalid_paging(self):
        with Service() as service:
            scan_id = service.request("POST", "/scans", {})[2]["id"]
            status, _, body = service.request("GET", f"/scans/{scan_id}/results?offset=-1&limit=1")
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_paging")


if __name__ == "__main__":
    unittest.main()
