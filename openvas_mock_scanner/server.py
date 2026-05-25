"""HTTP JSON service for the compatibility mock scanner."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import time
from urllib.parse import parse_qs, urlparse

from .config import Config, FailureAt, load_config
from .state import AppState, delete_scan, error, page_results, start_scan, status_for, stop_scan


PREFERENCES = [
    {"id": "port_range", "name": "Port range", "type": "string", "default": "T:1-1024", "required": True},
    {"id": "alive_test", "name": "Alive test", "type": "choice", "default": "ICMP, TCP-ACK", "required": False},
    {"id": "max_checks", "name": "Maximum checks", "type": "integer", "default": "4", "required": False},
]


def make_handler(app_state: AppState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "OpenVASMockScanner/0.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self._latency()
            parsed = urlparse(self.path)
            parts = _parts(parsed.path)
            if parsed.path == "/health":
                self._json(200, {"status": "ok", "scenario": app_state.config.scenario})
                return
            if parsed.path == "/capabilities":
                self._json(200, capabilities())
                return
            if parsed.path == "/preferences":
                self._json(200, {"preferences": PREFERENCES})
                return
            if len(parts) == 3 and parts[0] == "scans" and parts[2] == "status":
                self._scan_status(parts[1])
                return
            if len(parts) == 3 and parts[0] == "scans" and parts[2] == "results":
                self._scan_results(parts[1], parse_qs(parsed.query))
                return
            self._json(404, error("not_found", "route does not exist"))

        def do_POST(self) -> None:
            self._latency()
            parsed = urlparse(self.path)
            parts = _parts(parsed.path)
            if parsed.path == "/scans":
                self._create_scan()
                return
            if len(parts) == 3 and parts[0] == "scans" and parts[2] == "start":
                self._scan_action(parts[1], "start")
                return
            if len(parts) == 3 and parts[0] == "scans" and parts[2] == "stop":
                self._scan_action(parts[1], "stop")
                return
            self._json(404, error("not_found", "route does not exist"))

        def do_DELETE(self) -> None:
            self._latency()
            parsed = urlparse(self.path)
            parts = _parts(parsed.path)
            if len(parts) == 2 and parts[0] == "scans":
                self._delete_scan(parts[1])
                return
            self._json(404, error("not_found", "route does not exist"))

        def _create_scan(self) -> None:
            if _should_fail(app_state.config.failure_at, "create", 1):
                self._json(503, error("injected_create_failure", "configured create failure"))
                return
            payload = self._read_json()
            if payload is None:
                return
            if not isinstance(payload, dict):
                self._json(400, error("invalid_request", "scan create payload must be a JSON object"))
                return
            scan = app_state.create_scan(payload)
            self._json(201, {"id": scan.id})

        def _scan_action(self, scan_id: str, action: str) -> None:
            scan = app_state.get_scan(scan_id)
            if scan is None:
                self._json(404, error("scan_not_found", "scan id does not exist"))
                return
            if _should_fail(app_state.config.failure_at, action, scan.start_count + 1 if action == "start" else scan.stop_count + 1):
                self._json(503, error(f"injected_{action}_failure", f"configured {action} failure"))
                return
            status, body = start_scan(scan) if action == "start" else stop_scan(scan)
            self._json(status, body)

        def _scan_status(self, scan_id: str) -> None:
            scan = app_state.get_scan(scan_id)
            if scan is None:
                self._json(404, error("scan_not_found", "scan id does not exist"))
                return
            if _should_fail(app_state.config.failure_at, "status", scan.status_poll_count + 1):
                self._json(503, error("injected_status_failure", "configured status failure"))
                return
            self._json(200, status_for(scan))

        def _scan_results(self, scan_id: str, query: dict[str, list[str]]) -> None:
            scan = app_state.get_scan(scan_id)
            if scan is None:
                self._json(404, error("scan_not_found", "scan id does not exist"))
                return
            request_number = scan.results_request_count + 1
            if scan.scenario == "transient-results-error" and not scan.transient_results_failed and _matches_defaultable_failure(app_state.config.failure_at, request_number):
                scan.results_request_count += 1
                scan.transient_results_failed = True
                self._json(503, error("transient_results_error", "deterministic retryable results failure"))
                return
            if scan.scenario == "malformed-results" and _matches_defaultable_failure(app_state.config.failure_at, request_number):
                scan.results_request_count += 1
                self._json(200, {"scan_id": scan.id, "results": "schema-invalid"})
                return
            parsed = _parse_paging(query, app_state.config.page_size)
            if isinstance(parsed, dict):
                self._json(400, parsed)
                return
            offset, limit = parsed
            self._json(200, page_results(scan, offset, limit))

        def _delete_scan(self, scan_id: str) -> None:
            scan = app_state.get_scan(scan_id)
            if scan is None:
                self._json(404, error("scan_not_found", "scan id does not exist"))
                return
            if _should_fail(app_state.config.failure_at, "delete", scan.delete_count + 1):
                self._json(503, error("injected_delete_failure", "configured delete failure"))
                return
            status, body = delete_scan(scan)
            self._json(status, body)

        def _read_json(self) -> object | None:
            length = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(length) if length else b"{}"
            try:
                return json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(400, error("invalid_json", "request body is not valid JSON"))
                return None

        def _json(self, status: int, body: dict[str, object] | None) -> None:
            self.send_response(status)
            if body is None or status == HTTPStatus.NO_CONTENT:
                self.end_headers()
                return
            data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _latency(self) -> None:
            if app_state.config.latency_ms:
                time.sleep(app_state.config.latency_ms / 1000.0)

    return Handler


def capabilities() -> dict[str, object]:
    return {
        "api_version": "compat-1",
        "scanner_name": "openvas-mock-sanner",
        "features": {
            "start": True,
            "stop": True,
            "delete": True,
            "result_paging": True,
            "preferences": True,
        },
    }


def serve(config: Config | None = None) -> None:
    config = load_config() if config is None else config
    httpd = ThreadingHTTPServer((config.host, config.port), make_handler(AppState(config)))
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


def _parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part]


def _parse_paging(query: dict[str, list[str]], default_limit: int) -> tuple[int, int] | dict[str, object]:
    try:
        if "page" in query or "page_size" in query:
            page = int(query.get("page", ["1"])[0])
            page_size = int(query.get("page_size", [str(default_limit)])[0])
            if page < 1 or page_size < 1:
                raise ValueError
            return (page - 1) * page_size, page_size
        offset = int(query.get("offset", ["0"])[0])
        limit = int(query.get("limit", [str(default_limit)])[0])
        if offset < 0 or limit < 1:
            raise ValueError
    except ValueError:
        return error("invalid_paging", "offset/page must be non-negative and limit/page_size must be positive")
    return offset, limit


def _should_fail(failure_at: FailureAt | None, point: str, count: int) -> bool:
    return failure_at is not None and failure_at.point == point and (failure_at.count is None or failure_at.count == count)


def _matches_defaultable_failure(failure_at: FailureAt | None, request_number: int) -> bool:
    if failure_at is None:
        return request_number == 1
    return failure_at.point == "results" and (failure_at.count is None or failure_at.count == request_number)
