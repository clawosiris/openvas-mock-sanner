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
    {"id": "port_range", "name": "Port range", "type": "string", "description": "Ports to scan", "default": "T:1-1024", "required": True},
    {"id": "alive_test", "name": "Alive test", "type": "choice", "description": "Host alive detection", "default": "ICMP, TCP-ACK", "values": "ICMP, TCP-SYN, TCP-ACK, ARP, Consider Alive", "required": False},
    {"id": "max_checks", "name": "Maximum checks", "type": "integer", "description": "Maximum parallel checks", "default": "4", "required": False},
]


def make_handler(app_state: AppState) -> type[BaseHTTPRequestHandler]:
    """Create a request handler bound to a specific in-memory app state."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "OpenVASMockScanner/0.1"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_HEAD(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in {"/health", "/scans", "/vts", "/notus"}:
                self._headers(204 if parsed.path == "/scans" else 200)
                return
            self._headers(404)

        def do_GET(self) -> None:
            self._latency()
            parsed = urlparse(self.path)
            parts = _parts(parsed.path)
            if parsed.path == "/health":
                self._json(200, {"status": "ok", "scenario": app_state.config.scenario})
                return
            if parsed.path in {"/health/alive", "/health/ready", "/health/started"}:
                self._json(200, {"status": "ok"})
                return
            if parsed.path == "/capabilities":
                self._json(200, capabilities())
                return
            if parsed.path == "/preferences":
                self._json(200, {"preferences": PREFERENCES})
                return
            if parsed.path == "/scans/preferences":
                self._json(200, _openvasd_preferences())
                return
            if parsed.path == "/vts":
                self._json(200, _vts())
                return
            if parsed.path == "/notus":
                self._json(200, [])
                return
            if len(parts) == 2 and parts[0] == "scans":
                self._scan(parts[1])
                return
            if len(parts) == 3 and parts[0] == "scans" and parts[2] == "status":
                self._scan_status(parts[1])
                return
            if len(parts) == 3 and parts[0] == "scans" and parts[2] == "results":
                self._scan_results(parts[1], parsed.query)
                return
            if len(parts) == 4 and parts[0] == "scans" and parts[2] == "results":
                self._scan_result(parts[1], parts[3])
                return
            self._json(404, error("not_found", "route does not exist"))

        def do_POST(self) -> None:
            self._latency()
            parsed = urlparse(self.path)
            parts = _parts(parsed.path)
            if parsed.path == "/scans":
                self._create_scan()
                return
            if len(parts) == 2 and parts[0] == "scans":
                self._openvasd_scan_action(parts[1])
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
            try:
                scan = app_state.create_scan(payload)
            except ValueError:
                self._json(403, error("scan_id_conflict", "scan id already exists"))
                return
            self._json(201, scan.id)

        def _scan(self, scan_id: str) -> None:
            scan = app_state.get_scan(scan_id)
            if scan is None:
                self._json(404, error("scan_not_found", "scan id does not exist"))
                return
            body = dict(scan.payload)
            body["scan_id"] = scan.id
            self._json(200, body)

        def _openvasd_scan_action(self, scan_id: str) -> None:
            payload = self._read_json()
            if payload is None:
                return
            if not isinstance(payload, dict) or payload.get("action") not in {"start", "stop"}:
                self._json(400, error("invalid_action", "action must be start or stop"))
                return
            self._scan_action(scan_id, str(payload["action"]))

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

        def _scan_results(self, scan_id: str, raw_query: str) -> None:
            scan = app_state.get_scan(scan_id)
            if scan is None:
                self._json(404, error("scan_not_found", "scan id does not exist"))
                return
            request_number = scan.results_request_count + 1
            # Result faults default to the first request so callers can exercise
            # retry logic without also configuring MOCK_FAILURE_AT. Supplying
            # `MOCK_FAILURE_AT=results:N` moves the anomaly to a later page.
            if scan.scenario == "transient-results-error" and not scan.transient_results_failed and _matches_defaultable_failure(app_state.config.failure_at, request_number):
                scan.results_request_count += 1
                scan.transient_results_failed = True
                self._json(503, error("transient_results_error", "deterministic retryable results failure"))
                return
            if scan.scenario == "malformed-results" and _matches_defaultable_failure(app_state.config.failure_at, request_number):
                scan.results_request_count += 1
                self._json(200, {"items": "schema-invalid", "scan_id": scan.id, "results": "schema-invalid"})
                return
            parsed = _parse_paging(raw_query, app_state.config.page_size)
            if isinstance(parsed, dict):
                self._json(400, parsed)
                return
            offset, limit = parsed
            page = page_results(scan, offset, limit)
            page["items"] = [_openvasd_result(row) for row in page["results"]]
            self._json(200, page)

        def _scan_result(self, scan_id: str, result_id: str) -> None:
            scan = app_state.get_scan(scan_id)
            if scan is None:
                self._json(404, error("scan_not_found", "scan id does not exist"))
                return
            for row in scan.results:
                if str(row["ordinal"] - 1) == result_id or str(row["id"]) == result_id:
                    self._json(200, _openvasd_result(row))
                    return
            self._json(404, error("result_not_found", "result id does not exist"))

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

        def _headers(self, status: int, content_length: int = 0) -> None:
            self.send_response(status)
            self.send_header("api-version", "0.1")
            self.send_header("feed-version", "mock")
            self.send_header("authentication", "none")
            if content_length:
                self.send_header("Content-Length", str(content_length))
            self.end_headers()

        def _json(self, status: int, body: object | None) -> None:
            """Write compact deterministic JSON for stable golden comparisons."""

            if body is None or status == HTTPStatus.NO_CONTENT:
                self._headers(status)
                return
            data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("api-version", "0.1")
            self.send_header("feed-version", "mock")
            self.send_header("authentication", "none")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _latency(self) -> None:
            if app_state.config.latency_ms:
                time.sleep(app_state.config.latency_ms / 1000.0)

    return Handler


def capabilities() -> dict[str, object]:
    """Return a small feature document that manager tests can probe."""

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
    """Run the HTTP service until interrupted."""

    config = load_config() if config is None else config
    httpd = ThreadingHTTPServer((config.host, config.port), make_handler(AppState(config)))
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


def _parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part]


def _parse_paging(raw_query: str, default_limit: int) -> tuple[int, int] | dict[str, object]:
    """Normalize offset/limit and page/page_size query forms."""

    query = parse_qs(raw_query)
    try:
        if raw_query.startswith("range") or "range" in query:
            # openvasd uses `range=0-12`. libgvm currently emits `range0-12`
            # in one path, so accept both spellings for manager compatibility.
            range_raw = query.get("range", [raw_query.removeprefix("range")])[0]
            start_raw, sep, end_raw = range_raw.partition("-")
            offset = int(start_raw)
            if sep:
                end = int(end_raw)
                if end < offset:
                    raise ValueError
                return offset, end - offset + 1
            return offset, default_limit
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


def _openvasd_preferences() -> list[dict[str, object]]:
    return [{key: value for key, value in pref.items() if key != "required"} for pref in PREFERENCES]


def _vts() -> list[str]:
    return [f"1.3.6.1.4.1.25623.1.0.{100001 + index}" for index in range(10)]


def _openvasd_result(row: dict[str, object]) -> dict[str, object]:
    message = row.get("description", "")
    return {
        "id": int(row["ordinal"]) - 1,
        "type": row["type"],
        "ip_address": row["ip_address"],
        "hostname": row["hostname"],
        "oid": row["oid"],
        "port": row["port"],
        "protocol": row["protocol"],
        "message": message,
    }


def _should_fail(failure_at: FailureAt | None, point: str, count: int) -> bool:
    return failure_at is not None and failure_at.point == point and (failure_at.count is None or failure_at.count == count)


def _matches_defaultable_failure(failure_at: FailureAt | None, request_number: int) -> bool:
    """Match result fault injection with a scenario-level default."""

    if failure_at is None:
        return request_number == 1
    return failure_at.point == "results" and (failure_at.count is None or failure_at.count == request_number)
