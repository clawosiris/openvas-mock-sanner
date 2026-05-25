"""In-memory scan lifecycle model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .results import generate_results


TERMINAL_STATUSES = {"succeeded", "stopped", "failed", "error"}
ACTIVE_STATUSES = {"created", "queued", "stored", "requested", "running"}


@dataclass
class Scan:
    """Mutable lifecycle record for one synthetic scanner task.

    The mock keeps all state in memory because gvmd compatibility tests need
    deterministic scanner behavior, not scanner durability. The counters are
    part of that contract: they drive scenario transitions and one-shot faults.
    """

    id: str
    payload: dict[str, Any]
    scenario: str
    status: str = "created"
    status_poll_count: int = 0
    start_count: int = 0
    stop_count: int = 0
    delete_count: int = 0
    deleted: bool = False
    results: list[dict[str, object]] = field(default_factory=list)
    results_request_count: int = 0
    transient_results_failed: bool = False
    duplicate_page_sent: bool = False


class AppState:
    """Process-local registry for scans created during a test run."""

    def __init__(self, config: Config):
        self.config = config
        self._next_scan = 1
        self.scans: dict[str, Scan] = {}

    def create_scan(self, payload: dict[str, Any]) -> Scan:
        scan_id = f"scan-{self._next_scan:04d}"
        self._next_scan += 1
        scan = Scan(
            id=scan_id,
            payload=payload,
            scenario=self.config.scenario,
            results=generate_results(self.config, scan_id),
        )
        self.scans[scan_id] = scan
        return scan

    def get_scan(self, scan_id: str) -> Scan | None:
        scan = self.scans.get(scan_id)
        if scan is None or scan.deleted:
            return None
        return scan


def start_scan(scan: Scan) -> tuple[int, dict[str, object] | None]:
    if scan.status == "running":
        return 409, error("scan_already_running", "scan is already running")
    scan.start_count += 1
    if scan.status in {"failed", "stopped", "succeeded", "error"}:
        scan.status = "running"
        scan.status_poll_count = 0
    else:
        scan.status = "running"
    return 204, None


def stop_scan(scan: Scan) -> tuple[int, dict[str, object] | None]:
    if scan.status in TERMINAL_STATUSES:
        return 409, error("scan_terminal", "terminal scans cannot be stopped")
    scan.stop_count += 1
    scan.status = "stopped"
    return 204, None


def status_for(scan: Scan) -> dict[str, object]:
    """Advance and return the externally visible scanner status.

    Status polling is deliberately stateful. Real scanner integrations often
    encode behavior around repeated polls, so the mock models progress through
    poll counts instead of wall-clock time to keep tests stable and fast.
    """

    if scan.status == "created":
        return {"id": scan.id, "status": "created", "progress": 0, "poll_count": scan.status_poll_count}

    scan.status_poll_count += 1
    scenario = scan.scenario
    if scan.status == "stopped":
        return {"id": scan.id, "status": "stopped", "progress": 0, "poll_count": scan.status_poll_count}
    if scenario == "scanner-failure":
        if scan.status_poll_count >= 2:
            scan.status = "failed"
            return _status(scan, 65, scanner_error={"code": "scanner_fixture_failure", "message": "deterministic scanner failure"})
        return _status(scan, 35)
    if scenario == "stop-running":
        return _status(scan, 25 if scan.status_poll_count == 1 else 50)
    if scenario == "delayed-findings":
        if scan.status_poll_count >= 3:
            scan.status = "succeeded"
            return _status(scan, 100)
        return _status(scan, 30 * scan.status_poll_count)
    if scan.status_poll_count >= 2:
        scan.status = "succeeded"
        return _status(scan, 100)
    return _status(scan, 50)


def delete_scan(scan: Scan) -> tuple[int, dict[str, object] | None]:
    scan.delete_count += 1
    if scan.scenario == "delete-refused" and scan.status not in TERMINAL_STATUSES:
        return 409, error("delete_refused", "scanner refused to delete an active scan")
    scan.deleted = True
    return 204, None


def page_results(scan: Scan, offset: int, limit: int) -> dict[str, object]:
    """Return a deterministic page of results with scenario-specific anomalies."""

    scan.results_request_count += 1
    visible_results = scan.results
    if scan.scenario == "delayed-findings" and scan.status not in TERMINAL_STATUSES and scan.results_request_count == 1:
        visible_results = []

    total = len(visible_results)
    slice_offset = offset
    # Some manager implementations assume result paging is strictly monotonic.
    # This fixture intentionally repeats one page so compatibility tests can
    # verify duplicate detection and idempotent import behavior.
    if scan.scenario == "duplicate-result-page" and offset > 0 and not scan.duplicate_page_sent:
        slice_offset = max(0, offset - limit)
        scan.duplicate_page_sent = True

    rows = visible_results[slice_offset : slice_offset + limit]
    next_offset = offset + limit if offset + limit < total else None
    return {
        "scan_id": scan.id,
        "offset": offset,
        "limit": limit,
        "total": total,
        "next_offset": next_offset,
        "results": rows,
    }


def error(code: str, message: str) -> dict[str, object]:
    return {"error": {"code": code, "message": message}}


def _status(scan: Scan, progress: int, **extra: object) -> dict[str, object]:
    body: dict[str, object] = {
        "id": scan.id,
        "status": scan.status,
        "progress": progress,
        "poll_count": scan.status_poll_count,
    }
    body.update(extra)
    return body
