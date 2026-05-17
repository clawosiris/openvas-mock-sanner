#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS_DIR = REPO_ROOT / "implementations"
RESULTS_DIR = REPO_ROOT / "results"


@dataclass
class CheckResult:
    name: str
    passed: bool
    details: str


class BenchmarkFailure(RuntimeError):
    pass


def choose_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def load_manifest(implementation_dir: Path) -> dict[str, Any]:
    manifest_path = implementation_dir / "benchmark.json"
    with manifest_path.open("r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    if not isinstance(manifest.get("start_command"), list) or not manifest["start_command"]:
        raise BenchmarkFailure(f"Invalid start_command in {manifest_path}")
    if not isinstance(manifest.get("port_env"), str) or not manifest["port_env"]:
        raise BenchmarkFailure(f"Invalid port_env in {manifest_path}")
    return manifest


def wait_for_port(port: int, timeout_seconds: float) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise BenchmarkFailure(f"Server did not open port {port} within {timeout_seconds:.1f}s")


def http_json(method: str, url: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = None
    headers = {"accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["content-type"] = "application/json"
    request = Request(url, method=method, data=data, headers=headers)
    try:
        with urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            body = json.loads(raw) if raw else None
            return response.status, body
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        body = None
        if raw:
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = raw
        return exc.code, body
    except URLError as exc:
        raise BenchmarkFailure(f"HTTP request failed: {exc}") from exc


def expect(condition: bool, name: str, details: str, checks: list[CheckResult]) -> None:
    checks.append(CheckResult(name=name, passed=condition, details=details))
    if not condition:
        raise BenchmarkFailure(f"{name}: {details}")


def run_acceptance(base_url: str) -> list[CheckResult]:
    checks: list[CheckResult] = []

    status, created = http_json("POST", f"{base_url}/scans", {"target": {}, "vts": []})
    scan_id = created.get("id") if isinstance(created, dict) else None
    expect(status == 201 and isinstance(scan_id, str), "create_scan", f"status={status}, body={created}", checks)

    status, body = http_json("GET", f"{base_url}/scans/{scan_id}/status")
    expect(status == 200 and body.get("status") == "created", "status_before_start", f"status={status}, body={body}", checks)

    status, body = http_json("POST", f"{base_url}/scans/{scan_id}", {"action": "start"})
    expect(status == 200 and body.get("status") == "running", "start_scan", f"status={status}, body={body}", checks)

    status, body = http_json("GET", f"{base_url}/scans/{scan_id}/results")
    expect(status == 200 and body.get("results") == [], "results_delay_poll_1", f"status={status}, body={body}", checks)

    status, body = http_json("GET", f"{base_url}/scans/{scan_id}/results")
    expect(status == 200 and body.get("results") == [], "results_delay_poll_2", f"status={status}, body={body}", checks)

    status, body = http_json("GET", f"{base_url}/scans/{scan_id}/results")
    results = body.get("results") if isinstance(body, dict) else None
    expect(status == 200 and isinstance(results, list) and len(results) == 7, "results_count", f"status={status}, body_length={len(results) if isinstance(results, list) else 'n/a'}", checks)

    ids = [item.get("id") for item in results]
    expect(ids == list(range(1, 8)), "result_ids_stable", f"ids={ids}", checks)

    oid_count = len({item.get("oid") for item in results})
    expect(oid_count >= 3, "result_oid_variety", f"oid_count={oid_count}", checks)

    status, body_repeat = http_json("GET", f"{base_url}/scans/{scan_id}/results")
    expect(status == 200 and body_repeat == body, "results_deterministic", f"status={status}", checks)

    for poll_number in range(1, 4):
        status, body = http_json("GET", f"{base_url}/scans/{scan_id}/status")
        expected = "succeeded" if poll_number == 3 else "running"
        expect(status == 200 and body.get("status") == expected, f"status_poll_{poll_number}", f"status={status}, body={body}", checks)

    status, body = http_json("POST", f"{base_url}/scans/{scan_id}", {"action": "bogus"})
    expect(status == 400, "invalid_action", f"status={status}, body={body}", checks)

    status, created_stop = http_json("POST", f"{base_url}/scans", {"target": {}, "vts": []})
    stop_scan_id = created_stop.get("id") if isinstance(created_stop, dict) else None
    expect(status == 201 and isinstance(stop_scan_id, str), "create_scan_for_stop", f"status={status}, body={created_stop}", checks)

    status, body = http_json("POST", f"{base_url}/scans/{stop_scan_id}", {"action": "start"})
    expect(status == 200 and body.get("status") == "running", "start_scan_for_stop", f"status={status}, body={body}", checks)

    status, body = http_json("POST", f"{base_url}/scans/{stop_scan_id}", {"action": "stop"})
    expect(status == 200 and body.get("status") == "stopped", "stop_scan", f"status={status}, body={body}", checks)

    status, body = http_json("DELETE", f"{base_url}/scans/{scan_id}")
    expect(status in {200, 204}, "delete_scan", f"status={status}, body={body}", checks)

    for endpoint_name, endpoint in {
        "deleted_status_404": f"/scans/{scan_id}/status",
        "deleted_results_404": f"/scans/{scan_id}/results",
        "deleted_action_404": f"/scans/{scan_id}",
    }.items():
        method = "GET" if endpoint.endswith(("status", "results")) else "POST"
        payload = None if method == "GET" else {"action": "start"}
        status, body = http_json(method, f"{base_url}{endpoint}", payload)
        expect(status == 404, endpoint_name, f"status={status}, body={body}", checks)

    return checks


def run_invalid_config_check(manifest: dict[str, Any], implementation_dir: Path, output_dir: Path) -> CheckResult:
    env = os.environ.copy()
    env[manifest["port_env"]] = str(choose_free_port())
    env["MOCK_RESULT_COUNT"] = "-1"
    for key, value in manifest.get("env", {}).items():
        env.setdefault(key, str(value))
    process = subprocess.Popen(
        manifest["start_command"],
        cwd=implementation_dir / manifest.get("cwd", "."),
        env=env,
        stdout=(output_dir / "invalid-config.stdout.log").open("w", encoding="utf-8"),
        stderr=(output_dir / "invalid-config.stderr.log").open("w", encoding="utf-8"),
    )
    deadline = time.time() + 5
    while time.time() < deadline:
        return_code = process.poll()
        if return_code is not None:
            passed = return_code != 0
            return CheckResult(
                name="invalid_config_fails_fast",
                passed=passed,
                details=f"return_code={return_code}",
            )
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=5)
    return CheckResult(
        name="invalid_config_fails_fast",
        passed=False,
        details="process stayed alive with invalid config",
    )


def run_benchmark(implementation: str) -> int:
    implementation_dir = IMPLEMENTATIONS_DIR / implementation
    if not implementation_dir.exists():
        raise BenchmarkFailure(f"Implementation not found: {implementation_dir}")

    manifest = load_manifest(implementation_dir)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_dir = RESULTS_DIR / implementation / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    port = choose_free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env[manifest["port_env"]] = str(port)
    env.update({
        "MOCK_RESULT_COUNT": "7",
        "MOCK_FINDINGS_DELAY_POLLS": "2",
        "MOCK_SCAN_COMPLETE_POLLS": "3",
        "MOCK_HOST_COUNT": "3",
        "MOCK_SEED": "benchmark-seed",
    })
    for key, value in manifest.get("env", {}).items():
        env[key] = str(value)

    stdout_path = output_dir / "server.stdout.log"
    stderr_path = output_dir / "server.stderr.log"
    with stdout_path.open("w", encoding="utf-8") as stdout_fh, stderr_path.open("w", encoding="utf-8") as stderr_fh:
        process = subprocess.Popen(
            manifest["start_command"],
            cwd=implementation_dir / manifest.get("cwd", "."),
            env=env,
            stdout=stdout_fh,
            stderr=stderr_fh,
        )
        checks: list[CheckResult] = []
        exit_code = 1
        try:
            wait_for_port(port, timeout_seconds=60)
            checks = run_acceptance(base_url)
            invalid_check = run_invalid_config_check(manifest, implementation_dir, output_dir)
            checks.append(invalid_check)
            if not invalid_check.passed:
                raise BenchmarkFailure(f"{invalid_check.name}: {invalid_check.details}")
            exit_code = 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    summary = {
        "implementation": implementation,
        "timestamp": timestamp,
        "passed": exit_code == 0,
        "checks": [asdict(check) for check in checks],
        "artifacts": {
            "stdout": str(stdout_path.relative_to(REPO_ROOT)),
            "stderr": str(stderr_path.relative_to(REPO_ROOT)),
        },
    }
    with (output_dir / "summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the OpenVAS mock-server benchmark harness")
    parser.add_argument("--implementation", required=True, help="Implementation directory name under implementations/")
    args = parser.parse_args()
    try:
        return run_benchmark(args.implementation)
    except BenchmarkFailure as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
