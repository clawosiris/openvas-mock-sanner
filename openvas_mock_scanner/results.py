"""Deterministic synthetic result generation."""

from __future__ import annotations

from datetime import timedelta
from hashlib import sha256

from .config import Config


def generate_results(config: Config, scan_id: str) -> list[dict[str, object]]:
    """Generate the complete deterministic result set for a scan."""

    return [_result(config, scan_id, ordinal) for ordinal in range(1, config.result_count + 1)]


def threat_for_severity(severity: float) -> str:
    """Map CVSS-like numeric severity into Greenbone threat buckets."""

    if severity >= 9.0:
        return "Critical"
    if severity >= 7.0:
        return "High"
    if severity >= 4.0:
        return "Medium"
    if severity > 0.0:
        return "Low"
    return "Log"


def _result(config: Config, scan_id: str, ordinal: int) -> dict[str, object]:
    """Build one rich result object from stable scenario inputs."""

    digest = sha256(f"{config.seed}:{config.scenario}:{scan_id}:{ordinal}".encode("utf-8")).hexdigest()
    host_num = ((ordinal - 1) % config.host_count) + 1
    port = [22, 80, 443, 5432, 8080][(ordinal - 1) % 5]
    service = {22: "ssh", 80: "http", 443: "https", 5432: "postgresql", 8080: "http-alt"}[port]
    severities = [0.0, 2.1, 5.0, 7.5, 9.8]
    severity = severities[(ordinal - 1) % len(severities)]
    timestamp = (config.clock_start + timedelta(seconds=ordinal * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cve_year = 2020 + (ordinal % 7)
    cve_num = int(digest[:4], 16) % 9000 + 1000
    # The payload is intentionally richer than the current mock endpoints need.
    # gvmd imports depend on host, port, NVT, severity, references, and timing
    # fields, so keeping them present here prevents false confidence from a
    # too-thin scanner fixture.
    return {
        "id": f"{scan_id}-result-{ordinal:06d}",
        "ordinal": ordinal,
        "type": "alarm" if severity >= 4.0 else "log",
        "ip_address": f"10.42.{(host_num - 1) // 254}.{((host_num - 1) % 254) + 1}",
        "hostname": f"synthetic-host-{host_num:04d}.lab",
        "port": port,
        "protocol": "tcp",
        "service": service,
        "oid": f"1.3.6.1.4.1.25623.1.0.{100000 + ordinal}",
        "nvt_name": f"Synthetic {service.upper()} Finding {ordinal:04d}",
        "family": "Synthetic Compatibility",
        "severity": severity,
        "threat": threat_for_severity(severity),
        "qod": 70 + (ordinal % 30),
        "description": "Deterministic synthetic finding for compatibility tests.",
        "detection": f"Generated from seed {config.seed!r} for {scan_id}.",
        "solution": "Apply the synthetic remediation recommended by the compatibility fixture.",
        "solution_type": "Mitigation" if severity > 0 else "NoneAvailable",
        "created_at": timestamp,
        "updated_at": timestamp,
        "cve": [] if severity == 0.0 else [f"CVE-{cve_year}-{cve_num:04d}"],
        "cpe": [f"cpe:/a:synthetic:{service}:1.0"],
        "cvss_base": severity,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if severity >= 7.0 else "",
        "references": [{"type": "url", "id": f"https://example.test/{digest[:12]}"}],
        "tags": {
            "scenario": config.scenario,
            "seed": config.seed,
            "fixture": "openvas-mock-sanner",
        },
    }
