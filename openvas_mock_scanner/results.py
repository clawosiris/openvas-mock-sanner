"""Deterministic synthetic result generation."""

from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from typing import Any

from .config import Config
from .feed import FeedContext, HostProfile, PackageProfile, ServiceProfile, load_feed_context, scan_hosts, scan_ports, selected_scan_oids, stable_payload_digest


def generate_results(config: Config, scan_id: str, payload: dict[str, Any] | None = None, feed_context: FeedContext | None = None) -> list[dict[str, object]]:
    """Generate the complete deterministic result set for a scan."""

    payload = payload or {}
    feed_context = feed_context if feed_context is not None else load_feed_context(config)
    if feed_context.metadata:
        return _feed_results(config, scan_id, payload, feed_context)
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
    # Keep richer source data internally so scenarios can derive stable raw
    # scanner findings and future VT metadata from the same fixture row.
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


def _feed_results(config: Config, scan_id: str, payload: dict[str, Any], context: FeedContext) -> list[dict[str, object]]:
    selected = selected_scan_oids(payload)
    if selected:
        candidates = [context.metadata[oid] for oid in selected if oid in context.metadata]
    else:
        candidates = list(context.metadata.values())
    if not candidates:
        return [_result(config, scan_id, ordinal) for ordinal in range(1, config.result_count + 1)]

    ports = scan_ports(payload)
    hosts = _hosts_for_scan(config, payload, context)
    digest = stable_payload_digest(payload)
    ranked = sorted(
        candidates,
        key=lambda vt: (-_vt_score(vt, ports, hosts), _stable_rank(config, scan_id, digest, vt.oid)),
    )

    rows = []
    for ordinal in range(1, config.result_count + 1):
        vt = ranked[(ordinal - 1) % len(ranked)]
        host = hosts[(ordinal - 1) % len(hosts)]
        service = _service_for_vt(vt, host, ports, ordinal)
        rows.append(_feed_result(config, scan_id, ordinal, vt, host, service))
    return rows


def _feed_result(
    config: Config,
    scan_id: str,
    ordinal: int,
    vt: object,
    host: HostProfile,
    service: ServiceProfile,
) -> dict[str, object]:
    severity = float(getattr(vt, "severity"))
    timestamp = (config.clock_start + timedelta(seconds=ordinal * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    message = _feed_message(vt, host, service, severity)
    return {
        "id": f"{scan_id}-result-{ordinal:06d}",
        "ordinal": ordinal,
        "type": "alarm" if severity >= 4.0 else "log",
        "ip_address": host.host,
        "hostname": host.hostname or host.host,
        "port": service.port,
        "protocol": service.protocol,
        "service": service.name,
        "oid": getattr(vt, "oid"),
        "nvt_name": getattr(vt, "name"),
        "family": getattr(vt, "family"),
        "severity": severity,
        "threat": threat_for_severity(severity),
        "qod": getattr(vt, "qod"),
        "description": message,
        "detection": getattr(vt, "detection") or f"Feed-backed fixture matched {service.name} on {host.host}.",
        "solution": getattr(vt, "solution") or "Review the feed metadata for remediation guidance.",
        "solution_type": getattr(vt, "solution_type") or ("Mitigation" if severity > 0 else "NoneAvailable"),
        "created_at": timestamp,
        "updated_at": timestamp,
        "cve": list(getattr(vt, "cves")),
        "cpe": list(getattr(vt, "cpes")) or ([service.cpe] if service.cpe else []),
        "cvss_base": severity,
        "cvss_vector": getattr(vt, "cvss_vector"),
        "references": list(getattr(vt, "references")),
        "tags": {
            "scenario": config.scenario,
            "seed": config.seed,
            "fixture": "openvas-mock-sanner",
            "feed-backed": True,
            **getattr(vt, "tags"),
        },
    }


def _hosts_for_scan(config: Config, payload: dict[str, Any], context: FeedContext) -> list[HostProfile]:
    wanted_hosts = scan_hosts(payload)
    if context.target_profile:
        filtered = [host for host in context.target_profile if not wanted_hosts or host.host in wanted_hosts or host.hostname in wanted_hosts]
        if filtered:
            return filtered
    if wanted_hosts:
        return [HostProfile(host=host, hostname=host) for host in wanted_hosts]
    return [
        HostProfile(
            host=f"10.42.{(index - 1) // 254}.{((index - 1) % 254) + 1}",
            hostname=f"synthetic-host-{index:04d}.lab",
        )
        for index in range(1, config.host_count + 1)
    ]


def _vt_score(vt: object, ports: tuple[int, ...], hosts: list[HostProfile]) -> int:
    text = " ".join([getattr(vt, "name"), getattr(vt, "family"), " ".join(str(value) for value in getattr(vt, "tags").values())]).lower()
    score = 0
    if getattr(vt, "severity") > 0:
        score += 1
    if ports:
        for port in ports:
            if str(port) in text:
                score += 2
    for host in hosts:
        for service in host.services:
            service_terms = [service.name, service.product, service.cpe]
            if any(term and term.lower() in text for term in service_terms):
                score += 4
            if ports and service.port in ports:
                score += 1
        for package in host.packages:
            if _package_matches_text(package, text):
                score += 3
        if host.web_apps and any(term in text for term in ("web", "http", "apache", "nginx")):
            score += 2
    return score


def _package_matches_text(package: PackageProfile, text: str) -> bool:
    return any(term and term.lower() in text for term in (package.name, package.cpe, package.source))


def _stable_rank(config: Config, scan_id: str, payload_digest: str, oid: str) -> str:
    return sha256(f"{config.seed}:{config.scenario}:{scan_id}:{payload_digest}:{oid}".encode("utf-8")).hexdigest()


def _service_for_vt(vt: object, host: HostProfile, ports: tuple[int, ...], ordinal: int) -> ServiceProfile:
    if host.services:
        ranked = sorted(host.services, key=lambda service: (-_service_score(vt, service, ports), service.port, service.name))
        return ranked[(ordinal - 1) % len(ranked)]
    if ports:
        port = ports[(ordinal - 1) % len(ports)]
        return ServiceProfile(port=port, protocol="tcp", name=_service_name(port))
    port = [22, 80, 443, 5432, 8080][(ordinal - 1) % 5]
    return ServiceProfile(port=port, protocol="tcp", name=_service_name(port))


def _service_score(vt: object, service: ServiceProfile, ports: tuple[int, ...]) -> int:
    text = f"{getattr(vt, 'name')} {getattr(vt, 'family')}".lower()
    score = 0
    if service.name.lower() in text:
        score += 4
    if service.product and service.product.lower() in text:
        score += 4
    if service.cpe and service.cpe.lower() in text:
        score += 4
    if service.port in ports:
        score += 2
    return score


def _service_name(port: int) -> str:
    return {22: "ssh", 80: "http", 443: "https", 5432: "postgresql", 8080: "http-alt"}.get(port, "unknown")


def _feed_message(vt: object, host: HostProfile, service: ServiceProfile, severity: float) -> str:
    product = f" ({service.product} {service.version})" if service.product else ""
    summary = getattr(vt, "summary")
    prefix = f"{getattr(vt, 'name')} detected on {host.host}:{service.port}/{service.protocol}{product}."
    if summary:
        return f"{prefix} {summary}"
    if severity > 0:
        return f"{prefix} Feed metadata indicates this VT should be reportable for compatibility testing."
    return f"{prefix} Informational feed-backed scanner finding."
