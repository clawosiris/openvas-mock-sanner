"""Feed metadata and target profile helpers for realistic fixtures."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable

from .config import Config, ConfigError


@dataclass(frozen=True)
class VtMetadata:
    oid: str
    name: str
    family: str
    severity: float = 0.0
    cvss_vector: str = ""
    cves: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()
    references: tuple[dict[str, str], ...] = ()
    tags: dict[str, object] = field(default_factory=dict)
    summary: str = ""
    detection: str = ""
    solution: str = ""
    solution_type: str = ""
    qod: int = 70

    def as_dict(self) -> dict[str, object]:
        return {
            "oid": self.oid,
            "name": self.name,
            "family": self.family,
            "severity": self.severity,
            "cvss_vector": self.cvss_vector,
            "cves": list(self.cves),
            "cpes": list(self.cpes),
            "references": list(self.references),
            "tags": self.tags,
            "summary": self.summary,
            "detection": self.detection,
            "solution": self.solution,
            "solution_type": self.solution_type,
            "qod": self.qod,
        }


@dataclass(frozen=True)
class ServiceProfile:
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""
    cpe: str = ""


@dataclass(frozen=True)
class HostProfile:
    host: str
    hostname: str = ""
    services: tuple[ServiceProfile, ...] = ()
    packages: tuple[dict[str, object], ...] = ()
    web_apps: tuple[dict[str, object], ...] = ()
    auth: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class FeedContext:
    metadata: dict[str, VtMetadata]
    target_profile: tuple[HostProfile, ...] = ()
    diagnostics: tuple[str, ...] = ()


def load_feed_context(config: Config) -> FeedContext:
    """Load optional feed/profile files according to strict-mode semantics."""

    diagnostics: list[str] = []
    metadata: dict[str, VtMetadata] = {}
    target_profile: tuple[HostProfile, ...] = ()

    if config.vt_metadata_path:
        metadata = _load_metadata_file(config.vt_metadata_path, config.feed_strict, diagnostics)
    if config.target_profile_path:
        target_profile = _load_target_profile(config.target_profile_path, config.feed_strict, diagnostics)
    return FeedContext(metadata=metadata, target_profile=target_profile, diagnostics=tuple(diagnostics))


def selected_scan_oids(payload: dict[str, Any]) -> set[str]:
    vts = payload.get("vts")
    if not isinstance(vts, list):
        return set()
    selected: set[str] = set()
    for vt in vts:
        oid = None
        if isinstance(vt, str):
            oid = vt
        elif isinstance(vt, dict):
            raw = vt.get("oid") or vt.get("id")
            oid = raw if isinstance(raw, str) else None
        if oid:
            selected.add(oid)
    return selected


def scan_hosts(payload: dict[str, Any]) -> tuple[str, ...]:
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    hosts = _string_values(target.get("hosts")) or _string_values(payload.get("hosts"))
    excluded = set(_string_values(target.get("excluded_hosts")) + _string_values(target.get("exclude_hosts")) + _string_values(payload.get("excluded_hosts")))
    return tuple(host for host in hosts if host not in excluded)


def scan_ports(payload: dict[str, Any]) -> tuple[int, ...]:
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    values = target.get("ports", payload.get("ports"))
    ports = set(_ports_from_value(values))
    preferences = payload.get("scan_preferences")
    if isinstance(preferences, dict):
        for key, value in preferences.items():
            if "port" in str(key).lower():
                ports.update(_ports_from_value(value))
    return tuple(sorted(ports))


def stable_payload_digest(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(data.encode("utf-8")).hexdigest()


def _load_metadata_file(path: str, strict: bool, diagnostics: list[str]) -> dict[str, VtMetadata]:
    try:
        data = _read_json_file(path)
        entries = [_metadata_from_object(item) for item in _iter_vt_objects(data)]
        metadata = {entry.oid: entry for entry in entries if entry is not None}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if strict:
            raise ConfigError(f"invalid MOCK_VT_METADATA_PATH: {exc}") from exc
        diagnostics.append(f"skipped VT metadata {path}: {exc}")
        return {}
    if not metadata and strict:
        raise ConfigError("invalid MOCK_VT_METADATA_PATH: no usable VT metadata entries")
    return metadata


def _load_target_profile(path: str, strict: bool, diagnostics: list[str]) -> tuple[HostProfile, ...]:
    try:
        data = _read_json_file(path)
        hosts = data.get("hosts") if isinstance(data, dict) else None
        if not isinstance(hosts, list):
            raise ValueError("target profile must contain a hosts array")
        parsed = tuple(host for host in (_host_from_object(item) for item in hosts) if host is not None)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if strict:
            raise ConfigError(f"invalid MOCK_TARGET_PROFILE: {exc}") from exc
        diagnostics.append(f"skipped target profile {path}: {exc}")
        return ()
    if not parsed and strict:
        raise ConfigError("invalid MOCK_TARGET_PROFILE: no usable host entries")
    return parsed


def _read_json_file(path: str) -> object:
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _iter_vt_objects(data: object) -> Iterable[dict[str, object]]:
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(data, dict):
        return
    for key in ("data", "results", "vts", "items", "metadata", "vt_metadata", "vulnerability_tests"):
        value = data.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item
            return
    for key, value in data.items():
        if isinstance(value, dict):
            item = dict(value)
            item.setdefault("oid", key)
            yield item


def _metadata_from_object(item: dict[str, object]) -> VtMetadata | None:
    oid = _first_string(item, ("oid", "id", "vt_oid"))
    name = _first_string(item, ("name", "nvt_name", "title"))
    family = _first_string(item, ("family", "vt_family"))
    if not oid or not name or not family:
        return None
    references = tuple(_references(_first_present(item, ("references", "refs"))))
    cves = tuple(_string_values(_first_present(item, ("cves", "cve", "cve_refs")))) or tuple(_cves_from_references(references))
    return VtMetadata(
        oid=oid,
        name=name,
        family=family,
        severity=_float_value(_first_present(item, ("severity", "cvss_base", "cvss_base_score", "score")), 0.0),
        cvss_vector=_first_string(item, ("cvss_vector", "cvss_base_vector")),
        cves=cves,
        cpes=tuple(_string_values(_first_present(item, ("cpes", "cpe", "cpe_refs")))),
        references=references,
        tags=_tags(_first_present(item, ("tags", "tag"))),
        summary=_summary(item),
        detection=_first_string(item, ("detection", "detection_method")),
        solution=_first_string(item, ("solution", "remediation")),
        solution_type=_first_string(item, ("solution_type",)),
        qod=int(_float_value(_first_present(item, ("qod", "qod_value")), 70)),
    )


def _host_from_object(item: object) -> HostProfile | None:
    if not isinstance(item, dict):
        return None
    host = _first_string(item, ("host", "ip", "ip_address"))
    if not host:
        return None
    services = []
    for service in item.get("services", []):
        if not isinstance(service, dict):
            continue
        port = int(_float_value(service.get("port"), -1))
        protocol = _first_string(service, ("protocol",)) or "tcp"
        name = _first_string(service, ("name", "service"))
        if port < 1 or not name:
            continue
        services.append(
            ServiceProfile(
                port=port,
                protocol=protocol,
                name=name,
                product=_first_string(service, ("product",)),
                version=_first_string(service, ("version",)),
                cpe=_first_string(service, ("cpe",)),
            )
        )
    packages = item.get("packages", [])
    web_apps = item.get("web_apps", [])
    auth = item.get("auth", {})
    return HostProfile(
        host=host,
        hostname=_first_string(item, ("hostname", "name")),
        services=tuple(services),
        packages=tuple(pkg for pkg in packages if isinstance(pkg, dict)) if isinstance(packages, list) else (),
        web_apps=tuple(app for app in web_apps if isinstance(app, dict)) if isinstance(web_apps, list) else (),
        auth=auth if isinstance(auth, dict) else {},
    )


def _first_present(item: dict[str, object], keys: tuple[str, ...]) -> object:
    for key in keys:
        if key in item:
            return item[key]
    return None


def _first_string(item: dict[str, object], keys: tuple[str, ...]) -> str:
    value = _first_present(item, keys)
    return value.strip() if isinstance(value, str) else ""


def _string_values(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            if isinstance(item, str):
                values.extend(_string_values(item))
            elif isinstance(item, (int, float)):
                values.append(str(int(item)))
        return values
    if isinstance(value, (int, float)):
        return [str(int(value))]
    return []


def _ports_from_value(value: object) -> list[int]:
    if isinstance(value, list):
        ports: list[int] = []
        for item in value:
            if isinstance(item, dict):
                ports.extend(_ports_from_value(item.get("port")))
            else:
                ports.extend(_ports_from_value(item))
        return ports

    ports: list[int] = []
    for raw in _string_values(value):
        raw = raw.removeprefix("T:").removeprefix("U:")
        for part in raw.split(","):
            if "-" in part:
                start, _, end = part.partition("-")
                try:
                    ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
    return [port for port in ports if 1 <= port <= 65535]


def _references(value: object) -> list[dict[str, str]]:
    if isinstance(value, list):
        refs = []
        for item in value:
            if isinstance(item, dict):
                refs.append({str(key): str(val) for key, val in item.items()})
            elif isinstance(item, str):
                refs.append({"type": "url", "id": item})
        return refs
    if isinstance(value, dict):
        return [{str(key): str(val)} for key, val in value.items()]
    return [{"type": "url", "id": item} for item in _string_values(value)]


def _tags(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    tags = _string_values(value)
    return {tag: True for tag in tags}


def _summary(item: dict[str, object]) -> str:
    direct = _first_string(item, ("summary", "description", "impact", "insight"))
    if direct:
        return direct
    tag = item.get("tag")
    if isinstance(tag, dict):
        for key in ("summary", "description", "impact", "insight"):
            value = tag.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _cves_from_references(references: tuple[dict[str, str], ...]) -> list[str]:
    cves: list[str] = []
    for reference in references:
        ref_class = reference.get("class") or reference.get("type")
        ref_id = reference.get("id")
        if ref_id and ref_id.upper().startswith("CVE-") and (not ref_class or ref_class.lower() == "cve"):
            cves.append(ref_id.upper())
    return sorted(set(cves))


def _float_value(value: object, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default
