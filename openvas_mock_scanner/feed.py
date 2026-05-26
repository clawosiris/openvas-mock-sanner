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
class PackageProfile:
    name: str
    version: str = ""
    cpe: str = ""
    source: str = ""


@dataclass(frozen=True)
class HostProfile:
    host: str
    hostname: str = ""
    services: tuple[ServiceProfile, ...] = ()
    packages: tuple[PackageProfile, ...] = ()
    web_apps: tuple[dict[str, object], ...] = ()
    auth: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PackageAdvisory:
    oid: str
    name: str
    family: str = "Linux Local Security Checks"
    severity: float = 0.0
    cves: tuple[str, ...] = ()
    packages: tuple[PackageProfile, ...] = ()
    summary: str = ""
    solution: str = ""
    references: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class ScapCve:
    cve_id: str
    severity: float = 0.0
    cvss_vector: str = ""
    summary: str = ""
    references: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class FeedContext:
    metadata: dict[str, VtMetadata]
    target_profile: tuple[HostProfile, ...] = ()
    advisories: dict[str, PackageAdvisory] = field(default_factory=dict)
    scap_cves: dict[str, ScapCve] = field(default_factory=dict)
    diagnostics: tuple[str, ...] = ()


def load_feed_context(config: Config) -> FeedContext:
    """Load optional feed/profile files according to strict-mode semantics."""

    diagnostics: list[str] = []
    metadata: dict[str, VtMetadata] = {}
    target_profile: tuple[HostProfile, ...] = ()
    advisories: dict[str, PackageAdvisory] = {}
    scap_cves: dict[str, ScapCve] = {}

    if config.vt_metadata_path:
        metadata = _load_metadata_file(config.vt_metadata_path, config.feed_strict, diagnostics)
    if config.scap_metadata_path:
        scap_cves = _load_scap_metadata(config.scap_metadata_path, config.feed_strict, diagnostics)
    if config.notus_advisories_path:
        advisories = _load_notus_advisories(config.notus_advisories_path, config.feed_strict, diagnostics)
    if config.target_profile_path:
        target_profile = _load_target_profile(config.target_profile_path, config.feed_strict, diagnostics)
    if advisories:
        metadata = _merge_advisory_metadata(metadata, advisories, scap_cves)
    return FeedContext(
        metadata=metadata,
        target_profile=target_profile,
        advisories=advisories,
        scap_cves=scap_cves,
        diagnostics=tuple(diagnostics),
    )


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


def _load_notus_advisories(path: str, strict: bool, diagnostics: list[str]) -> dict[str, PackageAdvisory]:
    try:
        data = _read_json_file(path)
        advisories = {item.oid: item for item in (_advisory_from_object(raw) for raw in _iter_advisory_objects(data)) if item is not None}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if strict:
            raise ConfigError(f"invalid MOCK_NOTUS_ADVISORIES_PATH: {exc}") from exc
        diagnostics.append(f"skipped Notus advisories {path}: {exc}")
        return {}
    if not advisories and strict:
        raise ConfigError("invalid MOCK_NOTUS_ADVISORIES_PATH: no usable advisory entries")
    return advisories


def _load_scap_metadata(path: str, strict: bool, diagnostics: list[str]) -> dict[str, ScapCve]:
    try:
        data = _read_json_file(path)
        cves = {item.cve_id: item for item in (_scap_cve_from_object(raw) for raw in _iter_cve_objects(data)) if item is not None}
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if strict:
            raise ConfigError(f"invalid MOCK_SCAP_METADATA_PATH: {exc}") from exc
        diagnostics.append(f"skipped SCAP metadata {path}: {exc}")
        return {}
    if not cves and strict:
        raise ConfigError("invalid MOCK_SCAP_METADATA_PATH: no usable CVE entries")
    return cves


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


def _iter_advisory_objects(data: object) -> Iterable[dict[str, object]]:
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(data, dict):
        return
    for key in ("advisories", "notus", "items", "data", "results"):
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


def _iter_cve_objects(data: object) -> Iterable[dict[str, object]]:
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(data, dict):
        return
    for key in ("cves", "vulnerabilities", "items", "data", "results"):
        value = data.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item
            return
    for key, value in data.items():
        if isinstance(value, dict):
            item = dict(value)
            item.setdefault("id", key)
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


def _advisory_from_object(item: dict[str, object]) -> PackageAdvisory | None:
    oid = _first_string(item, ("oid", "id", "vt_oid"))
    name = _first_string(item, ("name", "title", "advisory_id")) or oid
    if not oid or not name:
        return None
    packages = tuple(pkg for pkg in (_package_from_object(raw) for raw in _package_objects(item)) if pkg is not None)
    references = tuple(_references(_first_present(item, ("references", "refs"))))
    cves = tuple(_string_values(_first_present(item, ("cves", "cve", "cve_refs")))) or tuple(_cves_from_references(references))
    return PackageAdvisory(
        oid=oid,
        name=name,
        family=_first_string(item, ("family",)) or "Linux Local Security Checks",
        severity=_float_value(_first_present(item, ("severity", "cvss_base", "score")), 0.0),
        cves=tuple(cve.upper() for cve in cves),
        packages=packages,
        summary=_summary(item),
        solution=_first_string(item, ("solution", "remediation")),
        references=references,
    )


def _scap_cve_from_object(item: dict[str, object]) -> ScapCve | None:
    cve_id = _first_string(item, ("id", "cve", "cve_id", "name")).upper()
    if not cve_id.startswith("CVE-"):
        return None
    references = tuple(_references(_first_present(item, ("references", "refs"))))
    return ScapCve(
        cve_id=cve_id,
        severity=_float_value(_first_present(item, ("severity", "cvss_base", "cvss3_base_score", "score")), 0.0),
        cvss_vector=_first_string(item, ("cvss_vector", "cvss3_vector", "cvss_base_vector")),
        summary=_scap_summary(item),
        references=references,
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
    packages = tuple(pkg for pkg in (_package_from_object(raw) for raw in _package_objects(item)) if pkg is not None)
    web_apps = item.get("web_apps", [])
    auth = item.get("auth", {})
    return HostProfile(
        host=host,
        hostname=_first_string(item, ("hostname", "name")),
        services=tuple(services),
        packages=packages,
        web_apps=tuple(app for app in web_apps if isinstance(app, dict)) if isinstance(web_apps, list) else (),
        auth=auth if isinstance(auth, dict) else {},
    )


def _package_objects(item: dict[str, object]) -> Iterable[object]:
    for key in ("packages", "affected_packages", "affected", "installed_packages"):
        value = item.get(key)
        if isinstance(value, list):
            yield from value
            return


def _package_from_object(item: object) -> PackageProfile | None:
    if isinstance(item, str):
        name, _, version = item.partition("=")
        name = name.strip()
        if not name:
            return None
        return PackageProfile(name=name, version=version.strip())
    if not isinstance(item, dict):
        return None
    name = _first_string(item, ("name", "package", "product"))
    if not name:
        return None
    return PackageProfile(
        name=name,
        version=_first_string(item, ("version", "installed_version", "affected_version", "fixed_version")),
        cpe=_first_string(item, ("cpe",)),
        source=_first_string(item, ("source", "repository", "ecosystem")),
    )


def _merge_advisory_metadata(
    metadata: dict[str, VtMetadata],
    advisories: dict[str, PackageAdvisory],
    scap_cves: dict[str, ScapCve],
) -> dict[str, VtMetadata]:
    merged = dict(metadata)
    for advisory in advisories.values():
        existing = merged.get(advisory.oid)
        if existing is None:
            merged[advisory.oid] = _metadata_from_advisory(advisory, scap_cves)
        else:
            merged[advisory.oid] = _enrich_metadata_from_advisory(existing, advisory, scap_cves)
    return merged


def _metadata_from_advisory(advisory: PackageAdvisory, scap_cves: dict[str, ScapCve]) -> VtMetadata:
    severity = advisory.severity or max((scap_cves[cve].severity for cve in advisory.cves if cve in scap_cves), default=0.0)
    summaries = [scap_cves[cve].summary for cve in advisory.cves if cve in scap_cves and scap_cves[cve].summary]
    references = list(advisory.references)
    for cve in advisory.cves:
        references.append({"class": "cve", "id": cve})
        if cve in scap_cves:
            references.extend(scap_cves[cve].references)
    return VtMetadata(
        oid=advisory.oid,
        name=advisory.name,
        family=advisory.family,
        severity=severity,
        cvss_vector=next((scap_cves[cve].cvss_vector for cve in advisory.cves if cve in scap_cves and scap_cves[cve].cvss_vector), ""),
        cves=advisory.cves,
        references=tuple(references),
        tags={
            "feed-source": "notus",
            "packages": [package.name for package in advisory.packages],
        },
        summary=advisory.summary or (summaries[0] if summaries else ""),
        solution=advisory.solution,
        solution_type="VendorFix" if advisory.solution else "",
        qod=97,
    )


def _enrich_metadata_from_advisory(existing: VtMetadata, advisory: PackageAdvisory, scap_cves: dict[str, ScapCve]) -> VtMetadata:
    severity = existing.severity or advisory.severity or max((scap_cves[cve].severity for cve in advisory.cves if cve in scap_cves), default=0.0)
    cves = tuple(sorted(set(existing.cves + advisory.cves)))
    tags = dict(existing.tags)
    tags.setdefault("feed-source", "vt+notus")
    tags["packages"] = [package.name for package in advisory.packages]
    references = list(existing.references or advisory.references)
    known_cve_refs = {reference.get("id", "").upper() for reference in references if (reference.get("class") or reference.get("type", "")).lower() == "cve"}
    for cve in cves:
        if cve not in known_cve_refs:
            references.append({"class": "cve", "id": cve})
    return VtMetadata(
        oid=existing.oid,
        name=existing.name,
        family=existing.family,
        severity=severity,
        cvss_vector=existing.cvss_vector or next((scap_cves[cve].cvss_vector for cve in cves if cve in scap_cves and scap_cves[cve].cvss_vector), ""),
        cves=cves,
        cpes=existing.cpes,
        references=tuple(references),
        tags=tags,
        summary=existing.summary or advisory.summary,
        detection=existing.detection,
        solution=existing.solution or advisory.solution,
        solution_type=existing.solution_type or ("VendorFix" if advisory.solution else ""),
        qod=existing.qod,
    )


def _scap_summary(item: dict[str, object]) -> str:
    direct = _summary(item)
    if direct:
        return direct
    descriptions = item.get("descriptions")
    if isinstance(descriptions, list):
        for description in descriptions:
            if not isinstance(description, dict):
                continue
            value = description.get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


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
