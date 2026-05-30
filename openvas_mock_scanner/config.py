"""Runtime configuration for the compatibility mock scanner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Mapping


SCENARIOS = {
    "success-basic",
    "success-large-report",
    "empty-report",
    "delayed-findings",
    "stop-running",
    "scanner-failure",
    "malformed-results",
    "transient-results-error",
    "delete-refused",
    "duplicate-result-page",
    "auth-missing",
    "dependency-missing",
    "port-closed",
    "vt-timeout",
    "partial-feed-results",
}

FAILURE_POINTS = {"create", "start", "status", "results", "delete"}


class ConfigError(ValueError):
    """Raised when environment configuration is invalid."""


@dataclass(frozen=True)
class FailureAt:
    """Configurable fault injection point.

    `point` names a lifecycle endpoint such as `start` or `results`. `count`
    optionally limits the failure to the Nth call for that point, which lets
    gvmd compatibility tests distinguish persistent scanner errors from
    retryable transient failures.
    """

    point: str
    count: int | None = None


@dataclass(frozen=True)
class Config:
    """Fully validated runtime configuration for one mock scanner process."""

    host: str
    port: int
    scenario: str
    page_size: int
    failure_at: FailureAt | None
    clock_start: datetime
    latency_ms: int
    result_count: int
    host_count: int
    seed: str
    vt_metadata_path: str | None = None
    target_profile_path: str | None = None
    notus_advisories_path: str | None = None
    scap_metadata_path: str | None = None
    feed_strict: bool = False


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Load scanner behavior from environment-style key/value pairs.

    The service intentionally avoids config files and third-party packages so
    the same artifact can run as a plain Python process, a CI test fixture, or a
    container replacement for the real OpenVAS scanner.
    """

    source = os.environ if env is None else env
    scenario = source.get("MOCK_SCENARIO", "success-basic")
    if scenario not in SCENARIOS:
        raise ConfigError(f"invalid MOCK_SCENARIO: {scenario!r}")

    listening_host, listening_port = _parse_listening(source.get("LISTENING"))
    defaults = _scenario_defaults(scenario)
    return Config(
        host=source.get("MOCK_HOST", listening_host or "127.0.0.1"),
        port=_parse_int(source, "MOCK_PORT", listening_port or 8080, minimum=1, maximum=65535),
        scenario=scenario,
        page_size=_parse_int(source, "MOCK_PAGE_SIZE", 100, minimum=1),
        failure_at=_parse_failure_at(source.get("MOCK_FAILURE_AT")),
        clock_start=_parse_clock(source.get("MOCK_CLOCK_START", "2026-01-01T00:00:00Z")),
        latency_ms=_parse_int(source, "MOCK_LATENCY_MS", 0, minimum=0),
        result_count=_parse_int(source, "MOCK_RESULT_COUNT", defaults["result_count"], minimum=0),
        host_count=_parse_int(source, "MOCK_HOST_COUNT", defaults["host_count"], minimum=1),
        seed=source.get("MOCK_SEED", "compat"),
        vt_metadata_path=_parse_optional_path(source.get("MOCK_VT_METADATA_PATH"), "MOCK_VT_METADATA_PATH"),
        target_profile_path=_parse_optional_path(source.get("MOCK_TARGET_PROFILE"), "MOCK_TARGET_PROFILE"),
        notus_advisories_path=_parse_optional_path(source.get("MOCK_NOTUS_ADVISORIES_PATH"), "MOCK_NOTUS_ADVISORIES_PATH"),
        scap_metadata_path=_parse_optional_path(source.get("MOCK_SCAP_METADATA_PATH"), "MOCK_SCAP_METADATA_PATH"),
        feed_strict=_parse_bool(source.get("MOCK_FEED_STRICT", "false"), "MOCK_FEED_STRICT"),
    )


def _scenario_defaults(scenario: str) -> dict[str, int]:
    """Return result volume defaults that make scenario intent visible."""

    if scenario == "success-large-report":
        return {"result_count": 250, "host_count": 25}
    if scenario == "empty-report":
        return {"result_count": 0, "host_count": 1}
    return {"result_count": 12, "host_count": 3}


def _parse_listening(raw: str | None) -> tuple[str | None, int | None]:
    """Parse openvasd's LISTENING host:port env alias.

    Greenbone's openvas-scanner container commonly sets
    `LISTENING=0.0.0.0:80` for openvasd. The mock accepts the same variable so
    it can be swapped into compose files without renaming bind settings.
    """

    if not raw:
        return None, None
    match = re.fullmatch(r"(.+):([0-9]+)", raw.strip())
    if not match:
        raise ConfigError("invalid LISTENING: must be host:port")
    host, port_raw = match.groups()
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ConfigError("invalid LISTENING: port must be an integer") from exc
    if port < 1 or port > 65535:
        raise ConfigError("invalid LISTENING: port must be 1..65535")
    return host, port


def _parse_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"invalid {name}: must be an integer") from exc
    if value < minimum or (maximum is not None and value > maximum):
        range_text = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
        raise ConfigError(f"invalid {name}: must be {range_text}")
    return value


def _parse_clock(raw: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError("invalid MOCK_CLOCK_START: must be RFC 3339") from exc
    if value.tzinfo is None:
        raise ConfigError("invalid MOCK_CLOCK_START: timezone is required")
    return value.astimezone(timezone.utc)


def _parse_failure_at(raw: str | None) -> FailureAt | None:
    if not raw:
        return None
    point, sep, count_raw = raw.partition(":")
    if point not in FAILURE_POINTS:
        raise ConfigError(f"invalid MOCK_FAILURE_AT: unsupported point {point!r}")
    if not sep:
        return FailureAt(point)
    try:
        count = int(count_raw)
    except ValueError as exc:
        raise ConfigError("invalid MOCK_FAILURE_AT: count must be an integer") from exc
    if count < 1:
        raise ConfigError("invalid MOCK_FAILURE_AT: count must be >= 1")
    return FailureAt(point, count)


def _parse_optional_path(raw: str | None, name: str) -> str | None:
    if raw is None or raw.strip() == "":
        return None
    path = Path(raw).expanduser()
    if not path.exists():
        return str(path)
    if not path.is_file():
        raise ConfigError(f"invalid {name}: must point to a file")
    return str(path)


def _parse_bool(raw: str, name: str) -> bool:
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"invalid {name}: must be true or false")
