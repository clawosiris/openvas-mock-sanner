"""Runtime configuration for the compatibility mock scanner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
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
}

FAILURE_POINTS = {"create", "start", "status", "results", "delete"}


class ConfigError(ValueError):
    """Raised when environment configuration is invalid."""


@dataclass(frozen=True)
class FailureAt:
    point: str
    count: int | None = None


@dataclass(frozen=True)
class Config:
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


def load_config(env: Mapping[str, str] | None = None) -> Config:
    source = os.environ if env is None else env
    scenario = source.get("MOCK_SCENARIO", "success-basic")
    if scenario not in SCENARIOS:
        raise ConfigError(f"invalid MOCK_SCENARIO: {scenario!r}")

    defaults = _scenario_defaults(scenario)
    return Config(
        host=source.get("MOCK_HOST", "127.0.0.1"),
        port=_parse_int(source, "MOCK_PORT", 8080, minimum=1, maximum=65535),
        scenario=scenario,
        page_size=_parse_int(source, "MOCK_PAGE_SIZE", 100, minimum=1),
        failure_at=_parse_failure_at(source.get("MOCK_FAILURE_AT")),
        clock_start=_parse_clock(source.get("MOCK_CLOCK_START", "2026-01-01T00:00:00Z")),
        latency_ms=_parse_int(source, "MOCK_LATENCY_MS", 0, minimum=0),
        result_count=_parse_int(source, "MOCK_RESULT_COUNT", defaults["result_count"], minimum=0),
        host_count=_parse_int(source, "MOCK_HOST_COUNT", defaults["host_count"], minimum=1),
        seed=source.get("MOCK_SEED", "compat"),
    )


def _scenario_defaults(scenario: str) -> dict[str, int]:
    if scenario == "success-large-report":
        return {"result_count": 250, "host_count": 25}
    if scenario == "empty-report":
        return {"result_count": 0, "host_count": 1}
    return {"result_count": 12, "host_count": 3}


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
