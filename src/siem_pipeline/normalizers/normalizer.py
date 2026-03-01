"""
LogNormalizer — maps raw parsed dicts to the canonical NormalizedEvent schema.

Field mapping is driven by two mechanisms:
  1. A static FIELD_MAP that covers common vendor field names.
  2. Per-log-source transform functions for more complex mappings.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable

from ..utils.schema import NormalizedEvent
from ..utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Field alias map: raw_field_name -> canonical_field_name
# Extend this to cover additional vendors / log formats.
# ---------------------------------------------------------------------------
FIELD_MAP: dict[str, str] = {
    # Timestamps
    "time": "timestamp",
    "datetime": "timestamp",
    "event_time": "timestamp",
    "@timestamp": "timestamp",
    "ts": "timestamp",
    "date": "timestamp",
    # Source IP
    "src_ip": "source_ip",
    "srcip": "source_ip",
    "src": "source_ip",
    "client_ip": "source_ip",
    "remoteip": "source_ip",
    "remote_addr": "source_ip",
    # Dest IP
    "dst_ip": "dest_ip",
    "dstip": "dest_ip",
    "dst": "dest_ip",
    "server_ip": "dest_ip",
    "destination_ip": "dest_ip",
    # Ports
    "src_port": "source_port",
    "srcport": "source_port",
    "dst_port": "dest_port",
    "dstport": "dest_port",
    "port": "dest_port",
    # User
    "user": "username",
    "user_name": "username",
    "account": "username",
    "logon_user": "username",
    "login": "username",
    # Host
    "host": "hostname",
    "computer": "hostname",
    "device": "hostname",
    "machine": "hostname",
    # Action / outcome
    "event": "action",
    "action_type": "action",
    "activity": "action",
    "result": "outcome",
    "status": "outcome",
    "auth_result": "outcome",
    # Classification
    "type": "event_type",
    "category": "event_type",
    "log_type": "event_type",
    # Severity
    "level": "severity",
    "priority": "severity",
    "criticality": "severity",
    # Message / raw
    "message": "raw_message",
    "msg": "raw_message",
    "log": "raw_message",
    "description": "raw_message",
}

# Canonical severity levels (normalise to these)
SEVERITY_MAP: dict[str, str] = {
    "0": "critical", "1": "critical",
    "2": "high",     "3": "high",
    "4": "medium",   "5": "medium",
    "6": "low",      "7": "low",
    "critical": "critical", "crit": "critical",
    "error": "high",  "err": "high",
    "warning": "medium", "warn": "medium",
    "notice": "low",
    "info": "low",    "information": "low",
    "debug": "low",
}

# Outcome normalisation
OUTCOME_MAP: dict[str, str] = {
    "success": "success", "succeeded": "success", "ok": "success",
    "200": "success", "accepted": "success", "allowed": "success",
    "failure": "failure", "failed": "failure", "fail": "failure",
    "denied": "failure", "rejected": "failure", "blocked": "failure",
    "error": "failure", "unauthorized": "failure",
}

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%d/%b/%Y:%H:%M:%S %z",   # Apache CLF
    "%b %d %H:%M:%S",          # syslog (no year)
]


def _parse_timestamp(raw: Any) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        # Unix epoch seconds or milliseconds
        ts = raw if raw < 1e12 else raw / 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (OSError, ValueError, OverflowError):
            return None
    s = str(raw).strip()
    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    logger.debug("Could not parse timestamp: %r", raw)
    return s  # return raw string rather than drop it


def _validate_ip(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    # Strip IPv6-mapped prefix if present
    if s.startswith("::ffff:"):
        s = s[7:]
    if _IP_RE.match(s):
        return s
    logger.debug("Invalid IP address discarded: %r", value)
    return None


def _normalise_severity(value: Any) -> str | None:
    if value is None:
        return None
    return SEVERITY_MAP.get(str(value).lower().strip())


def _normalise_outcome(value: Any) -> str | None:
    if value is None:
        return None
    return OUTCOME_MAP.get(str(value).lower().strip(), "unknown")


class LogNormalizer:
    """
    Converts a raw parsed dict into a NormalizedEvent.

    Usage::

        normalizer = LogNormalizer(log_source="cloudtrail")
        event = normalizer.normalize(raw_dict)
    """

    def __init__(self, log_source: str = "unknown") -> None:
        self.log_source = log_source

    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent:
        mapped = self._apply_field_map(raw)

        event = NormalizedEvent(
            log_source=self.log_source,
            timestamp=_parse_timestamp(mapped.pop("timestamp", None)),
            source_ip=_validate_ip(mapped.pop("source_ip", None)),
            dest_ip=_validate_ip(mapped.pop("dest_ip", None)),
            source_port=self._coerce_port(mapped.pop("source_port", None)),
            dest_port=self._coerce_port(mapped.pop("dest_port", None)),
            protocol=self._coerce_str(mapped.pop("protocol", None)),
            username=self._coerce_str(mapped.pop("username", None)),
            hostname=self._coerce_str(mapped.pop("hostname", None)),
            event_type=self._coerce_str(mapped.pop("event_type", None)),
            action=self._coerce_str(mapped.pop("action", None)),
            outcome=_normalise_outcome(mapped.pop("outcome", None)),
            severity=_normalise_severity(mapped.pop("severity", None)),
            raw_message=self._coerce_str(mapped.pop("raw_message", None)),
            extra=mapped,  # all unmapped fields land here
        )
        return event

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_field_map(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Return a new dict with canonical field names, preserving unknowns."""
        result: dict[str, Any] = {}
        for key, value in raw.items():
            canonical = FIELD_MAP.get(key.lower().strip(), key)
            # Last-write wins when two aliases map to the same canonical key
            result[canonical] = value
        return result

    @staticmethod
    def _coerce_port(value: Any) -> int | None:
        if value is None:
            return None
        try:
            port = int(value)
            return port if 0 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _coerce_str(value: Any) -> str | None:
        if value is None:
            return None
        s = str(value).strip()
        return s if s else None
