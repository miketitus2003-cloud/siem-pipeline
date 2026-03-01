"""Canonical event schema using dataclasses for type safety and serialization."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class NormalizedEvent:
    """
    Canonical normalized log event.

    All ingested logs are mapped to this schema before any downstream
    processing (rule evaluation, storage, forwarding).
    """

    # --- Identity ---
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_ts: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # --- Time ---
    timestamp: Optional[str] = None          # ISO-8601, UTC preferred

    # --- Network ---
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None

    # --- Identity ---
    username: Optional[str] = None
    hostname: Optional[str] = None

    # --- Event classification ---
    event_type: Optional[str] = None         # e.g. "authentication", "network", "process"
    action: Optional[str] = None             # e.g. "login_failed", "port_scan"
    outcome: Optional[str] = None            # "success" | "failure" | "unknown"
    severity: Optional[str] = None           # "low" | "medium" | "high" | "critical"

    # --- Source metadata ---
    log_source: Optional[str] = None         # "syslog", "windows_event", "cloudtrail", etc.
    raw_message: Optional[str] = None        # original unparsed line (for audit)

    # --- Freeform extensions ---
    extra: dict[str, Any] = field(default_factory=dict)

    # --- MITRE ATT&CK ---
    mitre_technique: Optional[str] = None    # e.g. "T1078"
    mitre_tactic: Optional[str] = None       # e.g. "Initial Access"

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict, omitting None-valued fields."""
        return {k: v for k, v in asdict(self).items() if v is not None and v != {}}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedEvent":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        init_kwargs = {k: v for k, v in data.items() if k in known}
        extra = {k: v for k, v in data.items() if k not in known}
        if extra:
            init_kwargs.setdefault("extra", {}).update(extra)
        return cls(**init_kwargs)
