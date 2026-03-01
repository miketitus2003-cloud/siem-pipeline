"""
Built-in detection rules.

Each rule is a self-contained class.  The RuleEngine auto-discovers all
BaseRule subclasses defined in this module via __subclasses__().

MITRE ATT&CK references are embedded as class-level metadata.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from .base import BaseRule, RuleMatch
from ..utils.schema import NormalizedEvent

# ---------------------------------------------------------------------------
# Helper: parse ISO timestamp safely
# ---------------------------------------------------------------------------

def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if ts is None:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


# ===========================================================================
# Rule 1 — Brute-Force / Repeated Failed Logins
# T1110 — Brute Force
# ===========================================================================

class BruteForceLoginRule(BaseRule):
    """
    Fires when the same source_ip has ≥ N failed authentication events
    within a rolling time window.
    """

    id = "RULE-1001"
    name = "Brute Force Login Detected"
    description = (
        "Multiple consecutive authentication failures from the same source IP "
        "suggest a brute-force attack."
    )
    severity = "high"
    mitre_technique = "T1110"
    mitre_tactic = "Credential Access"

    THRESHOLD = 5          # failures to trigger
    WINDOW_SECONDS = 300   # 5-minute rolling window

    def __init__(self) -> None:
        # ip -> deque of failure timestamps
        self._failures: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.THRESHOLD * 2)
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if event.event_type not in ("authentication", "auth", "login"):
            return None
        if event.outcome != "failure":
            return None
        if not event.source_ip:
            return None

        now = _parse_ts(event.timestamp) or datetime.now(timezone.utc)
        bucket = self._failures[event.source_ip]
        bucket.append(now)

        # Count failures within the window
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)
        recent = [t for t in bucket if t >= cutoff]

        if len(recent) >= self.THRESHOLD:
            return self._match(
                event,
                failure_count=len(recent),
                window_seconds=self.WINDOW_SECONDS,
                source_ip=event.source_ip,
                targeted_user=event.username,
            )
        return None


# ===========================================================================
# Rule 2 — Impossible Travel / Authentication from New Country
# (simplified: flags logins from >1 distinct IP for same user in short window)
# T1078 — Valid Accounts
# ===========================================================================

class MultiSourceLoginRule(BaseRule):
    """
    Fires when the same username authenticates successfully from
    more than N distinct source IPs within a rolling window.
    This is a lightweight proxy for impossible-travel detection.
    """

    id = "RULE-1002"
    name = "Authentication from Multiple Source IPs"
    description = (
        "A single account authenticated successfully from multiple distinct "
        "source IPs in a short window — possible credential sharing or compromise."
    )
    severity = "medium"
    mitre_technique = "T1078"
    mitre_tactic = "Initial Access"

    THRESHOLD_IPS = 3
    WINDOW_SECONDS = 600   # 10-minute window

    def __init__(self) -> None:
        # username -> list of (timestamp, ip) tuples
        self._logins: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if event.event_type not in ("authentication", "auth", "login"):
            return None
        if event.outcome != "success":
            return None
        if not event.username or not event.source_ip:
            return None

        now = _parse_ts(event.timestamp) or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        history = self._logins[event.username]
        history.append((now, event.source_ip))

        # Prune old entries
        history[:] = [(t, ip) for t, ip in history if t >= cutoff]

        distinct_ips = {ip for _, ip in history}
        if len(distinct_ips) >= self.THRESHOLD_IPS:
            return self._match(
                event,
                username=event.username,
                distinct_ips=sorted(distinct_ips),
                count=len(distinct_ips),
                window_seconds=self.WINDOW_SECONDS,
            )
        return None


# ===========================================================================
# Rule 3 — Port Scan Detection
# T1046 — Network Service Discovery
# ===========================================================================

class PortScanRule(BaseRule):
    """
    Fires when a single source IP contacts more than N distinct destination
    ports within a short time window — classic horizontal port scan signature.
    """

    id = "RULE-1003"
    name = "Port Scan Detected"
    description = (
        "A single source IP contacted an unusually high number of distinct "
        "destination ports, indicating possible port scanning activity."
    )
    severity = "medium"
    mitre_technique = "T1046"
    mitre_tactic = "Discovery"

    THRESHOLD_PORTS = 15
    WINDOW_SECONDS = 60

    def __init__(self) -> None:
        # src_ip -> list of (timestamp, dest_port)
        self._contacts: dict[str, list[tuple[datetime, int]]] = defaultdict(list)

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not event.source_ip or event.dest_port is None:
            return None

        now = _parse_ts(event.timestamp) or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        history = self._contacts[event.source_ip]
        history.append((now, event.dest_port))
        history[:] = [(t, p) for t, p in history if t >= cutoff]

        distinct_ports = {p for _, p in history}
        if len(distinct_ports) >= self.THRESHOLD_PORTS:
            return self._match(
                event,
                source_ip=event.source_ip,
                distinct_ports_count=len(distinct_ports),
                sample_ports=sorted(distinct_ports)[:20],
                window_seconds=self.WINDOW_SECONDS,
            )
        return None


# ===========================================================================
# Rule 4 — Privileged Account Usage Outside Business Hours
# T1078.003 — Valid Accounts: Local Accounts
# ===========================================================================

class PrivilegedAfterHoursRule(BaseRule):
    """
    Fires when a privileged-sounding account authenticates successfully
    outside of 06:00–20:00 UTC.  Extend with an account allowlist as needed.
    """

    id = "RULE-1004"
    name = "Privileged Account Login Outside Business Hours"
    description = (
        "A privileged account authenticated outside normal business hours, "
        "which may indicate unauthorized access or insider threat activity."
    )
    severity = "high"
    mitre_technique = "T1078.003"
    mitre_tactic = "Persistence"

    PRIVILEGED_PATTERNS = ("admin", "root", "administrator", "svc_", "service_", "sa_")
    WORK_HOUR_START = 6   # UTC
    WORK_HOUR_END = 20    # UTC

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if event.outcome != "success":
            return None
        if not event.username:
            return None

        uname = event.username.lower()
        is_privileged = any(uname.startswith(p) or p in uname for p in self.PRIVILEGED_PATTERNS)
        if not is_privileged:
            return None

        ts = _parse_ts(event.timestamp)
        if ts is None:
            return None

        hour = ts.hour  # UTC
        if not (self.WORK_HOUR_START <= hour < self.WORK_HOUR_END):
            return self._match(
                event,
                username=event.username,
                login_hour_utc=hour,
                business_hours=f"{self.WORK_HOUR_START:02d}:00-{self.WORK_HOUR_END:02d}:00 UTC",
            )
        return None


# ===========================================================================
# Rule 5 — Known Malicious / Watchlist IP
# T1071 — Application Layer Protocol
# ===========================================================================

class WatchlistIPRule(BaseRule):
    """
    Fires when an event's source_ip appears in a configurable watchlist.
    In production this would pull from threat-intel feeds (STIX/TAXII, etc.).
    """

    id = "RULE-1005"
    name = "Traffic from Watchlist IP"
    description = (
        "Network activity was observed from/to an IP address on the threat "
        "intelligence watchlist."
    )
    severity = "critical"
    mitre_technique = "T1071"
    mitre_tactic = "Command and Control"

    # Extend this set from a config file or threat-intel API in production
    WATCHLIST: frozenset[str] = frozenset(
        {
            "192.0.2.1",    # RFC 5737 documentation range — safe placeholder
            "198.51.100.5",
            "203.0.113.99",
            "10.0.0.254",   # Demo internal pivot IP
        }
    )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        for ip_field in (event.source_ip, event.dest_ip):
            if ip_field and ip_field in self.WATCHLIST:
                return self._match(
                    event,
                    matched_ip=ip_field,
                    watchlist_size=len(self.WATCHLIST),
                )
        return None
