"""Unit tests for detection rules and the rule engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from siem_pipeline.rules.builtin_rules import (
    BruteForceLoginRule,
    MultiSourceLoginRule,
    PortScanRule,
    PrivilegedAfterHoursRule,
    WatchlistIPRule,
)
from siem_pipeline.rules.engine import RuleEngine
from siem_pipeline.utils.schema import NormalizedEvent


def _auth_event(
    outcome: str,
    source_ip: str = "10.0.0.1",
    username: str = "alice",
    timestamp: str = "2024-03-15T02:00:00+00:00",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_type="authentication",
        outcome=outcome,
        source_ip=source_ip,
        username=username,
        timestamp=timestamp,
    )


# ===========================================================================
# BruteForceLoginRule
# ===========================================================================

class TestBruteForceLoginRule:
    def _make_rule(self):
        rule = BruteForceLoginRule()
        rule.THRESHOLD = 3
        return rule

    def test_no_match_below_threshold(self):
        rule = self._make_rule()
        events = [_auth_event("failure") for _ in range(2)]
        matches = [rule.evaluate(e) for e in events]
        assert all(m is None for m in matches)

    def test_fires_at_threshold(self):
        rule = self._make_rule()
        events = [_auth_event("failure") for _ in range(3)]
        last = None
        for e in events:
            last = rule.evaluate(e)
        assert last is not None
        assert last.rule_id == "RULE-1001"
        assert last.details["failure_count"] >= 3

    def test_success_events_ignored(self):
        rule = self._make_rule()
        events = [_auth_event("success") for _ in range(10)]
        matches = [rule.evaluate(e) for e in events]
        assert all(m is None for m in matches)

    def test_different_ips_tracked_separately(self):
        rule = self._make_rule()
        events_a = [_auth_event("failure", source_ip="10.0.0.1") for _ in range(2)]
        events_b = [_auth_event("failure", source_ip="10.0.0.2") for _ in range(2)]
        all_matches = [rule.evaluate(e) for e in events_a + events_b]
        assert all(m is None for m in all_matches)

    def test_no_match_when_no_source_ip(self):
        rule = self._make_rule()
        event = NormalizedEvent(event_type="authentication", outcome="failure")
        assert rule.evaluate(event) is None

    def test_mitre_metadata(self):
        rule = BruteForceLoginRule()
        assert rule.mitre_technique == "T1110"
        assert rule.mitre_tactic == "Credential Access"


# ===========================================================================
# MultiSourceLoginRule
# ===========================================================================

class TestMultiSourceLoginRule:
    def _make_rule(self):
        rule = MultiSourceLoginRule()
        rule.THRESHOLD_IPS = 3
        return rule

    def test_no_match_below_threshold(self):
        rule = self._make_rule()
        ips = ["10.0.0.1", "10.0.0.2"]
        for ip in ips:
            result = rule.evaluate(_auth_event("success", source_ip=ip, username="bob"))
        assert result is None

    def test_fires_at_threshold(self):
        rule = self._make_rule()
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        last = None
        for ip in ips:
            last = rule.evaluate(_auth_event("success", source_ip=ip, username="bob"))
        assert last is not None
        assert last.rule_id == "RULE-1002"
        assert len(last.details["distinct_ips"]) >= 3

    def test_only_success_events_counted(self):
        rule = self._make_rule()
        for i in range(5):
            result = rule.evaluate(_auth_event("failure", source_ip=f"10.0.0.{i}", username="charlie"))
        assert result is None


# ===========================================================================
# PortScanRule
# ===========================================================================

class TestPortScanRule:
    def _make_rule(self):
        rule = PortScanRule()
        rule.THRESHOLD_PORTS = 5
        return rule

    def test_no_match_below_threshold(self):
        rule = self._make_rule()
        for port in range(4):
            result = rule.evaluate(
                NormalizedEvent(source_ip="10.0.0.1", dest_port=port,
                                timestamp="2024-03-15T08:00:00+00:00")
            )
        assert result is None

    def test_fires_at_threshold(self):
        rule = self._make_rule()
        last = None
        for port in range(5):
            last = rule.evaluate(
                NormalizedEvent(source_ip="10.0.0.1", dest_port=port,
                                timestamp="2024-03-15T08:00:00+00:00")
            )
        assert last is not None
        assert last.rule_id == "RULE-1003"

    def test_no_source_ip_ignored(self):
        rule = self._make_rule()
        for port in range(10):
            result = rule.evaluate(NormalizedEvent(dest_port=port))
        assert result is None

    def test_mitre_metadata(self):
        assert PortScanRule.mitre_technique == "T1046"
        assert PortScanRule.mitre_tactic == "Discovery"


# ===========================================================================
# PrivilegedAfterHoursRule
# ===========================================================================

class TestPrivilegedAfterHoursRule:
    rule = PrivilegedAfterHoursRule()

    @pytest.mark.parametrize("hour,fires", [
        (3, True),    # 03:00 UTC — outside hours
        (23, True),   # 23:00 UTC — outside hours
        (9, False),   # 09:00 UTC — within hours
        (19, False),  # 19:00 UTC — within hours
    ])
    def test_hour_based_firing(self, hour, fires):
        ts = f"2024-03-15T{hour:02d}:00:00+00:00"
        event = NormalizedEvent(
            event_type="authentication",
            outcome="success",
            username="admin",
            timestamp=ts,
        )
        result = self.rule.evaluate(event)
        assert (result is not None) == fires

    def test_non_privileged_user_ignored(self):
        event = NormalizedEvent(
            outcome="success",
            username="regular_user",
            timestamp="2024-03-15T03:00:00+00:00",
        )
        assert self.rule.evaluate(event) is None

    def test_failure_outcome_ignored(self):
        event = NormalizedEvent(
            outcome="failure",
            username="admin",
            timestamp="2024-03-15T03:00:00+00:00",
        )
        assert self.rule.evaluate(event) is None

    @pytest.mark.parametrize("username", ["admin", "root", "svc_deploy", "administrator"])
    def test_privileged_patterns_detected(self, username):
        event = NormalizedEvent(
            outcome="success",
            username=username,
            timestamp="2024-03-15T03:00:00+00:00",
        )
        result = self.rule.evaluate(event)
        assert result is not None


# ===========================================================================
# WatchlistIPRule
# ===========================================================================

class TestWatchlistIPRule:
    rule = WatchlistIPRule()

    def test_watchlist_source_ip_fires(self):
        event = NormalizedEvent(source_ip="192.0.2.1")
        result = self.rule.evaluate(event)
        assert result is not None
        assert result.rule_id == "RULE-1005"
        assert result.severity == "critical"

    def test_watchlist_dest_ip_fires(self):
        event = NormalizedEvent(source_ip="10.0.0.1", dest_ip="203.0.113.99")
        result = self.rule.evaluate(event)
        assert result is not None

    def test_clean_ip_no_match(self):
        event = NormalizedEvent(source_ip="10.0.0.200", dest_ip="8.8.8.8")
        result = self.rule.evaluate(event)
        assert result is None

    def test_mitre_metadata(self):
        assert WatchlistIPRule.mitre_technique == "T1071"
        assert WatchlistIPRule.mitre_tactic == "Command and Control"


# ===========================================================================
# RuleEngine
# ===========================================================================

class TestRuleEngine:
    def test_load_builtin_rules(self):
        engine = RuleEngine()
        engine.load_builtin_rules()
        assert len(engine.rules) >= 5

    def test_run_yields_matches(self):
        engine = RuleEngine()
        engine.load_builtin_rules()
        events = [NormalizedEvent(source_ip="192.0.2.1")]
        matches = list(engine.run(iter(events)))
        assert any(m.rule_id == "RULE-1005" for m in matches)

    def test_run_empty_events(self):
        engine = RuleEngine()
        engine.load_builtin_rules()
        matches = list(engine.run(iter([])))
        assert matches == []

    def test_no_rules_loaded_yields_nothing(self):
        engine = RuleEngine()
        events = [NormalizedEvent(source_ip="192.0.2.1")]
        matches = list(engine.run(iter(events)))
        assert matches == []

    def test_match_has_all_metadata_fields(self):
        engine = RuleEngine()
        engine.load_builtin_rules()
        events = [NormalizedEvent(source_ip="192.0.2.1")]
        matches = list(engine.run(iter(events)))
        m = matches[0]
        assert m.rule_id
        assert m.rule_name
        assert m.severity
        d = m.to_dict()
        assert "matched_event" in d
        assert "mitre_technique" in d
