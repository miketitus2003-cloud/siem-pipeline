"""Tests for the SQLite persistence layer (siem_pipeline/db.py)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from siem_pipeline import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the db module at a fresh temp database for each test."""
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("SIEM_DB_PATH", str(db_file))
    _db.init_db(db_path=db_file)
    return db_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_event(event_id: str = "evt-001") -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2024-03-15T02:00:00+00:00",
        "source_ip": "10.0.0.1",
        "event_type": "authentication",
        "outcome": "failure",
    }


def _sample_alert(rule_id: str = "RULE-1001", severity: str = "high") -> dict:
    return {
        "rule_id": rule_id,
        "rule_name": "Brute Force Login",
        "severity": severity,
        "mitre_technique": "T1110",
        "mitre_tactic": "Credential Access",
        "description": "Multiple failed logins",
        "details": {"failure_count": 5},
        "matched_event": _sample_event(),
    }


# ---------------------------------------------------------------------------
# init_db
# ---------------------------------------------------------------------------

class TestInitDb:
    def test_creates_tables(self, tmp_db: Path):
        import sqlite3
        con = sqlite3.connect(tmp_db)
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        assert "events" in tables
        assert "alerts" in tables

    def test_idempotent(self, tmp_db: Path):
        # Calling init_db again should not raise or lose data
        _db.store_events([_sample_event()], source="test", ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        _db.init_db(db_path=tmp_db)
        rows = _db.query_alerts(db_path=tmp_db)
        assert isinstance(rows, list)


# ---------------------------------------------------------------------------
# store_events
# ---------------------------------------------------------------------------

class TestStoreEvents:
    def test_inserts_event(self, tmp_db: Path):
        n = _db.store_events([_sample_event()], source="test",
                             ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        assert n == 1

    def test_duplicate_event_id_skipped(self, tmp_db: Path):
        ev = _sample_event()
        _db.store_events([ev], source="test", ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        n = _db.store_events([ev], source="test", ingest_ts="2024-01-01T00:00:01+00:00", db_path=tmp_db)
        assert n == 0

    def test_multiple_events(self, tmp_db: Path):
        events = [_sample_event(f"evt-{i}") for i in range(5)]
        n = _db.store_events(events, source="test", ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        assert n == 5

    def test_returns_zero_for_empty_list(self, tmp_db: Path):
        n = _db.store_events([], source="test", ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        assert n == 0


# ---------------------------------------------------------------------------
# store_alerts
# ---------------------------------------------------------------------------

class TestStoreAlerts:
    def test_inserts_alert(self, tmp_db: Path):
        n = _db.store_alerts([_sample_alert()], ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        assert n == 1

    def test_multiple_alerts(self, tmp_db: Path):
        alerts = [_sample_alert(f"RULE-100{i}") for i in range(3)]
        n = _db.store_alerts(alerts, ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        assert n == 3

    def test_alert_details_roundtrip(self, tmp_db: Path):
        _db.store_alerts([_sample_alert()], ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        rows = _db.query_alerts(db_path=tmp_db)
        assert rows[0]["details"]["failure_count"] == 5

    def test_alert_matched_event_roundtrip(self, tmp_db: Path):
        _db.store_alerts([_sample_alert()], ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        rows = _db.query_alerts(db_path=tmp_db)
        assert rows[0]["matched_event"]["source_ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# query_alerts
# ---------------------------------------------------------------------------

class TestQueryAlerts:
    def _seed(self, tmp_db: Path):
        alerts = [
            _sample_alert("RULE-1001", "high"),
            _sample_alert("RULE-1002", "medium"),
            _sample_alert("RULE-1005", "critical"),
        ]
        _db.store_alerts(alerts, ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)

    def test_returns_all_without_filter(self, tmp_db: Path):
        self._seed(tmp_db)
        rows = _db.query_alerts(db_path=tmp_db)
        assert len(rows) == 3

    def test_filter_by_severity(self, tmp_db: Path):
        self._seed(tmp_db)
        rows = _db.query_alerts(severity="high", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["severity"] == "high"

    def test_filter_by_rule_id(self, tmp_db: Path):
        self._seed(tmp_db)
        rows = _db.query_alerts(rule_id="RULE-1005", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "RULE-1005"

    def test_limit_pagination(self, tmp_db: Path):
        alerts = [_sample_alert(f"RULE-{i}", "medium") for i in range(10)]
        _db.store_alerts(alerts, ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        page1 = _db.query_alerts(limit=5, offset=0, db_path=tmp_db)
        page2 = _db.query_alerts(limit=5, offset=5, db_path=tmp_db)
        assert len(page1) == 5
        assert len(page2) == 5
        assert {r["id"] for r in page1}.isdisjoint({r["id"] for r in page2})

    def test_returns_empty_list_when_no_db(self, tmp_path: Path):
        nonexistent = tmp_path / "noexist.db"
        rows = _db.query_alerts(db_path=nonexistent)
        assert rows == []

    def test_combined_filters(self, tmp_db: Path):
        self._seed(tmp_db)
        rows = _db.query_alerts(severity="medium", rule_id="RULE-1002", db_path=tmp_db)
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# query_stats
# ---------------------------------------------------------------------------

class TestQueryStats:
    def test_returns_zeros_when_no_db(self, tmp_path: Path):
        nonexistent = tmp_path / "noexist.db"
        stats = _db.query_stats(db_path=nonexistent)
        assert stats["total_events"] == 0
        assert stats["total_alerts"] == 0

    def test_counts_match_inserts(self, tmp_db: Path):
        events = [_sample_event(f"e{i}") for i in range(4)]
        alerts = [_sample_alert("RULE-1001", "high"), _sample_alert("RULE-1005", "critical")]
        _db.store_events(events, source="test", ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        _db.store_alerts(alerts, ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        stats = _db.query_stats(db_path=tmp_db)
        assert stats["total_events"] == 4
        assert stats["total_alerts"] == 2

    def test_alerts_by_severity_breakdown(self, tmp_db: Path):
        alerts = [
            _sample_alert("RULE-1001", "high"),
            _sample_alert("RULE-1001", "high"),
            _sample_alert("RULE-1005", "critical"),
        ]
        _db.store_alerts(alerts, ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        stats = _db.query_stats(db_path=tmp_db)
        assert stats["alerts_by_severity"]["high"] == 2
        assert stats["alerts_by_severity"]["critical"] == 1

    def test_alerts_by_rule_breakdown(self, tmp_db: Path):
        alerts = [
            _sample_alert("RULE-1001", "high"),
            _sample_alert("RULE-1001", "high"),
        ]
        _db.store_alerts(alerts, ingest_ts="2024-01-01T00:00:00+00:00", db_path=tmp_db)
        stats = _db.query_stats(db_path=tmp_db)
        assert stats["alerts_by_rule"]["Brute Force Login"] == 2
