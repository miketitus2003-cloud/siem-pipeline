"""
SQLite persistence layer for the SIEM Pipeline.

Stores normalized events and rule-match alerts so the API can answer
historical queries without re-running the pipeline on every request.

Schema
------
  events  — one row per NormalizedEvent ingested via POST /ingest
  alerts  — one row per RuleMatch produced during ingestion

Both tables are append-only; no update/delete logic is intentional.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

_DEFAULT_DB_PATH = Path("siem_pipeline.db")


def get_db_path() -> Path:
    """Return the active DB path (overridable in tests via env var)."""
    import os
    env = os.environ.get("SIEM_DB_PATH")
    return Path(env) if env else _DEFAULT_DB_PATH


@contextmanager
def _conn(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT UNIQUE NOT NULL,
    ingest_ts   TEXT NOT NULL,
    source      TEXT,
    payload     TEXT NOT NULL   -- JSON-serialized NormalizedEvent
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_ts        TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    mitre_technique TEXT,
    mitre_tactic    TEXT,
    description     TEXT,
    details         TEXT,       -- JSON
    matched_event   TEXT,       -- JSON NormalizedEvent
    event_id        TEXT        -- FK → events.event_id
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id    ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_ts   ON alerts(alert_ts);
CREATE INDEX IF NOT EXISTS idx_events_event_id   ON events(event_id);
"""


def init_db(db_path: Optional[Path] = None) -> None:
    """Create tables if they don't exist."""
    path = db_path or get_db_path()
    with _conn(path) as con:
        con.executescript(_DDL)


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def store_events(events: list[dict], source: str, ingest_ts: str,
                 db_path: Optional[Path] = None) -> int:
    """
    Persist a list of NormalizedEvent dicts.

    Returns the number of rows inserted (duplicates by event_id are skipped).
    """
    path = db_path or get_db_path()
    inserted = 0
    with _conn(path) as con:
        for ev in events:
            try:
                con.execute(
                    "INSERT OR IGNORE INTO events (event_id, ingest_ts, source, payload) "
                    "VALUES (?, ?, ?, ?)",
                    (ev.get("event_id", ""), ingest_ts, source, json.dumps(ev)),
                )
                inserted += con.execute("SELECT changes()").fetchone()[0]
            except sqlite3.Error:
                continue
    return inserted


def store_alerts(alerts: list[dict], ingest_ts: str,
                 db_path: Optional[Path] = None) -> int:
    """
    Persist a list of RuleMatch dicts.

    Returns the number of rows inserted.
    """
    path = db_path or get_db_path()
    inserted = 0
    with _conn(path) as con:
        for al in alerts:
            matched = al.get("matched_event", {})
            con.execute(
                "INSERT INTO alerts "
                "(alert_ts, rule_id, rule_name, severity, mitre_technique, "
                " mitre_tactic, description, details, matched_event, event_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ingest_ts,
                    al.get("rule_id", ""),
                    al.get("rule_name", ""),
                    al.get("severity", ""),
                    al.get("mitre_technique"),
                    al.get("mitre_tactic"),
                    al.get("description", ""),
                    json.dumps(al.get("details", {})),
                    json.dumps(matched),
                    matched.get("event_id", ""),
                ),
            )
            inserted += 1
    return inserted


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------

def query_alerts(
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[Path] = None,
) -> list[dict]:
    """Return stored alerts with optional filters."""
    path = db_path or get_db_path()
    if not path.exists():
        return []

    clauses: list[str] = []
    params: list = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity.lower())
    if rule_id:
        clauses.append("rule_id = ?")
        params.append(rule_id)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        f"SELECT * FROM alerts {where} "
        f"ORDER BY id DESC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])

    with _conn(path) as con:
        rows = con.execute(sql, params).fetchall()

    result = []
    for row in rows:
        d = dict(row)
        d["details"] = json.loads(d["details"] or "{}")
        d["matched_event"] = json.loads(d["matched_event"] or "{}")
        result.append(d)
    return result


def query_stats(db_path: Optional[Path] = None) -> dict:
    """Return aggregate counts from the DB."""
    path = db_path or get_db_path()
    if not path.exists():
        return {"total_events": 0, "total_alerts": 0,
                "alerts_by_severity": {}, "alerts_by_rule": {}}

    with _conn(path) as con:
        total_events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

        by_sev = con.execute(
            "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity"
        ).fetchall()
        by_rule = con.execute(
            "SELECT rule_name, COUNT(*) AS cnt FROM alerts GROUP BY rule_name"
        ).fetchall()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "alerts_by_severity": {r["severity"]: r["cnt"] for r in by_sev},
        "alerts_by_rule": {r["rule_name"]: r["cnt"] for r in by_rule},
    }
