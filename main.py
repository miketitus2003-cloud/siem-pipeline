"""
FastAPI entry point for the SIEM Pipeline API.
Start command: uvicorn main:app --host 0.0.0.0 --port $PORT
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from siem_pipeline.pipeline import Pipeline

app = FastAPI(
    title="SIEM Pipeline API",
    description=(
        "A production-style security information and event management pipeline. "
        "Ingests multi-format log sources, normalizes events to a common schema, "
        "and applies MITRE ATT&CK-mapped detection rules in real time.\n\n"
        "**Source:** [github.com/miketitus2003-cloud/siem-pipeline]"
        "(https://github.com/miketitus2003-cloud/siem-pipeline)"
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    version: str


class RuleInfo(BaseModel):
    id: str
    name: str
    severity: str
    mitre_tactic: str | None
    mitre_technique: str | None


class RulesResponse(BaseModel):
    count: int
    rules: list[RuleInfo]


class PipelineSummary(BaseModel):
    total_events: int
    total_alerts: int
    alerts_by_severity: dict[str, int]
    alerts_by_rule: dict[str, int]


class RunResponse(BaseModel):
    summary: PipelineSummary
    alerts: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------

_LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SIEM Pipeline</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0d1117;
      color: #e6edf3;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 2rem;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      max-width: 720px;
      width: 100%;
      padding: 2.5rem 3rem;
    }
    .badge {
      display: inline-block;
      background: #1f6feb22;
      border: 1px solid #1f6feb55;
      color: #58a6ff;
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 0.25rem 0.75rem;
      border-radius: 20px;
      margin-bottom: 1.25rem;
    }
    h1 {
      font-size: 2rem;
      font-weight: 700;
      color: #f0f6fc;
      margin-bottom: 0.75rem;
      letter-spacing: -0.02em;
    }
    .subtitle {
      color: #8b949e;
      font-size: 1rem;
      line-height: 1.6;
      margin-bottom: 2rem;
    }
    .features {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
      margin-bottom: 2rem;
    }
    .feature {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 0.85rem 1rem;
      font-size: 0.875rem;
    }
    .feature .icon { margin-right: 0.5rem; }
    .feature .label { color: #f0f6fc; font-weight: 500; }
    .feature .detail { color: #8b949e; font-size: 0.8rem; margin-top: 0.2rem; }
    .rules-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
      margin-bottom: 2rem;
    }
    .rules-table th {
      text-align: left;
      color: #8b949e;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-size: 0.72rem;
      padding: 0 0.75rem 0.6rem;
      border-bottom: 1px solid #21262d;
    }
    .rules-table td {
      padding: 0.55rem 0.75rem;
      border-bottom: 1px solid #21262d;
      color: #c9d1d9;
    }
    .rules-table tr:last-child td { border-bottom: none; }
    .sev {
      display: inline-block;
      padding: 0.15rem 0.55rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .sev-critical { background: #490202; color: #ff7b72; }
    .sev-high     { background: #3d1a00; color: #f0883e; }
    .sev-medium   { background: #2d2a00; color: #e3b341; }
    .actions {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .btn {
      display: inline-block;
      padding: 0.6rem 1.25rem;
      border-radius: 6px;
      font-size: 0.875rem;
      font-weight: 500;
      text-decoration: none;
      transition: opacity 0.15s;
    }
    .btn:hover { opacity: 0.85; }
    .btn-primary { background: #238636; color: #fff; }
    .btn-secondary {
      background: transparent;
      border: 1px solid #30363d;
      color: #c9d1d9;
    }
    .footer {
      margin-top: 2rem;
      color: #484f58;
      font-size: 0.78rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Security Engineering Portfolio</div>
    <h1>SIEM Pipeline</h1>
    <p class="subtitle">
      A production-style security information and event management pipeline.
      Ingests multi-format log sources, normalizes events to a common schema,
      and applies MITRE ATT&amp;CK-mapped detection rules in real time.
    </p>
    <div class="features">
      <div class="feature">
        <div><span class="icon">&#x26A1;</span><span class="label">Multi-Format Ingestion</span></div>
        <div class="detail">JSON, JSONL, CSV log sources</div>
      </div>
      <div class="feature">
        <div><span class="icon">&#x1F50D;</span><span class="label">5 Detection Rules</span></div>
        <div class="detail">MITRE ATT&amp;CK mapped, extensible</div>
      </div>
      <div class="feature">
        <div><span class="icon">&#x1F4CB;</span><span class="label">Schema Normalization</span></div>
        <div class="detail">Common event model across sources</div>
      </div>
      <div class="feature">
        <div><span class="icon">&#x1F4E1;</span><span class="label">REST API</span></div>
        <div class="detail">FastAPI + auto-generated docs</div>
      </div>
    </div>
    <table class="rules-table">
      <thead>
        <tr>
          <th>Rule</th>
          <th>Severity</th>
          <th>MITRE Technique</th>
          <th>Tactic</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Brute Force Login</td>
          <td><span class="sev sev-high">High</span></td>
          <td>T1110</td>
          <td>Credential Access</td>
        </tr>
        <tr>
          <td>Multi-Source Auth</td>
          <td><span class="sev sev-medium">Medium</span></td>
          <td>T1078</td>
          <td>Initial Access</td>
        </tr>
        <tr>
          <td>Port Scan</td>
          <td><span class="sev sev-medium">Medium</span></td>
          <td>T1046</td>
          <td>Discovery</td>
        </tr>
        <tr>
          <td>Privileged After-Hours Login</td>
          <td><span class="sev sev-high">High</span></td>
          <td>T1078.003</td>
          <td>Persistence</td>
        </tr>
        <tr>
          <td>Watchlist IP Traffic</td>
          <td><span class="sev sev-critical">Critical</span></td>
          <td>T1071</td>
          <td>Command &amp; Control</td>
        </tr>
      </tbody>
    </table>
    <div class="actions">
      <a href="/docs" class="btn btn-primary">Explore API Docs</a>
      <a href="/docs#/Detection/run_pipeline_run_post" class="btn btn-secondary">Try /run</a>
      <a href="https://github.com/miketitus2003-cloud/siem-pipeline" class="btn btn-secondary">GitHub</a>
    </div>
  </div>
  <div class="footer">Built with FastAPI &nbsp;&middot;&nbsp; Deployed on Railway &nbsp;&middot;&nbsp; Python 3.11</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing():
    return _LANDING_HTML


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns service status. Used by Railway and uptime monitors.",
    tags=["System"],
)
def health():
    return HealthResponse(status="ok", version=app.version)


@app.get(
    "/rules",
    response_model=RulesResponse,
    summary="List detection rules",
    description=(
        "Returns all loaded detection rules with their MITRE ATT&CK technique "
        "and tactic mappings, severity level, and unique rule ID."
    ),
    tags=["Detection"],
)
def list_rules():
    from siem_pipeline.rules.engine import RuleEngine

    engine = RuleEngine()
    engine.load_builtin_rules()
    rules = [
        RuleInfo(
            id=r.id,
            name=r.name,
            severity=r.severity,
            mitre_tactic=r.mitre_tactic,
            mitre_technique=r.mitre_technique,
        )
        for r in engine.rules
    ]
    return RulesResponse(count=len(rules), rules=rules)


@app.post(
    "/run",
    response_model=RunResponse,
    summary="Run the detection pipeline",
    description=(
        "Parses the bundled sample log files (`data/raw/`), normalizes every event "
        "to the canonical schema, evaluates all detection rules, and returns a "
        "summary plus the full list of triggered alerts with matched event details.\n\n"
        "**Sample data includes:** `auth_logs.json`, `firewall_logs.csv`, "
        "`cloudtrail_sample.jsonl`"
    ),
    tags=["Detection"],
)
def run_pipeline(source: str = "demo"):
    data_dir = Path("data/raw")
    if not data_dir.exists():
        raise HTTPException(status_code=404, detail="data/raw directory not found")

    pipeline = Pipeline(log_source=source, enable_rules=True)
    input_paths = [p for p in data_dir.iterdir() if p.is_file()]

    if not input_paths:
        raise HTTPException(status_code=404, detail="No log files found in data/raw")

    summary, _events, matches = pipeline.run(input_paths)

    return RunResponse(
        summary=PipelineSummary(**summary),
        alerts=[m.to_dict() for m in matches],
    )


class EventsResponse(BaseModel):
    count: int
    events: list[dict[str, Any]]


@app.get(
    "/events",
    response_model=EventsResponse,
    summary="List normalized events from sample data",
    description=(
        "Parses and normalizes the bundled sample log files without running "
        "detection rules. Returns the canonical `NormalizedEvent` schema for "
        "each log record — useful for inspecting what normalization produces."
    ),
    tags=["Detection"],
)
def list_events(limit: int = 20):
    data_dir = Path("data/raw")
    if not data_dir.exists():
        raise HTTPException(status_code=404, detail="data/raw directory not found")

    pipeline = Pipeline(log_source="demo", enable_rules=False)
    input_paths = [p for p in data_dir.iterdir() if p.is_file()]

    if not input_paths:
        raise HTTPException(status_code=404, detail="No log files found in data/raw")

    _, events, _ = pipeline.run(input_paths)
    capped = events[:limit]
    return EventsResponse(count=len(events), events=[e.to_dict() for e in capped])
