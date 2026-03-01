"""
FastAPI entry point for the SIEM Pipeline API.
Railway start command: uvicorn main:app --host 0.0.0.0 --port $PORT
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from siem_pipeline.pipeline import Pipeline

app = FastAPI(
    title="SIEM Pipeline API",
    description="Mini SIEM-style security data pipeline",
    version="0.1.0",
)


@app.get("/")
def health():
    return {"status": "ok", "service": "siem-pipeline"}


@app.get("/rules")
def list_rules():
    from siem_pipeline.rules.engine import RuleEngine

    engine = RuleEngine()
    engine.load_builtin_rules()
    return {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity,
                "mitre_tactic": r.mitre_tactic,
                "mitre_technique": r.mitre_technique,
            }
            for r in engine.rules
        ]
    }


@app.post("/run")
def run_pipeline(source: str = "unknown"):
    """Run the pipeline against the bundled sample data."""
    data_dir = Path("data/raw")
    if not data_dir.exists():
        raise HTTPException(status_code=404, detail="data/raw directory not found")

    pipeline = Pipeline(log_source=source, enable_rules=True)
    input_paths = [p for p in data_dir.iterdir() if p.is_file()]

    if not input_paths:
        raise HTTPException(status_code=404, detail="No log files found in data/raw")

    summary, _events, matches = pipeline.run(input_paths)

    return {
        "summary": summary,
        "alerts": [m.to_dict() for m in matches],
    }
