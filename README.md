# SIEM Pipeline

[![CI](https://github.com/miketitus2003-cloud/siem-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/miketitus2003-cloud/siem-pipeline/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A production-style **security information and event management pipeline** built in Python. Ingests JSON, JSONL, and CSV log files, normalizes them to a canonical event schema, evaluates stateful MITRE ATT&CK-mapped detection rules, and surfaces alerts via a REST API — like a mini SIEM engine.

**Live demo:** [https://siem-pipeline.up.railway.app](https://siem-pipeline.up.railway.app) &nbsp;|&nbsp; **API docs:** [/docs](https://siem-pipeline.up.railway.app/docs)

---

## What it does

```
Raw Logs (JSON / CSV / JSONL)
        │
        ▼
   Log Parsers          ← dirty-data tolerant, format auto-detected
        │
        ▼
  Normalization         ← 60+ field aliases → canonical NormalizedEvent schema
        │
        ▼
  Rule Engine           ← stateful, MITRE ATT&CK mapped detection rules
        │
        ▼
  Alerts + Summary      ← JSON output, CLI summary, REST API
```

---

## Detection Rules

| ID | Rule | Severity | MITRE Technique | Tactic |
|---|---|---|---|---|
| RULE-1001 | Brute Force Login | **High** | T1110 — Brute Force | Credential Access |
| RULE-1002 | Multi-Source Authentication | Medium | T1078 — Valid Accounts | Initial Access |
| RULE-1003 | Port Scan | Medium | T1046 — Network Service Discovery | Discovery |
| RULE-1004 | Privileged After-Hours Login | **High** | T1078.003 — Local Accounts | Persistence |
| RULE-1005 | Watchlist IP Traffic | **Critical** | T1071 — Application Layer Protocol | Command & Control |

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Landing page |
| `GET` | `/health` | Health check — `{"status": "ok"}` |
| `GET` | `/rules` | List all detection rules with MITRE metadata |
| `GET` | `/events?limit=20` | List normalized events from sample data |
| `POST` | `/run?source=<name>` | Run full pipeline — normalize + detect |
| `GET` | `/docs` | Interactive Swagger UI |
| `GET` | `/redoc` | ReDoc documentation |

---

## Project Structure

```
siem-pipeline/
├── main.py                      # FastAPI app + landing page
├── siem_pipeline/
│   ├── cli.py                   # CLI entrypoint (argparse)
│   ├── pipeline.py              # Orchestrator — wires all layers
│   ├── parsers/
│   │   ├── base.py              # Abstract BaseParser contract
│   │   ├── json_parser.py       # JSON array + NDJSON/JSON-L
│   │   └── csv_parser.py        # CSV/TSV with type coercion
│   ├── normalizers/
│   │   └── normalizer.py        # 60+ field aliases + validation
│   ├── rules/
│   │   ├── base.py              # BaseRule + RuleMatch dataclasses
│   │   ├── builtin_rules.py     # 5 production-style detection rules
│   │   └── engine.py            # Rule loader + evaluation engine
│   └── utils/
│       ├── schema.py            # NormalizedEvent dataclass
│       └── logger.py            # Structured logging config
├── tests/                       # 91 pytest unit + integration tests
├── data/
│   ├── raw/                     # Sample input logs (JSON, JSONL, CSV)
│   └── sample_output/           # Example pipeline output
├── config/
│   └── rules_config.yaml        # Rule tuning reference
├── requirements.txt
├── Procfile
└── nixpacks.toml
```

---

## Quickstart

```bash
git clone https://github.com/miketitus2003-cloud/siem-pipeline.git
cd siem-pipeline
python3 -m venv .venv && source .venv/bin/activate
pip install fastapi "uvicorn[standard]"

# Run the API
uvicorn main:app --reload

# Or run the CLI
pip install -e .
siem-pipeline run data/raw/ --output data/processed --source demo
siem-pipeline rules
```

---

## Canonical Event Schema

All log sources are normalized to `NormalizedEvent`:

| Field | Type | Description |
|---|---|---|
| `event_id` | str | UUID, auto-generated |
| `pipeline_ts` | str | ISO-8601 timestamp when event entered pipeline |
| `timestamp` | str | Original event time (ISO-8601, UTC) |
| `source_ip` | str | Validated IPv4 source address |
| `dest_ip` | str | Validated IPv4 destination address |
| `source_port` | int | Validated port (0–65535) |
| `dest_port` | int | Validated port (0–65535) |
| `username` | str | Normalized username |
| `event_type` | str | `authentication`, `network`, `process`, etc. |
| `outcome` | str | `success` \| `failure` \| `unknown` |
| `severity` | str | `low` \| `medium` \| `high` \| `critical` |
| `raw_message` | str | Original unparsed log line (audit trail) |
| `extra` | dict | Unmapped vendor-specific fields |
| `mitre_technique` | str | e.g. `T1110` |
| `mitre_tactic` | str | e.g. `Credential Access` |

---

## Adding a Custom Rule

```python
# my_rules.py
from siem_pipeline.rules.base import BaseRule, RuleMatch
from siem_pipeline.utils.schema import NormalizedEvent

class LargeDataExfiltration(BaseRule):
    id        = "RULE-9001"
    name      = "Large Outbound Transfer"
    severity  = "high"
    mitre_technique = "T1048"
    mitre_tactic    = "Exfiltration"

    def evaluate(self, event: NormalizedEvent) -> RuleMatch | None:
        bytes_out = int(event.extra.get("bytes_sent", 0) or 0)
        if bytes_out > 100_000_000:
            return self._match(event, bytes_sent=bytes_out)
        return None
```

```bash
siem-pipeline run data/raw/ --rules-file my_rules.py
```

---

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest                                          # 91 tests
pytest --cov=siem_pipeline --cov-report=term-missing
```

---

## Extending the Pipeline

| Area | How |
|---|---|
| New log format | Subclass `BaseParser` → add to `_PARSERS` in `pipeline.py` |
| New field alias | Add entry to `FIELD_MAP` in `normalizers/normalizer.py` |
| New detection rule | Subclass `BaseRule` in `builtin_rules.py` or pass via `--rules-file` |
| Threat intel feed | Replace `WatchlistIPRule.WATCHLIST` with a live API/file fetch |
| Output sink | Extend `Pipeline._write_outputs()` (Elasticsearch, S3, webhook) |

---

## Tech Stack

- **Python 3.11** — stdlib only for core pipeline; no heavy dependencies
- **FastAPI** — REST API with auto-generated OpenAPI docs
- **uvicorn** — ASGI server
- **pytest** — 91 unit and integration tests
- **Railway** — deployment platform

---

## License

MIT
