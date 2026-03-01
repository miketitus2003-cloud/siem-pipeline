# Security Data Pipeline (SIEM-Style Engine)

A modular, portfolio-quality **security data pipeline** written in Python. Ingests JSON and CSV log files, normalizes them to a canonical schema, evaluates stateful detection rules with MITRE ATT&CK metadata, and outputs structured alerts — like a mini SIEM engine.

---

## Description

Log ingestion, normalization, and detection pipeline with rule engine and MITRE mapping.

The pipeline accepts raw logs from heterogeneous sources (syslog, CloudTrail, firewall exports, auth logs), maps them to a unified `NormalizedEvent` schema, and runs a configurable set of detection rules against the stream. Results are written to disk as structured JSON and surfaced via a terminal-friendly CLI summary.

---

## Features

- **Log parsers** — JSON array, NDJSON/JSON-L, and CSV/TSV with dirty-data handling (missing fields, malformed rows, invalid values)
- **Normalized schema** — canonical `NormalizedEvent` dataclass with validated IP addresses, timestamps, port numbers, severity, and outcome fields
- **Detection rules** — stateful rule engine with 5 built-in rules; easily extensible by subclassing `BaseRule`
- **CLI interface** — `siem-pipeline run` and `siem-pipeline rules` subcommands; JSON or human-readable output; CI-friendly exit codes
- **Tests** — 91 pytest unit and integration tests covering parsers, normalizer, every rule, and the full pipeline

---

## Project Structure

```
siem-pipeline/
├── src/
│   └── siem_pipeline/
│       ├── cli.py               # CLI entrypoint (argparse)
│       ├── pipeline.py          # Orchestrator — wires all layers
│       ├── parsers/
│       │   ├── base.py          # Abstract BaseParser contract
│       │   ├── json_parser.py   # JSON array + NDJSON/JSON-L
│       │   └── csv_parser.py    # CSV/TSV with type coercion
│       ├── normalizers/
│       │   └── normalizer.py    # Field alias map + validation
│       ├── rules/
│       │   ├── base.py          # BaseRule + RuleMatch dataclasses
│       │   ├── builtin_rules.py # 5 production-style detection rules
│       │   └── engine.py        # Rule loader + evaluation engine
│       └── utils/
│           ├── schema.py        # NormalizedEvent dataclass
│           └── logger.py        # Structured logging config
├── tests/
│   ├── conftest.py              # Shared pytest fixtures
│   ├── test_parsers.py
│   ├── test_normalizer.py
│   ├── test_rules.py
│   └── test_pipeline.py         # End-to-end integration tests
├── data/
│   ├── raw/                     # Sample input logs
│   │   ├── auth_logs.json
│   │   ├── firewall_logs.csv
│   │   └── cloudtrail_sample.jsonl
│   └── processed/               # Pipeline output (git-ignored)
├── config/
│   └── rules_config.yaml        # Rule tuning reference
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

---

## Installation

### Prerequisites

- Python 3.11+
- No external runtime dependencies (stdlib only)

### Setup

```bash
# Clone or open the project
cd siem-pipeline

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the package in editable mode
pip install -e .

# Install development/test dependencies
pip install -r requirements-dev.txt
```

---

## Usage

### Run the pipeline

```bash
# Process all logs in a directory, write output files
siem-pipeline run data/raw/ --output data/processed --source demo

# Process a single file
siem-pipeline run data/raw/auth_logs.json --source syslog

# JSON-formatted output (useful for piping or CI integration)
siem-pipeline run data/raw/auth_logs.json --format json

# Normalize only — skip rule evaluation
siem-pipeline run data/raw/firewall_logs.csv --no-rules

# Load additional custom rules from a Python file
siem-pipeline run data/raw/ --rules-file my_rules.py

# Enable DEBUG logging
siem-pipeline run data/raw/ --verbose
```

### List detection rules

```bash
siem-pipeline rules
```

```
ID           SEVERITY   TACTIC                 TECHNIQUE    NAME
------------------------------------------------------------------------------------------
RULE-1001    high       Credential Access      T1110        Brute Force Login Detected
RULE-1002    medium     Initial Access         T1078        Authentication from Multiple Source IPs
RULE-1003    medium     Discovery              T1046        Port Scan Detected
RULE-1004    high       Persistence            T1078.003    Privileged Account Login Outside Business Hours
RULE-1005    critical   Command and Control    T1071        Traffic from Watchlist IP
```

### Output files

When `--output DIR` is provided:

| File | Contents |
|---|---|
| `normalized_events.json` | All ingested events in canonical schema |
| `alerts.json` | All rule matches with matched event embedded |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Pipeline completed; no critical or high alerts |
| `1` | Pipeline completed; one or more critical/high alerts detected |

Exit code `1` allows you to gate CI/CD pipelines on alert severity.

---

## Canonical Event Schema

All log sources are normalized to `NormalizedEvent`:

| Field | Type | Description |
|---|---|---|
| `event_id` | str | UUID, auto-generated per event |
| `pipeline_ts` | str | ISO-8601 timestamp when the event entered the pipeline |
| `timestamp` | str | Original event time (ISO-8601, UTC) |
| `source_ip` | str | Validated IPv4 source address |
| `dest_ip` | str | Validated IPv4 destination address |
| `source_port` | int | Validated port (0–65535) |
| `dest_port` | int | Validated port (0–65535) |
| `protocol` | str | e.g. `TCP`, `UDP` |
| `username` | str | Normalized username |
| `hostname` | str | Device or host name |
| `event_type` | str | `authentication`, `network`, `process`, etc. |
| `action` | str | e.g. `login_failed`, `port_scan` |
| `outcome` | str | `success` \| `failure` \| `unknown` |
| `severity` | str | `low` \| `medium` \| `high` \| `critical` |
| `log_source` | str | Caller-supplied source label |
| `raw_message` | str | Original unparsed log line (audit trail) |
| `extra` | dict | Unmapped vendor-specific fields |
| `mitre_technique` | str | e.g. `T1110` |
| `mitre_tactic` | str | e.g. `Credential Access` |

---

## MITRE ATT&CK Coverage

| Rule ID | Rule Name | Technique | Technique Name | Tactic | Severity |
|---|---|---|---|---|---|
| RULE-1001 | Brute Force Login Detected | T1110 | Brute Force | Credential Access | High |
| RULE-1002 | Authentication from Multiple Source IPs | T1078 | Valid Accounts | Initial Access | Medium |
| RULE-1003 | Port Scan Detected | T1046 | Network Service Discovery | Discovery | Medium |
| RULE-1004 | Privileged Account Login Outside Business Hours | T1078.003 | Valid Accounts: Local Accounts | Persistence | High |
| RULE-1005 | Traffic from Watchlist IP | T1071 | Application Layer Protocol | Command and Control | Critical |

---

## Adding a Custom Rule

Create a Python file with a `BaseRule` subclass:

```python
# my_rules.py
from siem_pipeline.rules.base import BaseRule, RuleMatch
from siem_pipeline.utils.schema import NormalizedEvent

class LargeDataExfiltration(BaseRule):
    id = "RULE-9001"
    name = "Large Outbound Transfer"
    severity = "high"
    mitre_technique = "T1048"
    mitre_tactic = "Exfiltration"

    def evaluate(self, event: NormalizedEvent) -> RuleMatch | None:
        bytes_out = event.extra.get("bytes_sent", 0) or 0
        if int(bytes_out) > 100_000_000:  # 100 MB
            return self._match(event, bytes_sent=bytes_out)
        return None
```

```bash
siem-pipeline run data/raw/ --rules-file my_rules.py
```

---

## Running Tests

```bash
# Full test suite
pytest

# With line-level coverage report
pytest --cov=siem_pipeline --cov-report=term-missing

# Single module
pytest tests/test_rules.py -v
```

Expected output: **91 passed**

---

## Future Work

- **Cloud log sources** — AWS CloudTrail (full field mapping), GCP Cloud Audit Logs, Azure Activity Log
- **Additional detection rules** — lateral movement (T1021), privilege escalation (T1068), persistence via scheduled tasks (T1053)
- **Threat intelligence integration** — live watchlist updates via STIX/TAXII feeds or MISP API
- **Output sinks** — Elasticsearch index writer, S3/GCS export, syslog forwarding
- **Structured (JSON) logging** — swap stdlib logging for `structlog` for machine-readable pipeline logs
- **Rule configuration file** — load thresholds and watchlists from `config/rules_config.yaml` at runtime
- **Web dashboard** — simple Flask/FastAPI frontend to browse normalized events and alerts

---

## Extending the Pipeline

| Area | How |
|---|---|
| New log format | Subclass `BaseParser` in `parsers/`, add instance to `_PARSERS` in `pipeline.py` |
| New field alias | Add entry to `FIELD_MAP` in `normalizers/normalizer.py` |
| New detection rule | Subclass `BaseRule`; pass file via `--rules-file` or drop into `builtin_rules.py` |
| Threat intel feed | Replace `WatchlistIPRule.WATCHLIST` with a live API/file fetch |
| Output sink | Extend `Pipeline._write_outputs()` (Elasticsearch, S3, webhook, etc.) |

---

## License

MIT
