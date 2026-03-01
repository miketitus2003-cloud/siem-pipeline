"""
CLI entrypoint for the SIEM pipeline.

Usage examples:
    siem-pipeline run data/raw/auth_logs.json
    siem-pipeline run data/raw/ --output data/processed --source cloudtrail
    siem-pipeline run data/raw/firewall.csv --no-rules --verbose
    siem-pipeline rules
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .pipeline import Pipeline
from .utils.logger import get_logger

logger = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem-pipeline",
        description="Mini SIEM-style security data pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  siem-pipeline run data/raw/auth_logs.json
  siem-pipeline run data/raw/ --output data/processed --source syslog
  siem-pipeline run data/raw/fw.csv --no-rules
  siem-pipeline rules
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── run ─────────────────────────────────────────────────────────────────
    run_cmd = subparsers.add_parser("run", help="Ingest, normalize, and detect")
    run_cmd.add_argument(
        "inputs",
        nargs="+",
        metavar="FILE_OR_DIR",
        help="Log files or directories to process (.json, .csv, .jsonl supported)",
    )
    run_cmd.add_argument(
        "--output", "-o",
        metavar="DIR",
        help="Directory to write normalized_events.json and alerts.json",
    )
    run_cmd.add_argument(
        "--source", "-s",
        default="unknown",
        metavar="SOURCE",
        help="Log source label (e.g. syslog, cloudtrail, windows_event)",
    )
    run_cmd.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable rule evaluation (normalization only)",
    )
    run_cmd.add_argument(
        "--rules-file",
        metavar="PY_FILE",
        help="Path to a Python file containing additional custom rule classes",
    )
    run_cmd.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    run_cmd.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for the summary",
    )

    # ── rules ────────────────────────────────────────────────────────────────
    rules_cmd = subparsers.add_parser("rules", help="List all loaded detection rules")
    rules_cmd.add_argument(
        "--rules-file",
        metavar="PY_FILE",
        help="Include rules from an additional file",
    )

    return parser


def _print_summary_text(summary: dict, matches: list) -> None:
    print("\n" + "=" * 60)
    print("  PIPELINE SUMMARY")
    print("=" * 60)
    print(f"  Total events processed : {summary['total_events']}")
    print(f"  Total alerts generated : {summary['total_alerts']}")

    if summary["alerts_by_severity"]:
        print("\n  Alerts by Severity:")
        for sev in ("critical", "high", "medium", "low"):
            count = summary["alerts_by_severity"].get(sev, 0)
            if count:
                print(f"    {sev.upper():10s} {count}")

    if summary["alerts_by_rule"]:
        print("\n  Alerts by Rule:")
        for rule_name, count in sorted(
            summary["alerts_by_rule"].items(), key=lambda x: -x[1]
        ):
            print(f"    [{count:3d}]  {rule_name}")

    if matches:
        print("\n  Recent Alerts (last 5):")
        for match in matches[-5:]:
            event = match.event
            print(
                f"    [{match.severity.upper():8s}] {match.rule_name}"
                f" | src={event.source_ip or '-'}"
                f" user={event.username or '-'}"
                f" ts={event.timestamp or '-'}"
            )
    print("=" * 60 + "\n")


def cmd_run(args: argparse.Namespace) -> int:
    if args.verbose:
        logging.getLogger("siem_pipeline").setLevel(logging.DEBUG)

    input_paths = [Path(p) for p in args.inputs]
    output_dir = Path(args.output) if args.output else None
    custom_rules = Path(args.rules_file) if args.rules_file else None

    pipeline = Pipeline(
        log_source=args.source,
        enable_rules=not args.no_rules,
        custom_rule_file=custom_rules,
    )

    summary, events, matches = pipeline.run(input_paths, output_dir=output_dir)

    if args.format == "json":
        out = {
            "summary": summary,
            "alerts": [m.to_dict() for m in matches],
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        _print_summary_text(summary, matches)

    # Exit code 1 if critical/high alerts found
    critical_high = (
        summary["alerts_by_severity"].get("critical", 0)
        + summary["alerts_by_severity"].get("high", 0)
    )
    return 1 if critical_high > 0 else 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .rules.engine import RuleEngine

    engine = RuleEngine()
    engine.load_builtin_rules()
    if getattr(args, "rules_file", None):
        engine.load_rules_from_file(Path(args.rules_file))

    print(f"\n{'ID':<12} {'SEVERITY':<10} {'TACTIC':<22} {'TECHNIQUE':<12} NAME")
    print("-" * 90)
    for rule in engine.rules:
        print(
            f"{rule.id:<12} "
            f"{rule.severity:<10} "
            f"{(rule.mitre_tactic or '-'):<22} "
            f"{(rule.mitre_technique or '-'):<12} "
            f"{rule.name}"
        )
    print()
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "run":
        sys.exit(cmd_run(args))
    elif args.command == "rules":
        sys.exit(cmd_rules(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
