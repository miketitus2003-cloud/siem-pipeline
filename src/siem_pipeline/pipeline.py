"""
Pipeline orchestrator — wires parsers, normalizer, and rule engine together.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .parsers import JSONLogParser, CSVLogParser, BaseParser
from .normalizers import LogNormalizer
from .rules.engine import RuleEngine
from .rules.base import RuleMatch
from .utils.schema import NormalizedEvent
from .utils.logger import get_logger

logger = get_logger(__name__)

_PARSERS: list[BaseParser] = [JSONLogParser(), CSVLogParser()]


def _select_parser(path: Path) -> BaseParser | None:
    for p in _PARSERS:
        if p.can_handle(path):
            return p
    return None


class Pipeline:
    """
    High-level orchestrator.

    pipeline = Pipeline()
    pipeline.run(input_paths, output_dir)
    """

    def __init__(
        self,
        log_source: str = "unknown",
        enable_rules: bool = True,
        custom_rule_file: Path | None = None,
    ) -> None:
        self.log_source = log_source
        self.normalizer = LogNormalizer(log_source=log_source)
        self.engine = RuleEngine()

        if enable_rules:
            self.engine.load_builtin_rules()
            if custom_rule_file:
                self.engine.load_rules_from_file(custom_rule_file)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_file(self, path: Path) -> tuple[list[NormalizedEvent], list[RuleMatch]]:
        """Parse, normalize, and run rules for a single file."""
        parser = _select_parser(path)
        if parser is None:
            logger.error("No parser for file type: %s", path.suffix)
            return [], []

        raw_records = list(parser.parse(path))
        events = [self.normalizer.normalize(r) for r in raw_records]
        matches = list(self.engine.run(iter(events)))
        return events, matches

    def run(
        self,
        input_paths: list[Path],
        output_dir: Path | None = None,
    ) -> dict[str, object]:
        """
        Process all input paths.

        Returns a summary dict with counts and all matches.
        Optionally writes normalized events and alerts to output_dir.
        """
        all_events: list[NormalizedEvent] = []
        all_matches: list[RuleMatch] = []

        for path in input_paths:
            if not path.exists():
                logger.error("File not found: %s", path)
                continue
            if path.is_dir():
                for child in sorted(path.rglob("*")):
                    if child.is_file() and _select_parser(child):
                        events, matches = self.process_file(child)
                        all_events.extend(events)
                        all_matches.extend(matches)
            else:
                events, matches = self.process_file(path)
                all_events.extend(events)
                all_matches.extend(matches)

        summary = {
            "total_events": len(all_events),
            "total_alerts": len(all_matches),
            "alerts_by_severity": self._count_by(all_matches, lambda m: m.severity),
            "alerts_by_rule": self._count_by(all_matches, lambda m: m.rule_name),
        }

        if output_dir:
            self._write_outputs(output_dir, all_events, all_matches)

        return summary, all_events, all_matches

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    @staticmethod
    def _count_by(matches: list[RuleMatch], key_fn) -> dict:
        counts: dict = {}
        for m in matches:
            k = key_fn(m)
            counts[k] = counts.get(k, 0) + 1
        return counts

    @staticmethod
    def _write_outputs(
        output_dir: Path,
        events: list[NormalizedEvent],
        matches: list[RuleMatch],
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        events_path = output_dir / "normalized_events.json"
        with events_path.open("w") as fh:
            json.dump([e.to_dict() for e in events], fh, indent=2, default=str)
        logger.info("Wrote %d events to %s", len(events), events_path)

        alerts_path = output_dir / "alerts.json"
        with alerts_path.open("w") as fh:
            json.dump([m.to_dict() for m in matches], fh, indent=2, default=str)
        logger.info("Wrote %d alerts to %s", len(matches), alerts_path)
