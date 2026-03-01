"""Integration tests for the full Pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siem_pipeline.pipeline import Pipeline


class TestPipelineIntegration:
    def test_processes_json_file(self, sample_json_log: Path, tmp_path: Path):
        pipeline = Pipeline(log_source="test", enable_rules=False)
        summary, events, matches = pipeline.run([sample_json_log])
        assert summary["total_events"] == 2
        assert summary["total_alerts"] == 0

    def test_processes_csv_file(self, sample_csv_log: Path):
        pipeline = Pipeline(log_source="test", enable_rules=False)
        summary, events, _ = pipeline.run([sample_csv_log])
        assert summary["total_events"] == 3

    def test_detects_watchlist_ip(self, tmp_path: Path):
        # Write a log with a watchlist IP
        records = [{"src_ip": "192.0.2.1", "ts": "2024-03-15T09:00:00Z"}]
        log = tmp_path / "watchlist.json"
        log.write_text(json.dumps(records))

        pipeline = Pipeline(enable_rules=True)
        summary, events, matches = pipeline.run([log])
        assert any(m.rule_id == "RULE-1005" for m in matches)

    def test_writes_output_files(self, sample_json_log: Path, tmp_path: Path):
        out_dir = tmp_path / "output"
        pipeline = Pipeline(enable_rules=False)
        pipeline.run([sample_json_log], output_dir=out_dir)

        assert (out_dir / "normalized_events.json").exists()
        assert (out_dir / "alerts.json").exists()

    def test_output_json_is_valid(self, sample_json_log: Path, tmp_path: Path):
        out_dir = tmp_path / "output"
        pipeline = Pipeline(enable_rules=False)
        pipeline.run([sample_json_log], output_dir=out_dir)

        events_data = json.loads((out_dir / "normalized_events.json").read_text())
        assert isinstance(events_data, list)
        assert len(events_data) == 2
        assert "event_id" in events_data[0]
        assert "pipeline_ts" in events_data[0]

    def test_handles_missing_file_gracefully(self):
        pipeline = Pipeline(enable_rules=False)
        summary, events, matches = pipeline.run([Path("/does/not/exist.json")])
        assert summary["total_events"] == 0

    def test_handles_dirty_data(self, dirty_json_log: Path):
        pipeline = Pipeline(enable_rules=False)
        summary, events, _ = pipeline.run([dirty_json_log])
        # Should process valid records without crashing
        assert summary["total_events"] > 0

    def test_directory_input_recurses(self, tmp_path: Path):
        import json as _json
        sub = tmp_path / "logs"
        sub.mkdir()
        (sub / "a.json").write_text(_json.dumps([{"src_ip": "10.0.0.1"}]))
        (sub / "b.json").write_text(_json.dumps([{"src_ip": "10.0.0.2"}, {"src_ip": "10.0.0.3"}]))

        pipeline = Pipeline(enable_rules=False)
        summary, events, _ = pipeline.run([sub])
        assert summary["total_events"] == 3

    def test_summary_counts_alerts_by_severity(self, tmp_path: Path):
        records = [{"src_ip": "192.0.2.1"}]  # triggers WatchlistIPRule (critical)
        log = tmp_path / "watchlist.json"
        log.write_text(json.dumps(records))

        pipeline = Pipeline(enable_rules=True)
        summary, _, _ = pipeline.run([log])
        assert summary["alerts_by_severity"].get("critical", 0) >= 1
