"""Unit tests for log parsers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siem_pipeline.parsers.json_parser import JSONLogParser
from siem_pipeline.parsers.csv_parser import CSVLogParser


class TestJSONLogParser:
    parser = JSONLogParser()

    def test_parse_json_array(self, sample_json_log: Path):
        records = list(self.parser.parse(sample_json_log))
        assert len(records) == 2
        assert records[0]["user"] == "alice"
        assert records[1]["user"] == "bob"

    def test_parse_ndjson(self, tmp_path: Path):
        ndjson = tmp_path / "events.jsonl"
        ndjson.write_text(
            '{"a": 1}\n'
            '{"a": 2}\n'
            '{"a": 3}\n'
        )
        records = list(self.parser.parse(ndjson))
        assert len(records) == 3
        assert [r["a"] for r in records] == [1, 2, 3]

    def test_skips_invalid_json_lines(self, dirty_json_log: Path):
        records = list(self.parser.parse(dirty_json_log))
        # One bad JSON line → yielded as None → skipped in parse()
        # Valid records: first dict + third dict = 2
        assert len(records) == 2

    def test_empty_file(self, tmp_path: Path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        records = list(self.parser.parse(empty))
        assert records == []

    def test_can_handle_extensions(self):
        assert self.parser.can_handle(Path("log.json"))
        assert self.parser.can_handle(Path("log.jsonl"))
        assert self.parser.can_handle(Path("log.ndjson"))
        assert not self.parser.can_handle(Path("log.csv"))

    def test_non_object_records_skipped(self, tmp_path: Path):
        """Array-of-scalars should be skipped gracefully."""
        path = tmp_path / "scalars.json"
        path.write_text(json.dumps([1, 2, 3]))
        records = list(self.parser.parse(path))
        assert records == []

    def test_preserves_all_fields(self, tmp_path: Path):
        data = [{"key1": "val1", "nested": {"x": 1}}]
        path = tmp_path / "nested.json"
        path.write_text(json.dumps(data))
        records = list(self.parser.parse(path))
        assert records[0]["nested"] == {"x": 1}


class TestCSVLogParser:
    parser = CSVLogParser()

    def test_parse_basic_csv(self, sample_csv_log: Path):
        records = list(self.parser.parse(sample_csv_log))
        assert len(records) == 3

    def test_port_coercion(self, sample_csv_log: Path):
        records = list(self.parser.parse(sample_csv_log))
        assert records[0]["dst_port"] == 443
        assert isinstance(records[0]["dst_port"], int)

    def test_empty_string_becomes_none(self, tmp_path: Path):
        path = tmp_path / "test.csv"
        path.write_text("ip,user\n10.0.0.1,\n")
        records = list(self.parser.parse(path))
        assert records[0]["user"] is None

    def test_null_string_becomes_none(self, tmp_path: Path):
        path = tmp_path / "test.csv"
        path.write_text("ip,status\n10.0.0.1,null\n10.0.0.2,n/a\n")
        records = list(self.parser.parse(path))
        assert records[0]["status"] is None
        assert records[1]["status"] is None

    def test_missing_ip_becomes_none(self, sample_csv_log: Path):
        records = list(self.parser.parse(sample_csv_log))
        # Third row has empty src_ip
        assert records[2]["src_ip"] is None

    def test_can_handle_extensions(self):
        assert self.parser.can_handle(Path("logs.csv"))
        assert self.parser.can_handle(Path("logs.tsv"))
        assert not self.parser.can_handle(Path("logs.json"))

    def test_empty_file(self, tmp_path: Path):
        path = tmp_path / "empty.csv"
        path.write_text("")
        records = list(self.parser.parse(path))
        assert records == []
