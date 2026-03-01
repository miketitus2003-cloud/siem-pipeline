"""Unit tests for LogNormalizer."""

from __future__ import annotations

import pytest

from siem_pipeline.normalizers.normalizer import LogNormalizer
from siem_pipeline.utils.schema import NormalizedEvent


@pytest.fixture
def normalizer():
    return LogNormalizer(log_source="test")


class TestFieldMapping:
    def test_canonical_fields_pass_through(self, normalizer):
        raw = {
            "timestamp": "2024-03-15T09:00:00Z",
            "source_ip": "10.0.0.1",
            "username": "alice",
        }
        event = normalizer.normalize(raw)
        assert event.username == "alice"
        assert event.source_ip == "10.0.0.1"

    def test_alias_src_ip_maps_to_source_ip(self, normalizer):
        event = normalizer.normalize({"src_ip": "10.0.0.5"})
        assert event.source_ip == "10.0.0.5"

    def test_alias_user_maps_to_username(self, normalizer):
        event = normalizer.normalize({"user": "bob"})
        assert event.username == "bob"

    def test_alias_ts_maps_to_timestamp(self, normalizer):
        event = normalizer.normalize({"ts": "2024-01-01T00:00:00Z"})
        assert event.timestamp is not None

    def test_alias_level_maps_to_severity(self, normalizer):
        event = normalizer.normalize({"level": "warning"})
        assert event.severity == "medium"

    def test_unknown_fields_go_to_extra(self, normalizer):
        event = normalizer.normalize({"totally_unknown_field": "value"})
        assert event.extra.get("totally_unknown_field") == "value"

    def test_log_source_is_set(self, normalizer):
        event = normalizer.normalize({})
        assert event.log_source == "test"


class TestTimestampParsing:
    def test_iso8601_utc(self, normalizer):
        event = normalizer.normalize({"ts": "2024-03-15T09:00:00Z"})
        assert "2024-03-15" in event.timestamp

    def test_unix_epoch_seconds(self, normalizer):
        event = normalizer.normalize({"ts": 1710493200})
        assert event.timestamp is not None
        assert "2024" in event.timestamp

    def test_unix_epoch_milliseconds(self, normalizer):
        event = normalizer.normalize({"ts": 1710493200000})
        assert event.timestamp is not None

    def test_null_timestamp(self, normalizer):
        event = normalizer.normalize({"ts": None})
        assert event.timestamp is None

    def test_apache_clf_timestamp(self, normalizer):
        event = normalizer.normalize({"ts": "15/Mar/2024:09:00:00 +0000"})
        assert event.timestamp is not None


class TestIPValidation:
    def test_valid_ipv4(self, normalizer):
        event = normalizer.normalize({"src_ip": "192.168.1.100"})
        assert event.source_ip == "192.168.1.100"

    def test_invalid_ip_discarded(self, normalizer):
        event = normalizer.normalize({"src_ip": "not-an-ip"})
        assert event.source_ip is None

    def test_ipv6_mapped_stripped(self, normalizer):
        event = normalizer.normalize({"src_ip": "::ffff:10.0.0.1"})
        assert event.source_ip == "10.0.0.1"

    def test_empty_ip_discarded(self, normalizer):
        event = normalizer.normalize({"src_ip": ""})
        assert event.source_ip is None


class TestSeverityNormalization:
    @pytest.mark.parametrize("raw,expected", [
        ("critical", "critical"),
        ("error", "high"),
        ("warning", "medium"),
        ("warn", "medium"),
        ("info", "low"),
        ("debug", "low"),
        ("0", "critical"),
        ("7", "low"),
    ])
    def test_severity_mapping(self, normalizer, raw, expected):
        event = normalizer.normalize({"level": raw})
        assert event.severity == expected


class TestOutcomeNormalization:
    @pytest.mark.parametrize("raw,expected", [
        ("success", "success"),
        ("succeeded", "success"),
        ("200", "success"),
        ("failure", "failure"),
        ("denied", "failure"),
        ("blocked", "failure"),
        ("gibberish", "unknown"),
    ])
    def test_outcome_mapping(self, normalizer, raw, expected):
        event = normalizer.normalize({"status": raw})
        assert event.outcome == expected


class TestPortCoercion:
    def test_valid_port(self, normalizer):
        event = normalizer.normalize({"src_port": "443"})
        assert event.source_port == 443

    def test_out_of_range_port(self, normalizer):
        event = normalizer.normalize({"src_port": "99999"})
        assert event.source_port is None

    def test_negative_port(self, normalizer):
        event = normalizer.normalize({"src_port": "-1"})
        assert event.source_port is None


class TestSerialization:
    def test_to_dict_omits_none(self, normalizer):
        event = normalizer.normalize({"src_ip": "10.0.0.1"})
        d = event.to_dict()
        assert "dest_ip" not in d
        assert "source_ip" in d

    def test_from_dict_roundtrip(self, normalizer):
        event = normalizer.normalize({
            "ts": "2024-03-15T09:00:00Z",
            "src_ip": "10.0.0.1",
            "user": "alice",
        })
        d = event.to_dict()
        restored = NormalizedEvent.from_dict(d)
        assert restored.source_ip == event.source_ip
        assert restored.username == event.username
