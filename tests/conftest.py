"""Shared pytest fixtures."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from siem_pipeline.utils.schema import NormalizedEvent


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def sample_json_log(tmp_path: Path) -> Path:
    records = [
        {
            "ts": "2024-03-15T02:14:01Z",
            "src_ip": "10.0.0.1",
            "user": "alice",
            "event": "login_failed",
            "status": "failure",
        },
        {
            "ts": "2024-03-15T09:00:00Z",
            "src_ip": "10.0.0.2",
            "user": "bob",
            "event": "login_success",
            "status": "success",
        },
    ]
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(records))
    return path


@pytest.fixture
def sample_csv_log(tmp_path: Path) -> Path:
    content = (
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action\n"
        "2024-03-15T08:00:01Z,10.0.0.5,8.8.8.8,54320,443,TCP,allowed\n"
        "2024-03-15T08:00:02Z,10.0.0.5,8.8.8.8,54321,80,TCP,allowed\n"
        "2024-03-15T08:00:03Z,,8.8.8.8,54322,22,TCP,blocked\n"
    )
    path = tmp_path / "sample.csv"
    path.write_text(content)
    return path


@pytest.fixture
def dirty_json_log(tmp_path: Path) -> Path:
    content = (
        '{"ts": null, "src_ip": "bad-ip", "user": "", "status": "n/a"}\n'
        'NOT JSON AT ALL\n'
        '{"ts": "2024-03-15T10:00:00Z", "src_ip": "10.0.0.9", "user": "eve", "status": "success"}\n'
    )
    path = tmp_path / "dirty.jsonl"
    path.write_text(content)
    return path


@pytest.fixture
def auth_event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2024-03-15T02:14:01+00:00",
        source_ip="10.0.0.1",
        username="alice",
        event_type="authentication",
        action="login_failed",
        outcome="failure",
    )


@pytest.fixture
def success_event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2024-03-15T09:00:00+00:00",
        source_ip="10.0.0.2",
        username="admin",
        event_type="authentication",
        action="login_success",
        outcome="success",
    )
