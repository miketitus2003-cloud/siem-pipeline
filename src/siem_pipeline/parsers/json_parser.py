"""JSON log file parser.

Supports:
  - newline-delimited JSON (NDJSON / JSON-L) — one object per line
  - a single JSON array wrapping all records
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .base import BaseParser
from ..utils.logger import get_logger

logger = get_logger(__name__)


class JSONLogParser(BaseParser):
    SUPPORTED_EXTENSIONS = (".json", ".jsonl", ".ndjson")

    def _parse_file(self, path: Path) -> Iterator[dict | None]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            content = fh.read().strip()

        if not content:
            logger.warning("Empty file: %s", path)
            return

        # Try JSON array first
        if content.startswith("["):
            try:
                records = json.loads(content)
                if not isinstance(records, list):
                    raise ValueError("Expected JSON array")
                for rec in records:
                    yield self._coerce(rec, path)
                return
            except json.JSONDecodeError as exc:
                logger.warning("Not a valid JSON array (%s): %s", path, exc)

        # Fall through to NDJSON line-by-line
        for lineno, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                yield self._coerce(obj, path, lineno)
            except json.JSONDecodeError as exc:
                logger.warning("JSON parse error at %s:%d — %s", path.name, lineno, exc)
                yield None

    @staticmethod
    def _coerce(obj: object, path: Path, lineno: int = 0) -> dict | None:
        if not isinstance(obj, dict):
            logger.warning(
                "Skipping non-object record at %s:%d (type=%s)",
                path.name, lineno, type(obj).__name__,
            )
            return None
        return obj
