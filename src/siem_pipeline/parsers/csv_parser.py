"""CSV log file parser with header auto-detection and dirty-data handling."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Iterator

from .base import BaseParser
from ..utils.logger import get_logger

logger = get_logger(__name__)

# Columns that should be coerced to integers
_INT_FIELDS = {"source_port", "dest_port", "port", "src_port", "dst_port", "status_code"}


class CSVLogParser(BaseParser):
    SUPPORTED_EXTENSIONS = (".csv", ".tsv")

    def _parse_file(self, path: Path) -> Iterator[dict | None]:
        delimiter = "\t" if path.suffix.lower() == ".tsv" else ","

        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            content = fh.read()

        if not content.strip():
            logger.warning("Empty file: %s", path)
            return

        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)

        if reader.fieldnames is None:
            logger.error("Could not detect CSV headers in %s", path)
            return

        logger.debug("CSV headers: %s", list(reader.fieldnames))

        for lineno, row in enumerate(reader, start=2):  # 1-indexed; row 1 is header
            try:
                record = self._clean_row(dict(row), lineno, path)
                yield record
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to process row %d in %s: %s", lineno, path.name, exc)
                yield None

    @staticmethod
    def _clean_row(row: dict, lineno: int, path: Path) -> dict | None:
        # Strip whitespace from all string values; drop empty-string keys
        cleaned: dict = {}
        for k, v in row.items():
            if k is None:
                continue
            key = k.strip()
            if not key:
                continue
            if isinstance(v, str):
                v = v.strip()
                if v == "" or v.lower() in ("-", "n/a", "null", "none"):
                    v = None
            cleaned[key] = v

        # Coerce known integer fields
        for field in _INT_FIELDS:
            if field in cleaned and cleaned[field] is not None:
                try:
                    cleaned[field] = int(cleaned[field])
                except (ValueError, TypeError):
                    logger.debug(
                        "Could not coerce %s=%r to int at %s:%d",
                        field, cleaned[field], path.name, lineno,
                    )
                    cleaned[field] = None

        return cleaned if cleaned else None
