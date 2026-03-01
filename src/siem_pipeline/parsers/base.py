"""Abstract base class for all log parsers."""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Iterator

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ParseError(Exception):
    """Raised when a log record cannot be parsed."""


class BaseParser(abc.ABC):
    """
    Contract every parser must fulfil.

    Subclasses implement `_parse_file` and yield raw dicts.
    The base class handles logging and error isolation so a single
    bad record never aborts the pipeline.
    """

    #: Override in subclass to declare what file extensions are accepted.
    SUPPORTED_EXTENSIONS: tuple[str, ...] = ()

    def can_handle(self, path: Path) -> bool:
        return path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def parse(self, path: Path) -> Iterator[dict]:
        """
        Public entry point.  Yields raw record dicts, skipping bad lines.
        """
        logger.info("Parsing %s with %s", path, self.__class__.__name__)
        parsed = skipped = 0
        for record in self._parse_file(path):
            if record is None:
                skipped += 1
                continue
            parsed += 1
            yield record
        logger.info("Finished %s — parsed=%d skipped=%d", path.name, parsed, skipped)

    @abc.abstractmethod
    def _parse_file(self, path: Path) -> Iterator[dict | None]:
        """
        Yield one dict per log record, or None to signal a bad record.
        Implementations should catch per-record exceptions and yield None.
        """
