"""
Rule engine — applies all registered rules to a stream of NormalizedEvents.

Rules are auto-discovered from builtin_rules and any user-supplied modules.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Iterable, Iterator

from .base import BaseRule, RuleMatch
from ..utils.schema import NormalizedEvent
from ..utils.logger import get_logger

logger = get_logger(__name__)


class RuleEngine:
    """
    Loads and runs detection rules against normalized events.

    Usage::

        engine = RuleEngine()
        engine.load_builtin_rules()
        for match in engine.run(normalized_events):
            print(match.to_dict())
    """

    def __init__(self) -> None:
        self._rules: list[BaseRule] = []

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def load_builtin_rules(self) -> None:
        """Import and instantiate all BaseRule subclasses from builtin_rules."""
        from . import builtin_rules  # noqa: F401 — side-effect: registers subclasses

        loaded = self._register_subclasses(BaseRule)
        logger.info("Loaded %d built-in rules", loaded)

    def load_rules_from_file(self, path: Path) -> None:
        """Dynamically load additional rules from an external Python file."""
        spec = importlib.util.spec_from_file_location("custom_rules", path)
        if spec is None or spec.loader is None:
            logger.error("Cannot load rule module from %s", path)
            return
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        loaded = self._register_subclasses(BaseRule)
        logger.info("Loaded custom rules from %s (%d total rules)", path, loaded)

    def _register_subclasses(self, base: type) -> int:
        """Walk all subclasses of base; instantiate and register concrete ones."""
        count = 0
        already = {type(r) for r in self._rules}
        for cls in self._all_subclasses(base):
            if cls in already:
                continue
            if inspect.isabstract(cls):
                continue
            try:
                instance = cls()
                self._rules.append(instance)
                already.add(cls)
                count += 1
                logger.debug("Registered rule: %s (%s)", cls.name, cls.id)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to instantiate rule %s: %s", cls.__name__, exc)
        return count

    @staticmethod
    def _all_subclasses(cls: type) -> list[type]:
        result = []
        stack = list(cls.__subclasses__())
        while stack:
            sub = stack.pop()
            result.append(sub)
            stack.extend(sub.__subclasses__())
        return result

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def run(self, events: Iterable[NormalizedEvent]) -> Iterator[RuleMatch]:
        """
        Evaluate all rules against each event.

        Yields RuleMatch objects for every rule that fires.
        Rules maintain internal state (e.g. for brute-force counting)
        across the event stream, so order matters.
        """
        if not self._rules:
            logger.warning("No rules loaded — no detections will be generated")

        for event in events:
            for rule in self._rules:
                try:
                    match = rule.evaluate(event)
                    if match is not None:
                        logger.info(
                            "RULE HIT  [%s] %s — event_id=%s",
                            match.severity.upper(),
                            match.rule_name,
                            event.event_id,
                        )
                        yield match
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Rule %s raised an exception on event %s: %s",
                        rule.id, event.event_id, exc,
                    )

    @property
    def rules(self) -> list[BaseRule]:
        return list(self._rules)
