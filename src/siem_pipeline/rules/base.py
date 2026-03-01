"""Base classes for detection rules."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Optional

from ..utils.schema import NormalizedEvent


@dataclass
class RuleMatch:
    """Encapsulates a single rule hit against an event."""

    rule_id: str
    rule_name: str
    severity: str
    description: str
    event: NormalizedEvent
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "details": self.details,
            "matched_event": self.event.to_dict(),
        }


class BaseRule(abc.ABC):
    """
    Contract for all detection rules.

    Implement `evaluate` to return a RuleMatch when the rule fires,
    or None when the event does not match.

    Class attributes for rule metadata — override in subclasses:
    """

    id: str = "RULE-0000"
    name: str = "Unnamed Rule"
    description: str = ""
    severity: str = "medium"
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

    @abc.abstractmethod
    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        """Return a RuleMatch if the rule fires, else None."""

    def _match(self, event: NormalizedEvent, **details) -> RuleMatch:
        """Convenience constructor for a RuleMatch from this rule."""
        return RuleMatch(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            event=event,
            mitre_technique=self.mitre_technique,
            mitre_tactic=self.mitre_tactic,
            details=details,
        )
