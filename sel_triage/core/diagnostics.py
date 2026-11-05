"""Stable, factual diagnostic records shared by triage integrations."""

from dataclasses import dataclass
from typing import Any, Dict, Mapping


@dataclass(frozen=True)
class Diagnostic:
    """One deterministic finding with only the evidence that supports it."""

    code: str
    severity: str
    description: str
    evidence: Mapping[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "description": self.description,
            "evidence": dict(self.evidence),
        }


__all__ = ["Diagnostic"]
