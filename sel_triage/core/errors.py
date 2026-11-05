"""Shared error types for sel-triage."""

from typing import Optional


class TriageError(RuntimeError):
    """A categorized error raised while collecting triage data."""

    def __init__(
        self, message: str, category: str, reachable: Optional[bool] = None
    ) -> None:
        super().__init__(message)
        self.category = category
        self.reachable = reachable

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "message": str(self),
            "reachable": self.reachable,
        }
