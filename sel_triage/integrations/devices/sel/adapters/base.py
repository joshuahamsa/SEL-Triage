"""Adapter contract for model-specific SEL response parsing."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple


_EVENT_FORMATS = ("eve", "cev", "cev_raw")


def _positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("{0} must be a positive integer".format(field))
    return value


@dataclass(frozen=True)
class EventSelector:
    """A validated recent-event count or explicit relay event number."""

    mode: str
    count: int
    event_number: Optional[int]
    event_format: str

    def __post_init__(self) -> None:
        if self.mode not in ("latest", "number"):
            raise ValueError("selector mode must be latest or number")
        _positive_integer(self.count, "event count")
        self._format(self.event_format)
        if self.mode == "latest" and self.event_number is not None:
            raise ValueError("latest selector must not include an event number")
        if self.mode == "number":
            _positive_integer(self.event_number, "event number")
            if self.count != 1:
                raise ValueError("number selector count must be one")

    @classmethod
    def latest(
        cls, count: int = 1, event_format: str = "eve"
    ) -> "EventSelector":
        return cls(
            mode="latest",
            count=_positive_integer(count, "event count"),
            event_number=None,
            event_format=cls._format(event_format),
        )

    @classmethod
    def number(
        cls, event_number: int, event_format: str = "eve"
    ) -> "EventSelector":
        return cls(
            mode="number",
            count=1,
            event_number=_positive_integer(event_number, "event number"),
            event_format=cls._format(event_format),
        )

    @staticmethod
    def _format(value: str) -> str:
        if value not in _EVENT_FORMATS:
            raise ValueError(
                "event format must be one of: {0}".format(", ".join(_EVENT_FORMATS))
            )
        return value


@dataclass(frozen=True)
class EventRequest:
    """One adapter-selected capability invocation and evidence format."""

    capability: str
    argument: int
    event_format: str
    extension: str


class SelAdapter(ABC):
    """Normalize responses for one supported SEL device family."""

    family: str
    capabilities: Tuple[str, ...]
    # True for families that can read HIS and SER but have no event report
    # recipe: event collection then retrieves those two instead of reports.
    ser_only_events = False

    @abstractmethod
    def parse(self, capability: str, text: str) -> Dict[str, Any]:
        """Parse one capability response without discarding unknown lines."""

    def event_requests(self, selector: EventSelector) -> Iterable[EventRequest]:
        """Return capture-backed requests or reject unsupported retrieval."""

        raise ValueError(
            "command_unavailable for {0} family event retrieval".format(self.family)
        )


def numbered_event_requests(selector: EventSelector) -> Iterable[EventRequest]:
    """Request relay events 1..count (newest first) or one explicit number."""

    if not isinstance(selector, EventSelector):
        raise ValueError("selector must be an EventSelector")
    if selector.mode == "latest":
        numbers: Iterable[int] = range(1, selector.count + 1)
    else:
        numbers = (selector.event_number,)
    for number in numbers:
        yield EventRequest(
            capability=selector.event_format,
            argument=number,
            event_format=selector.event_format,
            extension="cev" if selector.event_format.startswith("cev") else "eve",
        )


__all__ = [
    "EventRequest",
    "EventSelector",
    "SelAdapter",
    "numbered_event_requests",
]
