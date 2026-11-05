"""Adapter for fixture-backed SEL-651-family responses."""

from typing import Any, Callable, Dict, Iterator

from .base import EventRequest, EventSelector, SelAdapter, numbered_event_requests
from ..parsers import sel651
from ..parsers.common import parse_ser_table


class Sel651Adapter(SelAdapter):
    family = "sel651"
    capabilities = (
        "identity",
        "status",
        "meter",
        "history",
        "eve",
        "cev",
        "cev_raw",
        "ser",
    )

    _PARSERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
        "identity": sel651.parse_identity,
        "status": sel651.parse_status,
        "meter": sel651.parse_meter,
        "history": sel651.parse_history,
        # SER is read by sel-event-sweep / event collection, not snapshots
        "ser": parse_ser_table,
    }

    def parse(self, capability: str, text: str) -> Dict[str, Any]:
        try:
            parser = self._PARSERS[capability]
        except (KeyError, TypeError):
            raise ValueError(
                "command_unavailable for SEL-651 family: {0}".format(capability)
            ) from None
        return parser(text)

    def event_requests(self, selector: EventSelector) -> Iterator[EventRequest]:
        return iter(numbered_event_requests(selector))


__all__ = ["Sel651Adapter"]
