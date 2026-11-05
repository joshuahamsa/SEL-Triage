"""Adapter for SEL-751-family relays, verified against live SEL-751 output."""

from typing import Any, Callable, Dict, Iterator

from .base import EventRequest, EventSelector, SelAdapter
from ..parsers import sel751
from ..parsers.common import parse_ser_table


class Sel751Adapter(SelAdapter):
    family = "sel751"
    capabilities = ("identity", "status", "meter", "breaker", "history", "target")
    # No capture-backed EVE/CEV recipe yet: event collection reads HIS and SER.
    ser_only_events = True

    _PARSERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
        "identity": sel751.parse_identity,
        "status": sel751.parse_status,
        "meter": sel751.parse_meter,
        "breaker": sel751.parse_breaker,
        "history": sel751.parse_history,
        "target": sel751.parse_target,
        # SER is read by sel-event-sweep / event collection, not snapshots
        "ser": parse_ser_table,
    }

    def parse(self, capability: str, text: str) -> Dict[str, Any]:
        try:
            parser = self._PARSERS[capability]
        except (KeyError, TypeError):
            raise ValueError(
                "unsupported capability for SEL-751: {0}".format(capability)
            ) from None
        return parser(text)

    def event_requests(self, selector: EventSelector) -> Iterator[EventRequest]:
        return iter(())


__all__ = ["Sel751Adapter"]
