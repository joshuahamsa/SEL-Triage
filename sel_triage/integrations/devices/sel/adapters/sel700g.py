"""Adapter for SEL-700G and SEL-700GT responses."""

from typing import Any, Callable, Dict, Iterator

from .base import EventRequest, EventSelector, SelAdapter, numbered_event_requests
from ..parsers import sel700g
from ..parsers.common import parse_settings


class Sel700GAdapter(SelAdapter):
    """Normalize the verified fast-snapshot surface for the 700G family."""

    family = "sel700g"
    capabilities = (
        "identity",
        "status",
        "meter",
        "breaker",
        "history",
        "target",
        "eve",
        "cev",
        "ser",
        "settings_global",
        "settings_group",
        "settings_logic",
        "settings_report",
    )

    _PARSERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
        "identity": sel700g.parse_identity,
        "status": sel700g.parse_status,
        "meter": sel700g.parse_meter,
        "breaker": sel700g.parse_breaker,
        "history": sel700g.parse_history,
        "target": sel700g.parse_target,
        "ser": sel700g.parse_ser,
        "settings_global": parse_settings,
        "settings_group": parse_settings,
        "settings_logic": parse_settings,
        "settings_report": parse_settings,
    }

    def parse(self, capability: str, text: str) -> Dict[str, Any]:
        try:
            parser = self._PARSERS[capability]
        except (KeyError, TypeError):
            raise ValueError(
                "unsupported capability for SEL-700G: {0}".format(capability)
            ) from None
        return parser(text)

    def event_requests(self, selector: EventSelector) -> Iterator[EventRequest]:
        return iter(numbered_event_requests(selector))


__all__ = ["Sel700GAdapter"]
