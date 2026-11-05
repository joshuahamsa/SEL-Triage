"""Adapter for SEL-735 meters, verified against live output."""

from typing import Any, Callable, Dict

from .base import SelAdapter
from ..parsers import sel735
from ..parsers.common import parse_ser_table


class Sel735Adapter(SelAdapter):
    """Normalize the fast-snapshot surface for SEL-735 meters.

    The 735 is a meter, so there is no breaker capability.
    """

    family = "sel735"
    capabilities = ("identity", "status", "meter", "history", "target")
    not_applicable = ("breaker",)

    _PARSERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
        "identity": sel735.parse_identity,
        "status": sel735.parse_status,
        "meter": sel735.parse_meter,
        "history": sel735.parse_history,
        "target": sel735.parse_target,
        # SER is read by sel-event-sweep / event collection, not snapshots
        "ser": parse_ser_table,
    }

    def parse(self, capability: str, text: str) -> Dict[str, Any]:
        try:
            parser = self._PARSERS[capability]
        except (KeyError, TypeError):
            raise ValueError(
                "unsupported capability for SEL-735: {0}".format(capability)
            ) from None
        return parser(text)


__all__ = ["Sel735Adapter"]
