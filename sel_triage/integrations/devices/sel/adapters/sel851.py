"""Adapter for SEL-851 relays, verified against live output."""

from typing import Any, Callable, Dict

from .base import SelAdapter
from ..parsers import sel851
from ..parsers.common import parse_ser_table


class Sel851Adapter(SelAdapter):
    """A live SEL-851 answers '"BRE" unknown.', so breaker is not applicable."""

    family = "sel851"
    capabilities = ("identity", "status", "meter", "history", "target")
    not_applicable = ("breaker",)

    _PARSERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
        "identity": sel851.parse_identity,
        "status": sel851.parse_status,
        "meter": sel851.parse_meter,
        "history": sel851.parse_history,
        "target": sel851.parse_target,
        # SER is read by sel-event-sweep / event collection, not snapshots
        "ser": parse_ser_table,
    }

    def parse(self, capability: str, text: str) -> Dict[str, Any]:
        try:
            parser = self._PARSERS[capability]
        except (KeyError, TypeError):
            raise ValueError(
                "unsupported capability for SEL-851: {0}".format(capability)
            ) from None
        return parser(text)


__all__ = ["Sel851Adapter"]
