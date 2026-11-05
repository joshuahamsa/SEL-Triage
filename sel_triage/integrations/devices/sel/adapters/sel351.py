"""Adapter for SEL-351-family relays, verified against live 351, 351A and 351S output."""

from typing import Any, Callable, Dict

from .base import SelAdapter
from ..parsers import sel351
from ..parsers.common import parse_ser_table


class Sel351Adapter(SelAdapter):

    family = "sel351"
    capabilities = ("identity", "status", "meter", "breaker", "history", "target")

    _PARSERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
        "identity": sel351.parse_identity,
        "status": sel351.parse_status,
        "meter": sel351.parse_meter,
        "breaker": sel351.parse_breaker,
        "history": sel351.parse_history,
        "target": sel351.parse_target,
        # SER is read by sel-event-sweep / event collection, not snapshots
        "ser": parse_ser_table,
    }

    def parse(self, capability: str, text: str) -> Dict[str, Any]:
        try:
            parser = self._PARSERS[capability]
        except (KeyError, TypeError):
            raise ValueError(
                "unsupported capability for SEL-351: {0}".format(capability)
            ) from None
        return parser(text)


__all__ = ["Sel351Adapter"]
