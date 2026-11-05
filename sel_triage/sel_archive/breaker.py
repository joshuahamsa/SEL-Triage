"""Breaker-monitor readings (``BRE``) for breaker.jsonl, one row per device per sweep.

``BRE`` is read only on families whose command policy has it (351, 700G, 751); the 651,
735 and 851 have no breaker monitor command. The row keeps the normalized fields
(``breaker_wear_percent`` = the worst phase, ``operation_count``) plus per-phase wear and
the family-specific details, so ``sel-breaker-trend`` can follow each breaker over time.
"""

from typing import Any, Dict, Optional

from ..integrations.devices.sel.commands import COMMANDS_BY_FAMILY
from . import records

BREAKER_FAMILIES = frozenset(family for family, commands in COMMANDS_BY_FAMILY.items() if "breaker" in commands)


def reads_breaker(family: Optional[str]) -> bool:
    return family in BREAKER_FAMILIES


def breaker_row(adapter: Any, text: str, read_at: str) -> Dict[str, Any]:
    """Parse one BRE response into a breaker.jsonl row (``bre_parse`` says how it went)."""

    row: Dict[str, Any] = {"read_at": read_at, "breaker_parser_version": records.BREAKER_PARSER_VERSION}
    try:
        parsed = adapter.parse("breaker", text)
    except Exception as error:  # parser gaps never stop a sweep
        row.update(bre_parse="parse_failed", bre_error=str(error)[:300])
        return row
    details = dict(parsed.get("details") or {})
    row.update(
        bre_parse="parsed",
        bre_error=None,
        monitor_enabled=details.pop("monitor_enabled", None),
        breaker_wear_percent=parsed.get("breaker_wear_percent"),
        operation_count=parsed.get("operation_count"),
        wear_percent=details.pop("wear_percent", None),
        relay_trip_count=details.pop("relay_trip_count", None),
        external_trip_count=details.pop("external_trip_count", None),
        last_reset=details.pop("last_reset", None),
        breaker=details.pop("breaker", None),
        details=details,
    )
    if row["monitor_enabled"] is None and row["breaker_wear_percent"] is not None:
        row["monitor_enabled"] = True
    return row


__all__ = ["BREAKER_FAMILIES", "breaker_row", "reads_breaker"]
