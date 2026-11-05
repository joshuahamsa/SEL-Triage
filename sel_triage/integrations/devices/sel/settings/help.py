"""Parse an SEL device's ``HELP`` response (offline).

Format (SEL-751 and similar)::

    METER            - Display metering data.
    89CLOSE          - Close Disconnect m n
                       m = L or E for 3 Pos Disconnects, n = 1-8
    CAUTION: For security purposes, some commands are not provided in this HELP ...

A command line is the name, padding, ``-`` and a description; an indented line continues
the description above. ``HELP`` deliberately omits elevated-privilege, identification and
configuration commands, so it is the firmware's *advertised* list, not the complete one
(the instruction manual is). A device that does not know ``HELP`` answers
``Invalid Command`` or ``"HELP" unknown``: that is reported as ``rejected``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_COMMAND = re.compile(r"^(?P<command>[A-Z0-9][A-Z0-9_/]*)\s+-\s+(?P<description>.*)$")
_REJECTED = re.compile(r'invalid command|"\w+" unknown', re.IGNORECASE)
_FRAMING = re.compile(r"[\x02\x03]")


def parse_help(text: str) -> Dict[str, Any]:
    lines = _FRAMING.sub("", text).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    commands: List[Dict[str, str]] = []
    notes: List[str] = []
    current = None
    in_note = False
    for raw in lines:
        if not raw.strip():
            current = None
            in_note = False
            continue
        stripped = raw.strip()
        match = _COMMAND.match(raw)
        if match is not None:
            current = {"command": match.group("command"), "description": match.group("description").strip()}
            commands.append(current)
            in_note = False
            continue
        if raw[0] == " ":
            if in_note and notes:
                notes[-1] = "{0} {1}".format(notes[-1], stripped)
            elif current is not None:
                current["description"] = "{0} {1}".format(current["description"], stripped).strip()
            continue
        current = None
        if stripped.upper().startswith(("CAUTION", "NOTE")):
            notes.append(stripped)
            in_note = True
    rejected = not commands and bool(_REJECTED.search(text))
    return {"commands": commands, "notes": notes, "rejected": rejected}


__all__ = ["parse_help"]
