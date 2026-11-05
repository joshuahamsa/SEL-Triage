from __future__ import annotations

from pathlib import Path

from .cev_parser import parse_cev
from .eve_parser import EveParseError, parse_eve
from .model import EventRecord


def parse_event(path: Path) -> EventRecord:
    path = Path(path)
    probe = path.read_bytes()[:16384].decode("latin-1", errors="replace")
    cev_signature = '"REF_NUM","FREQ","SAM/CYC_A"' in probe and '"TRIG"' in probe
    eve_signature = "Event Number" in probe and "Time Source:" in probe
    if cev_signature:
        if path.suffix.lower() == ".eve":
            raise EveParseError("CEV content has an EVE filename extension")
        return parse_cev(path)
    if eve_signature:
        if path.suffix.lower() == ".cev":
            raise EveParseError("EVE content has a CEV filename extension")
        return parse_eve(path)
    raise EveParseError(f"unrecognized SEL event format: {path}")
