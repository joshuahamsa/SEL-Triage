"""Parsers for SEL-851 responses, verified against live output.

Identity comes from anonymized SEL-Audit captures; STA, MET, HIS and TAR from
a live SEL-851 (R100 firmware, 2026-09-25). STA shares the SEL-700G layout.
MET is mostly labeled lines, TAR prints one LED per line, and the 851 does
not support BRE.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Match, Optional, Set

from . import sel700g
from .common import NUMBER, nonempty_lines, parse_labeled_scalars, remaining_lines


_FID = re.compile(r'"FID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_DEVID = re.compile(r'"DEVID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_MODEL = re.compile(r"\bSEL-851\b", re.I)


_NUM = r"[-+]?\d+(?:\.\d+)?"
_HEADER_TOKEN = re.compile(r"^[0-9A-Z]+$")
_LABELED_ROW = re.compile(r"^(?P<label>[A-Za-z][^\d]*?)\s+(?P<values>" + _NUM + r"(?:\s+" + _NUM + r")*)$")
_METER_SCALARS = (
    (re.compile(r"^Ave Curr Mag \(A pri\.\)\s+(?P<v>" + _NUM + r")$"), ("average_current_a",)),
    (re.compile(r"^Pos-Seq Curr I1 \(A pri\.\)\s+(?P<v>" + _NUM + r")$"), ("sequence_magnitudes", "I1")),
    (re.compile(r"^Neg-Seq Curr 3I2 \(A pri\.\)\s+(?P<v>" + _NUM + r")$"), ("sequence_magnitudes", "3I2")),
    (re.compile(r"^Pos-Seq Volt V1 \(V pri\.\)\s+(?P<v>" + _NUM + r")$"), ("sequence_magnitudes", "V1")),
    (re.compile(r"^Neg-Seq Volt 3V2 \(V pri\.\)\s+(?P<v>" + _NUM + r")$"), ("sequence_magnitudes", "3V2")),
    (re.compile(r"^Real Power \(kW\)\s+(?P<v>" + _NUM + r")$"), ("power_kw",)),
    (re.compile(r"^Reactive Power \(kVAR\)\s+(?P<v>" + _NUM + r")$"), ("reactive_kvar",)),
    (re.compile(r"^Apparent Power \(kVA\)\s+(?P<v>" + _NUM + r")$"), ("apparent_kva",)),
    (re.compile(r"^Frequency \(Hz\)\s+(?P<v>" + _NUM + r")$"), ("frequency_hz",)),
)
_POWER_FACTOR = re.compile(r"^Power Factor \((?P<dir>LEAD|LAG)\)\s+(?P<v>" + _NUM + r")$")
_HISTORY_HEADER = re.compile(r"^#\s+DATE\s+TIME\s+EVENT\s+CURR\s+FREQ\s+TARGETS\b")
_HISTORY_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<event>\S(?:.*?\S)?)\s+"
    r"(?P<current>" + _NUM + r")\s+(?P<freq>" + _NUM + r")\s+(?P<targets>[01]+)$"
)
_TARGET_LINE = re.compile(r"^(?P<name>\S+)\s+(?P<value>[01])$")

parse_status = sel700g.parse_status


def _text(match: Match[str]) -> str:
    return match.group("value").strip()


def parse_identity(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    values, consumed = parse_labeled_scalars(
        lines,
        {
            "firmware_id": (_FID, _text),
            "device_id": (_DEVID, _text),
        },
    )
    firmware_id = values.get("firmware_id")
    if firmware_id is not None:
        model = _MODEL.search(firmware_id)
        if model is not None:
            values["observed_model"] = model.group(0).upper()
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def _row_target(label: str, columns: List[str]) -> Optional[str]:
    line_to_line = "VAB" in columns
    return {
        "Current Magnitude (A pri.)": "currents_a",
        "Current Angle (deg)": "current_angles_deg",
        "Voltage Magnitude (V pri.)": "voltages_ll_v" if line_to_line else "voltages_ln_v",
        "Voltage Angle (deg)": "voltage_ll_angles_deg" if line_to_line else "voltage_ln_angles_deg",
    }.get(label)


def parse_meter(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    details: Dict[str, Any] = {}
    values: Dict[str, Any] = {}
    columns: List[str] = []
    header_index: Optional[int] = None
    for index, line in lines:
        stripped = " ".join(line.split())
        handled = False
        for pattern, path in _METER_SCALARS:
            match = pattern.match(stripped)
            if match is not None:
                value = float(match.group("v"))
                if path[0] == "sequence_magnitudes":
                    details.setdefault("sequence_magnitudes", {})[path[1]] = value
                elif path[0] == "frequency_hz":
                    values["frequency_hz"] = value
                else:
                    details[path[0]] = value
                handled = True
                break
        if not handled:
            match = _POWER_FACTOR.match(stripped)
            if match is not None:
                details["power_factor"] = float(match.group("v"))
                details["power_factor_direction"] = match.group("dir")
                handled = True
        if handled:
            consumed.add(index)
            continue
        tokens = stripped.split()
        if tokens and all(_HEADER_TOKEN.match(t) for t in tokens) and not all(NUMBER.match(t) for t in tokens):
            columns, header_index = tokens, index
            continue
        match = _LABELED_ROW.match(stripped)
        if match is None or not columns:
            continue
        numbers = [float(v) for v in match.group("values").split()]
        target = _row_target(match.group("label"), columns)
        # Angle rows can be shorter than their header (no angle for VAVG).
        if target is None or len(numbers) > len(columns):
            continue
        details[target] = dict(zip(columns, numbers))
        consumed.add(index)
        consumed.add(header_index)
    power = details.get("power_kw")
    if isinstance(power, float):
        values["active_power_mw"] = round(power / 1000.0, 6)
    currents, voltages = details.get("currents_a", {}), details.get("voltages_ln_v", {})
    phases = []
    for phase in ("A", "B", "C"):
        current, voltage = currents.get("I" + phase), voltages.get("V" + phase)
        if current is not None and voltage is not None:
            phases.append({"phase": phase, "voltage_kv": round(voltage / 1000.0, 6), "current_a": current})
    if len(phases) == 3:
        values["phases"] = phases
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_history(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    _, consumed = sel700g._clock_fields(lines)
    events: List[Dict[str, Any]] = []
    in_table = False
    for index, line in lines:
        stripped = line.strip()
        if _HISTORY_HEADER.match(stripped):
            in_table = True
            consumed.add(index)
            continue
        match = _HISTORY_ROW.match(stripped) if in_table else None
        if match is None:
            continue
        events.append(
            {
                "event_number": int(match.group("number")),
                "timestamp": "{0}-{1}-{2}T{3}".format(
                    match.group("year"), match.group("month"), match.group("day"), match.group("time")
                ),
                "event_type": match.group("event"),
                "details": {
                    "current_a": float(match.group("current")),
                    "frequency_hz": float(match.group("freq")),
                    "targets": match.group("targets"),
                },
            }
        )
        consumed.add(index)
    values: Dict[str, Any] = {}
    if events:
        values["events"] = events
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_target(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    targets: List[Dict[str, Any]] = []
    for index, line in lines:
        match = _TARGET_LINE.match(line.strip())
        if match is not None:
            targets.append({"name": match.group("name"), "asserted": match.group("value") == "1"})
            consumed.add(index)
    values: Dict[str, Any] = {}
    if targets:
        values["targets"] = targets
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


__all__ = ["parse_history", "parse_identity", "parse_meter", "parse_status", "parse_target"]
