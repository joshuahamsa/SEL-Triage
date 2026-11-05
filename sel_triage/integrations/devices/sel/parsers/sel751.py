"""Parsers for SEL-751-family responses, verified against live output.

Identity comes from real captures; STA, MET, BRE, HIS and TAR from a live
SEL-751 (R400 firmware, 2026-09-25), and the shorter 751A HIS layout from a
live SEL-751A (R420, 2026-10-12). SER uses ``common.parse_ser_table``. STA and TAR print the same layout as the
SEL-700G, so those parsers are shared.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Match, Set

from . import sel700g
from .common import (
    PF_DIRECTIONS,
    column_tables,
    nonempty_lines,
    parse_labeled_scalars,
    remaining_lines,
    use_row,
)


_FID = re.compile(r'"FID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_DEVID = re.compile(r'"DEVID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_MODEL = re.compile(r"\bSEL-751A?\b", re.I)
_NUM = r"[-+]?\d+(?:\.\d+)?"
_METER_SCALARS = (
    (re.compile(r"^Ave Curr Mag\s+\(A pri\.\)\s+(?P<v>" + _NUM + r")$"), ("average_current_a",)),
    (re.compile(r"^Neg-Seq Curr 3I2\s+\(A pri\.\)\s+(?P<v>" + _NUM + r")$"), ("sequence_magnitudes", "3I2")),
    (re.compile(r"^Current Imb \(%\)\s+(?P<v>" + _NUM + r")$"), ("current_imbalance_percent",)),
    (re.compile(r"^Avg Phase\s+\(V pri\.\)\s+(?P<v>" + _NUM + r")$"), ("average_phase_voltage_v",)),
    (re.compile(r"^Neg-Seq Volt 3V2\s+\(V pri\.\)\s+(?P<v>" + _NUM + r")$"), ("sequence_magnitudes", "3V2")),
    (re.compile(r"^Voltage Imb \(%\)\s+(?P<v>" + _NUM + r")$"), ("voltage_imbalance_percent",)),
)
_POWER_ROWS = {
    "Real Pwr (kW)": "power_kw",
    "Reactive Pwr (kVAR)": "reactive_kvar",
    "Apparent Pwr (kVA)": "apparent_kva",
    "Pwr Factor": "power_factor",
}
_EBMON_OFF = re.compile(r"^Breaker Monitor setting EBMON not enabled$", re.I)
_HISTORY_HEADER = re.compile(r"^#\s+REF\s+DATE\s+TIME\s+EVENT\s+LOCAT\s+CURRENT\s+FREQ\s+TARGETS\b")
_HISTORY_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<ref>\d+)\s+"
    r"(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<event>\S(?:.*?\S)?)\s+"
    r"(?P<location>\S+)\s+(?P<current>" + _NUM + r")\s+(?P<freq>" + _NUM + r")\s+(?P<targets>[01]+)$"
)
# SEL-751A (R420, live 2026-10-12) prints HIS without the REF and LOCAT columns.
_HISTORY_HEADER_SHORT = re.compile(r"^#\s+DATE\s+TIME\s+EVENT\s+CURRENT\s+FREQ\s+TARGETS\b")
_HISTORY_ROW_SHORT = re.compile(
    r"^(?P<number>\d+)\s+"
    r"(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<event>\S(?:.*?\S)?)\s+"
    r"(?P<current>" + _NUM + r")\s+(?P<freq>" + _NUM + r")\s+(?P<targets>[01]+)$"
)

parse_status = sel700g.parse_status
parse_target = sel700g.parse_target


def _text(match: Match[str]) -> str:
    return match.group("value").strip()


def _scalar(token: str) -> Any:
    return float(token) if "." in token else int(token)


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


def parse_meter(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    sequence: Dict[str, Any] = {}
    details: Dict[str, Any] = {}
    for table in column_tables(lines):
        columns = table["columns"]
        for label, row, row_index in table["rows"]:
            cells = dict(zip(columns, row))
            if label.startswith("Mag (A") or label.startswith("Mag (V") or label.startswith("Angle"):
                magnitude = label.startswith("Mag")
                if "IA" in columns:
                    phase_cells = {k: v for k, v in cells.items() if k != "I1"}
                    target = "currents_a" if magnitude else "current_angles_deg"
                    if magnitude and "I1" in cells:
                        sequence["I1"] = cells["I1"]
                elif "VAB" in columns:
                    phase_cells = {k: v for k, v in cells.items() if k != "V1"}
                    target = "voltages_ll_v" if magnitude else "voltage_ll_angles_deg"
                    if magnitude and "V1" in cells:
                        sequence["V1"] = cells["V1"]
                elif "VA" in columns:
                    phase_cells = cells
                    target = "voltages_ln_v" if magnitude else "voltage_ln_angles_deg"
                else:
                    continue
                details.setdefault(target, {}).update(phase_cells)
            elif label in _POWER_ROWS:
                details.setdefault(_POWER_ROWS[label], {}).update(cells)
            elif label == "" and all(v in PF_DIRECTIONS for v in row):
                details.setdefault("power_factor_direction", {}).update(cells)
            elif label == "Frequency (Hz)" and columns == ["FREQ"]:
                details["frequency_hz"] = row[0]
            else:
                continue
            use_row(consumed, table, row_index)
    for index, line in lines:
        stripped = line.strip()
        for pattern, path in _METER_SCALARS:
            match = pattern.match(stripped)
            if match is None:
                continue
            value = _scalar(match.group("v"))
            if path[0] == "sequence_magnitudes":
                sequence[path[1]] = value
            else:
                details[path[0]] = value
            consumed.add(index)
            break
    if sequence:
        details["sequence_magnitudes"] = sequence

    values: Dict[str, Any] = {}
    frequency = details.pop("frequency_hz", None)
    if isinstance(frequency, (int, float)):
        values["frequency_hz"] = float(frequency)
    power = details.get("power_kw", {})
    if isinstance(power.get("3P"), (int, float)):
        values["active_power_mw"] = round(power["3P"] / 1000.0, 6)
    currents, voltages = details.get("currents_a", {}), details.get("voltages_ln_v", {})
    phases: List[Dict[str, Any]] = []
    for phase in ("A", "B", "C"):
        current, voltage = currents.get("I" + phase), voltages.get("V" + phase)
        if isinstance(current, (int, float)) and isinstance(voltage, (int, float)):
            phases.append({"phase": phase, "voltage_kv": round(voltage / 1000.0, 6), "current_a": float(current)})
    if len(phases) == 3:
        values["phases"] = phases
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_breaker(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    for index, line in lines:
        if _EBMON_OFF.match(line.strip()):
            return {
                "details": {"monitor_enabled": False},
                "unparsed_lines": remaining_lines(lines, {index}),
            }
    # With the monitor enabled the 751 is expected to match the 700G layout;
    # anything that does not match stays in unparsed_lines.
    values = sel700g.parse_breaker(text)
    values.setdefault("details", {})["monitor_enabled"] = True
    return values


def parse_history(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    events: List[Dict[str, Any]] = []
    row_pattern = None
    for index, line in lines:
        stripped = line.strip()
        if _HISTORY_HEADER.match(stripped):
            row_pattern = _HISTORY_ROW
            consumed.add(index)
            continue
        if _HISTORY_HEADER_SHORT.match(stripped):
            row_pattern = _HISTORY_ROW_SHORT
            consumed.add(index)
            continue
        match = row_pattern.match(stripped) if row_pattern is not None else None
        if match is None:
            continue
        details: Dict[str, Any] = {}
        if row_pattern is _HISTORY_ROW:
            details["reference"] = int(match.group("ref"))
            details["location"] = match.group("location")
        details["current_a"] = float(match.group("current"))
        details["frequency_hz"] = float(match.group("freq"))
        details["targets"] = match.group("targets")
        events.append(
            {
                "event_number": int(match.group("number")),
                "timestamp": "{0}-{1}-{2}T{3}".format(
                    match.group("year"), match.group("month"), match.group("day"), match.group("time")
                ),
                "event_type": match.group("event"),
                "details": details,
            }
        )
        consumed.add(index)
    _, clock_consumed = sel700g._clock_fields(lines)
    consumed.update(clock_consumed)
    values: Dict[str, Any] = {}
    if events:
        values["events"] = events
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


__all__ = ["parse_breaker", "parse_history", "parse_identity", "parse_meter", "parse_status", "parse_target"]
