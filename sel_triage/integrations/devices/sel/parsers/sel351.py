"""Parsers for SEL-351-family (351, 351A, 351S) responses.

Identity comes from anonymized SEL-Audit captures (FID "SEL-351-5-..." is a
SEL-351). STA, MET, BRE, HIS and TAR are verified against live SEL-351A,
SEL-351 and SEL-351S output (R518 firmware, 2026-09-25), which share one
layout: two-digit years, voltages in kV, power in MW.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Match, Optional, Set

from .common import (
    NUMBER,
    PF_DIRECTIONS,
    column_tables,
    nonempty_lines,
    parse_labeled_scalars,
    remaining_lines,
    use_row,
)
from .sel735 import _clock_fields


_FID = re.compile(r'"FID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_DEVID = re.compile(r'"DEVID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_MODEL = re.compile(r"\bSEL-351[AS]?(?=-|\b)", re.I)


# Column names here include "A/D" and plain numbers ("50", "51", "81").
_HEADER_TOKEN = re.compile(r"^[+-]?[0-9A-Z_./]+$")
_STATUS_WORDS = {"OK", "NA", "W", "F", "WARN", "FAIL"}
_NUM = r"[-+]?\d+(?:\.\d+)?"
_OSH = re.compile(r"^OSH((?:\s+" + _NUM + r")+)$")
_FREQ_VDC = re.compile(r"^FREQ \(Hz\)\s+(?P<freq>" + _NUM + r")(?:\s+VDC \(V\)\s+(?P<vdc>" + _NUM + r"))?$")
_BREAKER_HEADERS = {"A-phase B-phase C-phase", "Trip A Trip B Trip C Cls A Cls B Cls C", "Alarm Total Count"}
_BREAKER_PHASE_ROWS = {
    "Accum Contact Wear (%)": "wear_percent",
    "Rly Accum Pri Current (kA)": "relay_accum_current_ka",
    "Ext Accum Pri Current (kA)": "external_accum_current_ka",
}
_BREAKER_COUNTS = {"Rly Trip Count": "relay_trip_count", "Ext Trip Count": "external_trip_count"}
_OP_TIMES = {
    "Avg. Elect Op Time (ms)": ("electrical_op_time_ms", "average"),
    "Last Elect Op Time (ms)": ("electrical_op_time_ms", "last"),
    "Avg. Mech Op Time (ms)": ("mechanical_op_time_ms", "average"),
    "Last Mech Op Time (ms)": ("mechanical_op_time_ms", "last"),
}
_SIX_OP_COLUMNS = ("trip_a", "trip_b", "trip_c", "close_a", "close_b", "close_c")
_ALARMS = re.compile(r"^(?P<kind>Mechanical|Electrical) Operating Time\s+\S+\s+(?P<count>\d+)$")
_LAST_RESET = re.compile(
    r"^LAST RESET\s+(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})$"
)
_LABELED_VALUES = re.compile(r"^(?P<label>\S.*?)\s+(?P<values>" + _NUM + r"\+?(?:\s+" + _NUM + r"\+?)*)$")
_HISTORY_HEADER = re.compile(r"^#\s+DATE\s+TIME\s+EVENT\s+LOCAT\s+CURR\s+FREQ\s+GRP\s+SHOT\s+TARGETS\b")
_HISTORY_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<event>\S+)\s+(?P<location>\S+)\s+"
    r"(?P<current>-?\d+)\s+(?P<freq>" + _NUM + r")\s+(?P<group>\d+)"
    r"(?:\s+(?P<shot>\d+)(?=\s|$))?(?:\s+(?P<targets>.*?))?\s*$"
)


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


def _number(token: str) -> Any:
    return float(token) if "." in token else int(token)


def _iso2(match: Match[str], time_group: str = "time") -> str:
    return "20{0}-{1}-{2}T{3}".format(
        match.group("year"), match.group("month"), match.group("day"), match.group(time_group)
    )


def parse_status(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    values = _clock_fields(lines, consumed)
    details: Dict[str, Any] = {}
    offset_columns: List[str] = []
    for table in column_tables(lines, _HEADER_TOKEN):
        columns = table["columns"]
        for label, row, row_index in table["rows"]:
            cells = dict(zip(columns, row))
            if label == "OS":
                details["offsets"] = cells
                offset_columns = columns
            elif label == "PS":
                details["power_supplies_v"] = cells
            elif label == "" and all(isinstance(v, (int, float)) or str(v).upper() in _STATUS_WORDS for v in row) and any(
                isinstance(v, str) for v in row
            ):
                for name, value in cells.items():
                    if name == "TEMP" and isinstance(value, (int, float)):
                        details["temperature_c"] = value
                    else:
                        details.setdefault("self_tests", {})[name] = value
            else:
                continue
            use_row(consumed, table, row_index)
    for index, line in lines:
        stripped = line.strip()
        osh = _OSH.match(stripped)
        if osh is not None and offset_columns:
            numbers = [_number(v) for v in osh.group(1).split()]
            details["offsets_high"] = dict(zip(offset_columns, numbers))
            consumed.add(index)
        elif stripped in ("Relay Enabled", "Relay Disabled"):
            details["relay_enabled"] = stripped == "Relay Enabled"
            consumed.add(index)
    tests = [str(v).upper() for v in details.get("self_tests", {}).values() if isinstance(v, str)]
    if tests:
        if any(v in ("F", "FAIL") for v in tests):
            values["self_test"] = "FAIL"
        elif any(v in ("W", "WARN") for v in tests):
            values["self_test"] = "WARN"
        else:
            values["self_test"] = "OK"
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


_METER_ROWS = {
    "I MAG (A)": "currents_a",
    "I ANG (DEG)": "current_angles_deg",
    "V MAG (KV)": "voltages_kv",
    "V ANG (DEG)": "voltage_angles_deg",
    "MW": "power_mw",
    "MVAR": "reactive_mvar",
    "PF": "power_factor",
}


def parse_meter(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    _clock_fields(lines, consumed)
    details: Dict[str, Any] = {}
    for table in column_tables(lines, _HEADER_TOKEN):
        columns = table["columns"]
        sequence = "V1" in columns
        for label, row, row_index in table["rows"]:
            cells = dict(zip(columns, row))
            if sequence and label == "MAG":
                # Voltages are printed in kV; store volts like the other models.
                details["sequence_magnitudes"] = {
                    name: round(value * 1000.0, 3) if name.lstrip("3").startswith("V") else value
                    for name, value in cells.items()
                }
            elif sequence and label == "ANG (DEG)":
                details["sequence_angles_deg"] = cells
            elif label in _METER_ROWS:
                details[_METER_ROWS[label]] = cells
            elif label == "" and all(v in PF_DIRECTIONS for v in row):
                details["power_factor_direction"] = cells
            else:
                continue
            use_row(consumed, table, row_index)
    values: Dict[str, Any] = {}
    for index, line in lines:
        match = _FREQ_VDC.match(line.strip())
        if match is not None:
            values["frequency_hz"] = float(match.group("freq"))
            if match.group("vdc") is not None:
                details["station_dc_v"] = float(match.group("vdc"))
            consumed.add(index)
    power = details.get("power_mw", {})
    if isinstance(power.get("3P"), (int, float)):
        values["active_power_mw"] = float(power["3P"])
    currents, voltages = details.get("currents_a", {}), details.get("voltages_kv", {})
    phases = []
    for phase in ("A", "B", "C"):
        current, voltage = currents.get(phase), voltages.get(phase)
        if isinstance(current, (int, float)) and isinstance(voltage, (int, float)):
            phases.append({"phase": phase, "voltage_kv": float(voltage), "current_a": float(current)})
    if len(phases) == 3:
        values["phases"] = phases
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def _op_values(tokens: List[str], names, over_range: List[str], prefix: str) -> Dict[str, float]:
    result = {}
    for name, token in zip(names, tokens):
        if token.endswith("+"):
            over_range.append("{0}.{1}".format(prefix, name))
            token = token[:-1]
        result[name] = float(token)
    return result


def parse_breaker(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    _clock_fields(lines, consumed)
    details: Dict[str, Any] = {}
    for index, line in lines:
        stripped = " ".join(line.split())
        if stripped in _BREAKER_HEADERS:
            consumed.add(index)
            continue
        for pattern, handle in (
            (_ALARMS, lambda m: details.setdefault("operating_time_alarms", {}).__setitem__(
                m.group("kind").lower(), int(m.group("count")))),
            (_LAST_RESET, lambda m: details.__setitem__("last_reset", _iso2(m))),
        ):
            match = pattern.match(stripped)
            if match is not None:
                handle(match)
                consumed.add(index)
                break
        else:
            match = _LABELED_VALUES.match(stripped)
            if match is None:
                continue
            label, tokens = match.group("label"), match.group("values").split()
            if label in _BREAKER_PHASE_ROWS and len(tokens) == 3:
                details[_BREAKER_PHASE_ROWS[label]] = dict(zip("ABC", (_number(t) for t in tokens)))
            elif label in _BREAKER_COUNTS and len(tokens) == 1:
                details[_BREAKER_COUNTS[label]] = int(tokens[0])
            elif label in _OP_TIMES and len(tokens) in (2, 6):
                group, which = _OP_TIMES[label]
                target = details.setdefault(group, {})
                over = target.setdefault("over_range", [])
                names = _SIX_OP_COLUMNS if len(tokens) == 6 else ("trip", "close")
                target[which] = _op_values(tokens, names, over, which)
            elif label == "Last Op Minimum VDC (V)" and len(tokens) == 2:
                details["last_op_minimum_vdc"] = {"trip": float(tokens[0]), "close": float(tokens[1])}
            else:
                continue
            consumed.add(index)
    for group in ("electrical_op_time_ms", "mechanical_op_time_ms"):
        if group in details and not details[group]["over_range"]:
            del details[group]["over_range"]
    values: Dict[str, Any] = {}
    wear = [v for v in details.get("wear_percent", {}).values() if isinstance(v, (int, float))]
    if wear:
        values["breaker_wear_percent"] = float(max(wear))
    counts = [details.get("relay_trip_count"), details.get("external_trip_count")]
    if any(isinstance(c, int) for c in counts):
        values["operation_count"] = sum(c for c in counts if isinstance(c, int))
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_history(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    _clock_fields(lines, consumed)
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
        shot: Optional[int] = int(match.group("shot")) if match.group("shot") is not None else None
        events.append(
            {
                "event_number": int(match.group("number")),
                "timestamp": _iso2(match),
                "event_type": match.group("event"),
                "details": {
                    "location": match.group("location"),
                    "current_a": int(match.group("current")),
                    "frequency_hz": float(match.group("freq")),
                    "group": int(match.group("group")),
                    "shot": shot,
                    "targets": (match.group("targets") or "").strip(),
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
    for table in column_tables(lines, _HEADER_TOKEN):
        for label, row, row_index in table["rows"]:
            if label == "" and all(value in (0, 1) for value in row):
                targets.extend({"name": name, "asserted": value == 1} for name, value in zip(table["columns"], row))
                use_row(consumed, table, row_index)
    values: Dict[str, Any] = {}
    if targets:
        values["targets"] = targets
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


__all__ = ["parse_breaker", "parse_history", "parse_identity", "parse_meter", "parse_status", "parse_target"]
