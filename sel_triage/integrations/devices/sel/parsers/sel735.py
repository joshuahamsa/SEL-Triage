"""Parsers for SEL-735 meter responses, verified against live output.

Identity comes from anonymized SEL-Audit captures; STA, MET, HIS and TAR from
a live SEL-735 (R207 firmware, 2026-09-25). Dates use two-digit years, the
time source is abbreviated ("int"), and column names can be mixed case.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Match, Set

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
_MODEL = re.compile(r"\bSEL-735\b", re.I)
_HEADER_TOKEN = re.compile(r"^(\*|[+-]?[0-9A-Za-z_.]*[A-Za-z][0-9A-Za-z_.]*)$")
_DATE_TIME = re.compile(
    r"Date:\s*(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{2}(?:\d{2})?)\s+"
    r"Time:\s*(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)
_TIME_SOURCE = re.compile(r"Time Source:\s*(?P<value>\S+)")
_TIME_SOURCES = {"int": "internal", "ext": "external"}
_NUM = r"[-+]?\d+(?:\.\d+)?"
_FREQUENCY = re.compile(r"^FREQ \(Hz\)\s+(?P<value>{0})$".format(_NUM))
_FREQUENCY_NOMINAL = re.compile(r"^F\(%NOM\)\s+(?P<value>{0})$".format(_NUM))
_HISTORY_HEADER = re.compile(r"^#\s+DATE\s+TIME\s+EVENT\s+FREQ\s+TARGETS\b")
_HISTORY_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<event>\S(?:.*?\S)?)\s+"
    r"(?P<freq>" + _NUM + r")\s+(?P<targets>[01]+)$"
)
_STATUS_TITLES = {"SELF TESTS", "Meter Enabled", "Meter Disabled"}


def _text(match: Match[str]) -> str:
    return match.group("value").strip()


def _iso(match: Match[str]) -> str:
    year = match.group("year")
    if len(year) == 2:
        year = "20" + year
    return "{0}-{1}-{2}T{3}".format(year, match.group("month"), match.group("day"), match.group("time"))


def _key(label: str) -> str:
    return re.sub(r"\s+", "", label).upper()


def _clock_fields(lines, consumed: Set[int]) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for index, line in lines:
        stamp = _DATE_TIME.search(line)
        if stamp is not None and "clock" not in values:
            values["clock"] = _iso(stamp)
            consumed.add(index)
        source = _TIME_SOURCE.search(line)
        if source is not None and "time_source" not in values:
            raw = source.group("value").lower()
            values["time_source"] = _TIME_SOURCES.get(raw, raw)
            consumed.add(index)
    return values


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


def _flagged(value: Any) -> str:
    """Return "FAIL", "WARN" or "" for one self-test cell (W=Warn, F=Fail)."""

    if not isinstance(value, str):
        return ""
    upper = value.upper()
    if upper in ("F", "FAIL") or (upper.endswith("F") and upper[:-1].replace(".", "", 1).lstrip("-").isdigit()):
        return "FAIL"
    if upper in ("W", "WARN") or (upper.endswith("W") and upper[:-1].replace(".", "", 1).lstrip("-").isdigit()):
        return "WARN"
    return ""


def _number(value: Any) -> Any:
    if isinstance(value, str) and value[-1:].upper() in ("W", "F"):
        try:
            return float(value[:-1])
        except ValueError:
            return value
    return value


def parse_status(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    values = _clock_fields(lines, consumed)
    details: Dict[str, Any] = {}
    flags: Dict[str, str] = {}
    for table in column_tables(lines, _HEADER_TOKEN):
        columns = table["columns"]
        for label, row, row_index in table["rows"]:
            cells = dict(zip(columns, row))
            if label == "OS":
                details["offsets"] = cells
            elif label == "" and columns[:2] == ["Batt", "TEMP"]:
                details["battery_v"] = _number(cells["Batt"])
                details["temperature_c"] = _number(cells["TEMP"])
                details["battery_warning"] = _flagged(cells["Batt"]) == "WARN"
            elif label == "" and all(
                isinstance(v, str) and (v.upper() in ("OK", "W", "F", "WARN", "FAIL") or _flagged(v))
                for v in row
            ):
                details.setdefault("self_tests", {}).update(cells)
            else:
                continue
            for name, cell in cells.items():
                flag = _flagged(cell)
                if flag:
                    flags[name] = flag
            use_row(consumed, table, row_index)
    for index, line in lines:
        stripped = line.strip()
        if stripped in _STATUS_TITLES:
            consumed.add(index)
            if stripped.startswith("Meter "):
                details["meter_enabled"] = stripped == "Meter Enabled"
    if "self_tests" in details or flags:
        states = set(flags.values())
        values["self_test"] = "FAIL" if "FAIL" in states else "WARN" if "WARN" in states else "OK"
    if flags:
        details["warning_items"] = sorted(flags)
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


_REACTIVE = {
    "QDELLAG(KVAR)": "del_lag",
    "QDELLEAD(KVAR)": "del_lead",
    "QRECLAG(KVAR)": "rec_lag",
    "QRECLEAD(KVAR)": "rec_lead",
}


def parse_meter(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    details: Dict[str, Any] = {}
    for table in column_tables(lines, _HEADER_TOKEN):
        columns = table["columns"]
        line_to_line = columns == ["AB", "BC", "CA"]
        sequence = "V1" in columns or "I1" in columns
        for label, row, row_index in table["rows"]:
            cells = dict(zip(columns, row))
            key = _key(label)
            if key == "IMAG(A)":
                target = "currents_a"
            elif key == "IANG(DEG)":
                target = "current_angles_deg"
            elif key == "VMAG(V)":
                target = "voltages_ll_v" if line_to_line else "voltages_ln_v"
            elif key == "VANG(DEG)":
                target = "voltage_ll_angles_deg" if line_to_line else "voltage_ln_angles_deg"
            elif key == "W(KW)":
                target = "power_kw"
            elif key == "S(KVA)":
                target = "apparent_kva"
            elif key in _REACTIVE:
                details.setdefault("reactive_kvar", {})[_REACTIVE[key]] = cells
                use_row(consumed, table, row_index)
                continue
            elif key == "DISPPF":
                target = "power_factor"
            elif key == "" and all(v in PF_DIRECTIONS for v in row):
                target = "power_factor_direction"
            elif sequence and key == "MAG":
                target = "sequence_magnitudes"
            elif sequence and key == "ANG(DEG)":
                target = "sequence_angles_deg"
            elif key == "V(%NOM)":
                target = "voltage_percent_nominal"
            else:
                continue
            details.setdefault(target, {}).update(cells)
            use_row(consumed, table, row_index)
    values: Dict[str, Any] = {}
    values.update(_clock_fields(lines, consumed))
    values.pop("clock", None)
    values.pop("time_source", None)
    for index, line in lines:
        stripped = line.strip()
        frequency = _FREQUENCY.match(stripped)
        if frequency is not None:
            values["frequency_hz"] = float(frequency.group("value"))
            consumed.add(index)
        nominal = _FREQUENCY_NOMINAL.match(stripped)
        if nominal is not None:
            details["frequency_percent_nominal"] = float(nominal.group("value"))
            consumed.add(index)
    power = details.get("power_kw", {})
    if isinstance(power.get("3P"), (int, float)):
        values["active_power_mw"] = round(power["3P"] / 1000.0, 6)
    currents = details.get("currents_a", {})
    voltages = details.get("voltages_ln_v", {})
    phases: List[Dict[str, Any]] = []
    for phase in ("A", "B", "C"):
        current, voltage = currents.get(phase), voltages.get(phase)
        if isinstance(current, (int, float)) and isinstance(voltage, (int, float)):
            phases.append({"phase": phase, "voltage_kv": round(voltage / 1000.0, 6), "current_a": float(current)})
    if len(phases) == 3:
        values["phases"] = phases
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
        events.append(
            {
                "event_number": int(match.group("number")),
                "timestamp": _iso(match),
                "event_type": match.group("event"),
                "details": {"frequency_hz": float(match.group("freq")), "targets": match.group("targets")},
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


__all__ = ["parse_history", "parse_identity", "parse_meter", "parse_status", "parse_target"]
