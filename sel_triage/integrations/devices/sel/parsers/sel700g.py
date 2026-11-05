"""Parsers for SEL-700G and SEL-700GT responses, verified against live output."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Match, Optional, Set, Tuple

from .common import PF_DIRECTIONS as _PF_DIRECTIONS
from .common import column_tables, nonempty_lines, parse_labeled_scalars, remaining_lines, use_row


_FID = re.compile(r'"FID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_DEVID = re.compile(r'"DEVID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_MODEL = re.compile(r"\bSEL-700GT?\b", re.I)

# Formats below are verified against live SEL-700GT output (R302 firmware,
# 2026-09-25): MET, STA and BRE print column tables (a row of column names,
# then value rows with an optional leading label), HIS prints one row per
# event, and TAR prints a name row followed by a 0/1 row.
_HEADER_TOKEN = re.compile(r"^[+-]?[0-9A-Z_.]*[A-Z][0-9A-Z_.]*$")
_DATE_TIME = re.compile(
    r"Date:\s*(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"Time:\s*(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)
_TIME_SOURCE = re.compile(r"Time Source:\s*(?P<value>\S+)")
_HISTORY_HEADER = re.compile(r"^#\s+REF\s+DATE\s+TIME\s+EVENT\b")
_HISTORY_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<ref>\d+)\s+"
    r"(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<event>\S(?:.*?\S)?)\s+"
    r"(?P<current>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<freq_x>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<freq_y>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<targets>\S+)$"
)
_SER_HEADER = re.compile(r"^#\s+DATE\s+TIME\s+ELEMENT\s+STATE$")
_SER_ROW = re.compile(
    r"^(?P<number>\d+)\s+"
    r"(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<element>\S+)\s+"
    r"(?P<state>Asserted|Deasserted)$"
)
_TRIP_COUNT = re.compile(r"^(?P<kind>Rly|Ext) Trips \(counts\)\s+(?P<value>\d+)$")
_LAST_RESET = re.compile(
    r"^LAST RESET\s*=\s*(?P<month>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})$"
)
_BREAKER_TITLE = re.compile(r"^Breaker (?P<value>\S+) Monitor Data$")
_VOLTS_PER_HZ = re.compile(r"^V/Hz \(%\)\s+(?P<value>[-+]?\d+(?:\.\d+)?)$")
# A status table cell: OK/NA/W/F words or a number, optionally flagged W or F.
_STATUS_CELL = re.compile(r"^(?:OK|NA|W|F|WARN|FAIL|[-+]?\d+(?:\.\d+)?[WF]?)$", re.I)
_STATUS_SECTIONS = (
    ("Self Tests", "self_tests"),
    ("Option Cards", "option_cards"),
    ("Offsets", "offsets_mv"),
)


def _iso(match: Match[str]) -> str:
    return "{0}-{1}-{2}T{3}".format(
        match.group("year"), match.group("month"), match.group("day"), match.group("time")
    )


def _clock_fields(lines) -> Tuple[Dict[str, Any], Set[int]]:
    values: Dict[str, Any] = {}
    consumed: Set[int] = set()
    for index, line in lines:
        stamp = _DATE_TIME.search(line)
        if stamp is not None and "clock" not in values:
            values["clock"] = _iso(stamp)
            consumed.add(index)
        source = _TIME_SOURCE.search(line)
        if source is not None and "time_source" not in values:
            values["time_source"] = source.group("value").lower()
            consumed.add(index)
    return values, consumed


def _text(match: Match[str]) -> str:
    return match.group("value").strip()


def _float(match: Match[str]) -> float:
    return float(match.group("value"))


def _int(match: Match[str]) -> int:
    return int(match.group("value"))


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


def parse_status(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    values, consumed = _clock_fields(lines)
    tables = column_tables(lines, _HEADER_TOKEN)
    details: Dict[str, Any] = {}
    for table in tables:
        key = next(
            (k for prefix, k in _STATUS_SECTIONS if table["title"].lower().startswith(prefix.lower())),
            None,
        )
        if key is None:
            continue
        section = details.setdefault(key, {})
        for label, row, row_index in table["rows"]:
            if label == "" and all(_STATUS_CELL.match(str(value)) for value in row):
                section.update(zip(table["columns"], row))
                use_row(consumed, table, row_index)
    for index, line in lines:
        stripped = line.strip()
        if stripped in ("Relay Enabled", "Relay Disabled"):
            details["relay_enabled"] = stripped == "Relay Enabled"
            consumed.add(index)
        elif any(stripped.lower().startswith(prefix.lower()) for prefix, _ in _STATUS_SECTIONS):
            consumed.add(index)
    checks = list(details.get("self_tests", {}).values()) + list(details.get("option_cards", {}).values())
    words = [str(value).upper() for value in checks if isinstance(value, str)]
    if words:
        if any("FAIL" in word for word in words):
            values["self_test"] = "FAIL"
        elif any(word == "W" or word.endswith("W") or word == "WARN" for word in words):
            values["self_test"] = "WARN"
        else:
            values["self_test"] = "OK"
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


_METER_ROWS = {
    "Real Pwr (kW)": "power_kw",
    "Reactive Pwr (kVAR)": "reactive_kvar",
    "Apparent Pwr (kVA)": "apparent_kva",
    "Pwr Factor": "power_factor",
    "Frequency (Hz)": "frequencies_hz",
}


def parse_meter(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    tables = column_tables(lines, _HEADER_TOKEN)
    consumed: Set[int] = set()
    details: Dict[str, Any] = {}
    for table in tables:
        for label, row, row_index in table["rows"]:
            columns = dict(zip(table["columns"], row))
            if label.startswith("Mag (A"):
                key = "currents_a"
            elif label.startswith("Mag (V"):
                key = "voltages_v"
            elif label.startswith("Angle"):
                key = "angles_deg"
            elif label in _METER_ROWS:
                key = _METER_ROWS[label]
            elif label == "" and all(value in _PF_DIRECTIONS for value in row):
                key = "power_factor_direction"
            else:
                continue
            details.setdefault(key, {}).update(columns)
            use_row(consumed, table, row_index)
    for index, line in lines:
        match = _VOLTS_PER_HZ.match(line.strip())
        if match is not None:
            details["volts_per_hz_percent"] = float(match.group("value"))
            consumed.add(index)

    values: Dict[str, Any] = {}
    frequencies = details.get("frequencies_hz", {})
    if isinstance(frequencies.get("FREQX"), (int, float)):
        values["frequency_hz"] = float(frequencies["FREQX"])
    power = details.get("power_kw", {})
    if isinstance(power.get("3PX"), (int, float)):
        values["active_power_mw"] = round(power["3PX"] / 1000.0, 6)
    currents = details.get("currents_a", {})
    voltages = details.get("voltages_v", {})
    phases = []
    for phase in ("A", "B", "C"):
        current = currents.get("I{0}X".format(phase))
        voltage = voltages.get("V{0}X".format(phase))
        if isinstance(current, (int, float)) and isinstance(voltage, (int, float)):
            phases.append(
                {"phase": phase, "voltage_kv": round(voltage / 1000.0, 6), "current_a": float(current)}
            )
    if len(phases) == 3:
        values["phases"] = phases
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_breaker(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    tables = column_tables(lines, _HEADER_TOKEN)
    consumed: Set[int] = set()
    details: Dict[str, Any] = {}
    for table in tables:
        for label, row, row_index in table["rows"]:
            columns = dict(zip(table["columns"], row))
            key = {
                "Rly Trip Current (kA)": "relay_trip_current_ka",
                "Ext Trip Current (kA)": "external_trip_current_ka",
                "Wear (%)": "wear_percent",
            }.get(label)
            if key is not None:
                details[key] = columns
                use_row(consumed, table, row_index)
    for index, line in lines:
        stripped = line.strip()
        for pattern, handle in (
            (_TRIP_COUNT, lambda m: details.__setitem__(
                "relay_trip_count" if m.group("kind") == "Rly" else "external_trip_count", int(m.group("value")))),
            (_LAST_RESET, lambda m: details.__setitem__("last_reset", _iso(m))),
            (_BREAKER_TITLE, lambda m: details.__setitem__("breaker", m.group("value"))),
        ):
            match = pattern.match(stripped)
            if match is not None:
                handle(match)
                consumed.add(index)
                break
        else:
            if stripped in ("Trip Counters", "Cumulative Interrupted Currents", "Breaker Contact Wear"):
                consumed.add(index)

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
    events: List[Dict[str, Any]] = []
    in_table = False
    for index, line in lines:
        stripped = line.strip()
        if _HISTORY_HEADER.match(stripped):
            in_table = True
            consumed.add(index)
            continue
        if not in_table:
            continue
        match = _HISTORY_ROW.match(stripped)
        if match is None:
            continue
        events.append(
            {
                "event_number": int(match.group("number")),
                "timestamp": _iso(match),
                "event_type": match.group("event"),
                "details": {
                    "reference": int(match.group("ref")),
                    "current_a": float(match.group("current")),
                    "frequency_x_hz": float(match.group("freq_x")),
                    "frequency_y_hz": float(match.group("freq_y")),
                    "targets": match.group("targets"),
                },
            }
        )
        consumed.add(index)
    _, clock_consumed = _clock_fields(lines)
    consumed.update(clock_consumed)
    values: Dict[str, Any] = {}
    if events:
        values["events"] = events
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_target(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    tables = column_tables(lines, _HEADER_TOKEN)
    consumed: Set[int] = set()
    targets: List[Dict[str, Any]] = []
    for table in tables:
        for label, row, row_index in table["rows"]:
            if label == "" and all(value in (0, 1) for value in row):
                targets.extend(
                    {"name": name, "asserted": value == 1} for name, value in zip(table["columns"], row)
                )
                use_row(consumed, table, row_index)
    values: Dict[str, Any] = {}
    if targets:
        values["targets"] = targets
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_ser(text: str) -> Dict[str, Any]:
    """Parse SER rows (newest last, numbered newest = 1) and count transitions."""

    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    records: List[Dict[str, Any]] = []
    in_table = False
    for index, line in lines:
        stripped = line.strip()
        if _SER_HEADER.match(stripped):
            in_table = True
            consumed.add(index)
            continue
        if not in_table:
            continue
        match = _SER_ROW.match(stripped)
        if match is None:
            continue
        records.append(
            {
                "number": int(match.group("number")),
                "timestamp": _iso(match),
                "element": match.group("element"),
                "state": match.group("state"),
            }
        )
        consumed.add(index)
    summary: Dict[str, Dict[str, Any]] = {}
    for record in records:
        entry = summary.setdefault(
            record["element"],
            {"asserted": 0, "deasserted": 0, "first": record["timestamp"], "last": None},
        )
        entry[record["state"].lower()] += 1
        entry["last"] = record["timestamp"]
    values, clock_consumed = _clock_fields(lines)
    consumed.update(clock_consumed)
    values["records"] = records
    values["element_summary"] = summary
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


__all__ = [
    "parse_breaker",
    "parse_history",
    "parse_identity",
    "parse_meter",
    "parse_ser",
    "parse_status",
    "parse_target",
]
