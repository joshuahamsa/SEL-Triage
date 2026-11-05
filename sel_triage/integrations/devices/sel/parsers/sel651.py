"""Fixture-backed parsers for SEL-651-family responses."""

from __future__ import annotations

import re
from typing import Any, Dict, Match, Optional, Sequence, Set, Tuple

from .common import nonempty_lines, parse_labeled_scalars, remaining_lines


_FID = re.compile(r'"FID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_DEVID = re.compile(r'"DEVID=(?P<value>[^"\r\n]+)"(?:,"[^"]*")?', re.I)
_MODEL = re.compile(r"\bSEL-651(?:RA|R-?2)?\b", re.I)

_CLOCK = re.compile(
    r".*\bDate:\s*(?P<date>\d{2}/\d{2}/\d{4})\s+"
    r"Time:\s*(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
    re.I,
)
_TIME_SOURCE = re.compile(r".*\bTime Source:\s*(?P<value>\S+)", re.I)
_TEMPERATURE = re.compile(
    r"(?P<value>[-+]?\d+(?:\.\d+)?)\s+degrees Celsius\s+\S+\s+\S+",
    re.I,
)
_RECLOSER_STATE = re.compile(r"Relay\s+(?P<value>Enabled|Disabled)", re.I)

_CURRENT_HEADER = re.compile(r"A\s+B\s+C\s+N\s+G", re.I)
_CURRENT_ROW = re.compile(
    r"I MAG \(A\)\s+"
    r"(?P<a>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<b>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<c>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<n>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<g>[-+]?\d+(?:\.\d+)?)",
    re.I,
)
_VOLTAGE_HEADER = re.compile(r"VAY\s+VBY\s+VCY\s+VAZ\s+VBZ\s+VCZ", re.I)
_VOLTAGE_ROW = re.compile(
    r"V MAG \(kV\)\s+"
    r"(?P<a>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<b>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<c>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<az>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<bz>[-+]?\d+(?:\.\d+)?)\s+"
    r"(?P<cz>[-+]?\d+(?:\.\d+)?)",
    re.I,
)
_POWER_HEADER = re.compile(r"A\s+B\s+C\s+3P", re.I)
_POWER_ROW = re.compile(
    r"MW\s+[-+]?\d+(?:\.\d+)?\s+[-+]?\d+(?:\.\d+)?\s+"
    r"[-+]?\d+(?:\.\d+)?\s+(?P<value>[-+]?\d+(?:\.\d+)?)",
    re.I,
)
_FREQUENCY = re.compile(
    r"FREQ\s+\(Hz\)\s+(?P<value>[-+]?\d+(?:\.\d+)?)", re.I
)

_HISTORY_HEADER = re.compile(
    r"#\s+DATE\s+TIME\s+EVENT\s+LOCAT\s+CURR\s+FREQ\s+GST\s+TARGETS",
    re.I,
)
_HISTORY_ROW = re.compile(
    r"(?P<number>\d+)\s+"
    r"(?P<date>\d{2}/\d{2}/\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<event_type>\S(?:.*?\S)?)\s+"
    r"(?P<source_fields>\${5}\s+.+)"
)


def _text(match: Match[str]) -> str:
    return match.group("value").strip()


def _float(match: Match[str]) -> float:
    return float(match.group("value"))


def _clock(match: Match[str]) -> str:
    month, day, year = match.group("date").split("/")
    return "{0}-{1}-{2}T{3}".format(year, month, day, match.group("time"))


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
            values["observed_model"] = model.group(0).upper().replace("R-2", "R2")
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_status(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    values, consumed = parse_labeled_scalars(
        lines,
        {
            "clock": (_CLOCK, _clock),
            "time_source": (_TIME_SOURCE, _text),
            "temperature_c": (_TEMPERATURE, _float),
            "recloser_state": (_RECLOSER_STATE, _text),
        },
    )
    details: Dict[str, Any] = {}
    if "recloser_state" in values:
        details["recloser_state"] = values.pop("recloser_state").upper()
    if "temperature_c" in values:
        details["temperature_c"] = values.pop("temperature_c")
    if details:
        values["details"] = details
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def _following_match(
    lines: Sequence[Tuple[int, str]],
    header: re.Pattern[str],
    row: re.Pattern[str],
) -> Tuple[Optional[Match[str]], Set[int]]:
    for position, (header_index, line) in enumerate(lines[:-1]):
        if header.fullmatch(line.strip()) is None:
            continue
        row_index, row_line = lines[position + 1]
        match = row.fullmatch(row_line.strip())
        if match is not None:
            return match, {header_index, row_index}
    return None, set()


def parse_meter(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    values, consumed = parse_labeled_scalars(
        lines, {"frequency_hz": (_FREQUENCY, _float)}
    )

    currents, current_consumed = _following_match(
        lines, _CURRENT_HEADER, _CURRENT_ROW
    )
    voltages, voltage_consumed = _following_match(
        lines, _VOLTAGE_HEADER, _VOLTAGE_ROW
    )
    if currents is not None and voltages is not None:
        consumed.update(current_consumed)
        consumed.update(voltage_consumed)
        values["phases"] = [
            {
                "phase": phase.upper(),
                "voltage_kv": float(voltages.group(phase)),
                "current_a": float(currents.group(phase)),
            }
            for phase in ("a", "b", "c")
        ]

    power, power_consumed = _following_match(lines, _POWER_HEADER, _POWER_ROW)
    consumed.update(power_consumed)
    if power is not None:
        values["active_power_mw"] = float(power.group("value"))

    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


def parse_history(text: str) -> Dict[str, Any]:
    lines = nonempty_lines(text)
    events = []
    consumed: Set[int] = set()
    header_seen = False
    for index, line in lines:
        candidate = line.strip()
        if not header_seen:
            if _HISTORY_HEADER.fullmatch(candidate) is not None:
                header_seen = True
                consumed.add(index)
            continue
        match = _HISTORY_ROW.fullmatch(candidate)
        if match is None:
            continue
        month, day, year = match.group("date").split("/")
        events.append(
            {
                "event_number": int(match.group("number")),
                "timestamp": "{0}-{1}-{2}T{3}".format(
                    year, month, day, match.group("time")
                ),
                "event_type": match.group("event_type"),
                "details": {"source_fields": match.group("source_fields")},
            }
        )
        consumed.add(index)

    values: Dict[str, Any] = {}
    if events:
        values["events"] = events
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


__all__ = ["parse_history", "parse_identity", "parse_meter", "parse_status"]
