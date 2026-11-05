"""Parsers for SEL RTAC web interface responses.

Layouts were observed on a live SEL-3505-3 (R146 firmware, 2026-09-25): the
login page carries a temp_auth_token, auth.sel answers with a session UUID,
soe.csv / alarms.csv are CSV exports with blank separator rows, and the
Connected IED report is an HTML table. Tests use synthetic fixtures.
"""

import csv
import io
import re
from typing import Any, Dict, List, Optional

_TOKEN = re.compile(r'id="temp_auth_token"[^>]*value="([^"]+)"')
_SESSION = re.compile(r"[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12}")
_TITLE_MODEL = re.compile(r"<title>\s*(SEL-\d+(?:-\d+)?)\s+Web Interface\s*</title>", re.I)
_DEVICE = re.compile(r"Device:\s*(SEL-[0-9A-Za-z-]+)")
_POWER_UP = re.compile(r"RTAC started with firmware:\s*(?P<firmware>[^,]+),\s*project:\s*(?P<project>.+)$")
_ROW = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S | re.I)
_CELL = re.compile(r"<t[hd][^>]*>(.*?)</t[hd]>", re.S | re.I)
_TAG = re.compile(r"<[^>]+>")
POWER_UP_TAG = "SystemTags.Power_Up_Description"


def login_token(html: str) -> Optional[str]:
    match = _TOKEN.search(html)
    return match.group(1) if match else None


def session_id(response: str) -> Optional[str]:
    match = _SESSION.search(response)
    return match.group(0) if match else None


def parse_home(html: str) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    model = _TITLE_MODEL.search(html)
    if model:
        values["observed_model"] = model.group(1).upper()
    device = _DEVICE.search(html)
    if device:
        values["device_id"] = device.group(1)
    values["communication_active"] = "Communication with device is active" in html
    return values


def _timestamp(value: str) -> str:
    return value.strip().replace(" ", "T", 1)


def parse_soe(text: str) -> List[Dict[str, Any]]:
    """Rows of an soe.csv or alarms.csv export (blank rows skipped)."""

    events = []
    for row in csv.DictReader(io.StringIO(text)):
        stamp = (row.get("t_value") or "").strip()
        if not stamp:
            continue
        events.append(
            {
                "timestamp": _timestamp(stamp),
                "category": (row.get("category") or "").strip(),
                "priority": (row.get("priority") or "").strip(),
                "tag": (row.get("tag_name") or "").strip(),
                "message": (row.get("message") or "").strip(),
                "device_name": (row.get("device_name") or "").strip(),
            }
        )
    return events


def summarize_soe(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = sorted(events, key=lambda e: e["timestamp"])
    summary: Dict[str, Any] = {"event_count": len(ordered)}
    if not ordered:
        return summary
    summary["first_event"] = ordered[0]["timestamp"]
    summary["last_event"] = ordered[-1]["timestamp"]
    history = []
    for event in ordered:
        if event["tag"] != POWER_UP_TAG:
            continue
        match = _POWER_UP.search(event["message"])
        if match:
            history.append(
                {
                    "timestamp": event["timestamp"],
                    "project": match.group("project").strip(),
                    "firmware": match.group("firmware").strip(),
                }
            )
    summary["power_up_count"] = len(history)
    if history:
        summary["last_power_up"] = history[-1]["timestamp"]
        summary["firmware"] = history[-1]["firmware"]
        summary["project"] = history[-1]["project"]
        # Keep only power-ups where the project or firmware changed.
        changes = [history[0]] + [
            item for previous, item in zip(history, history[1:])
            if (item["project"], item["firmware"]) != (previous["project"], previous["firmware"])
        ]
        summary["project_history"] = changes
    counts: Dict[str, int] = {}
    for event in ordered:
        counts[event["tag"]] = counts.get(event["tag"], 0) + 1
    summary["tag_counts"] = counts
    return summary


def _clean(cell: str) -> str:
    return re.sub(r"\s+", " ", _TAG.sub("", cell).replace("&nbsp;", " ")).strip()


def parse_ied_table(html: str) -> List[Dict[str, str]]:
    """Rows below the 'Protocol | Remote Device | ...' header of an IED table."""

    header: Optional[List[str]] = None
    rows: List[Dict[str, str]] = []
    for row in _ROW.findall(html):
        cells = [_clean(c) for c in _CELL.findall(row)]
        if not cells:
            continue
        if header is None:
            if cells[0] == "Protocol":
                header = [re.sub(r"[^a-z0-9]+", "_", c.lower()).strip("_") for c in cells]
            continue
        if any(cells):
            rows.append(dict(zip(header, cells)))
    return rows


__all__ = ["login_token", "parse_home", "parse_ied_table", "parse_soe", "session_id", "summarize_soe"]
