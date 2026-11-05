"""Parsers for saved SEL settings captures (offline, no device access).

SEL-Audit's ``cli_read_settings.py`` saves one folder per capture run with the
``ID`` response (``ID.txt``), ``CFG.TXT`` and the ``FILE READ`` settings
streams (``set_1.txt``, ``set_G.txt``, ...). Settings streams are an
``[INFO]`` block followed by ``[class]`` and ``KEY,"value"`` rows (CSV-style:
a literal quote is doubled). SEL-851 keys are dotted (``Sys.PhRot``).

Values under password-like keys are redacted before they leave the parser.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from sel_triage.core.redaction import redact_settings

_RECORD_SEPARATOR = "\x1c"
_FID = re.compile(
    r"^(?P<model>.+?)-(?P<revision>R\d+)-(?P<version>V\d+)-(?P<z_number>Z\d+)-D(?P<date>\d{8})$"
)
_ID_ROW = re.compile(r'^"(?P<key>[A-Z]+)=(?P<value>[^"]*)"(?:,"[0-9A-Fa-f]{4}")?$')
_ID_FIELDS = {
    "BFID": "bfid",
    "CID": "cid",
    "DEVID": "device_id",
    "DEVCODE": "devcode",
    "PARTNO": "part_number",
    "SERIALNO": "serial_number",
    "CONFIG": "config",
    "SPECIAL": "special",
}
_DATA_ROW = re.compile(r'^(?P<key>[^,"\[\s][^,"]*),"(?P<value>.*)"$')
_SECTION = re.compile(r"^\[(?P<name>[^\]]+)\]$")
_CLASS_ROW = re.compile(
    r'^"?(?P<cls>[A-Za-z0-9]+)"?,"(?P<name>[^"]*)"(?:,"[^"]*")?(?:,"(?P<checksum>[0-9A-Fa-f]+)")?$'
)
_BANNER = re.compile(
    r"Date:\s*(?P<a>\d{1,4})/(?P<b>\d{1,2})/(?P<c>\d{1,4})\s+Time:\s*"
    r"(?P<h>\d{1,2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.\d+)?"
)
_TIME_SOURCE = re.compile(r"Time Source:\s*(?P<value>[A-Za-z0-9]+)")


def _iso_date(text: str) -> Optional[str]:
    try:
        return datetime.strptime(text, "%Y%m%d").date().isoformat()
    except ValueError:
        return None


def parse_fid(fid: str) -> Dict[str, Any]:
    """Split ``SEL-751-R400-V4-Z100100-D20241031`` into its parts."""

    result: Dict[str, Any] = {"fid": fid}
    match = _FID.match(fid.strip())
    if match is None:
        return result
    date = _iso_date(match.group("date"))
    result.update(
        model=match.group("model"),
        revision=match.group("revision"),
        version=match.group("version"),
        z_number=match.group("z_number"),
    )
    if date is not None:
        result["date"] = date
    return result


def parse_id_text(text: str) -> Dict[str, Any]:
    """Parse the ``ID`` command response saved as ``ID.txt``.

    Returns {} when no FID row is present (an empty or failed capture).
    """

    rows: Dict[str, str] = {}
    for line in text.splitlines():
        match = _ID_ROW.match(line.strip())
        if match is not None and match.group("key") not in rows:
            rows[match.group("key")] = match.group("value").strip()
    if "FID" not in rows:
        return {}
    firmware = parse_fid(rows["FID"])
    result: Dict[str, Any] = {"fid": rows["FID"], "firmware": firmware}
    if "model" in firmware:
        result["model"] = firmware["model"]
    for key, name in _ID_FIELDS.items():
        if rows.get(key):
            result[name] = rows[key]
    return result


def parse_cfg(text: str) -> Dict[str, Any]:
    """Parse ``CFG.TXT``: relay type, FID and the settings classes."""

    result: Dict[str, Any] = {"classes": {}}
    section = None
    for raw in text.splitlines():
        line = raw.strip().replace(_RECORD_SEPARATOR, "")
        if not line:
            continue
        header = _SECTION.match(line)
        if header is not None:
            section = header.group("name").upper()
            continue
        if section == "INFO" and "=" in line:
            key, value = line.split("=", 1)
            name = {"RELAYTYPE": "relay_type", "FID": "fid", "BFID": "bfid", "PARTNO": "part_number"}.get(key)
            if name:
                result[name] = value.strip()
        elif section == "CLASSES":
            row = _CLASS_ROW.match(line)
            if row is not None:
                entry = {"name": row.group("name")}
                if row.group("checksum"):
                    entry["checksum"] = row.group("checksum").upper()
                result["classes"][row.group("cls")] = entry
    return result


def parse_settings_file(text: str) -> Dict[str, Any]:
    """Parse one ``set_<class>.txt`` FILE READ stream.

    Returns {"class", "info", "settings", "unparsed_lines"}. Secret-looking
    keys are redacted.
    """

    info: Dict[str, str] = {}
    settings: Dict[str, str] = {}
    unparsed: List[str] = []
    cls: Optional[str] = None
    section = None
    for raw in text.splitlines():
        line = raw.replace(_RECORD_SEPARATOR, "").strip()
        if not line:
            continue
        header = _SECTION.match(line)
        if header is not None:
            section = header.group("name")
            if section.upper() != "INFO" and cls is None:
                cls = section
            continue
        if section is not None and section.upper() == "INFO" and "=" in line:
            key, value = line.split("=", 1)
            info[key.strip()] = value.strip()
            continue
        row = _DATA_ROW.match(line)
        if row is not None:
            settings[row.group("key").strip()] = row.group("value").replace('""', '"')
            continue
        unparsed.append(line)
    return {
        "class": cls,
        "info": info,
        "settings": redact_settings(settings),
        "unparsed_lines": unparsed,
    }


def parse_banner(text: str, date_format: str = "MDY") -> Dict[str, Any]:
    """Relay date/time and time source from the login banner of a transcript.

    Only these two fields are read; nothing else from the transcript (which
    can contain the typed password) is kept.
    """

    result: Dict[str, Any] = {}
    match = _BANNER.search(text)
    if match is not None:
        a, b, c = match.group("a"), match.group("b"), match.group("c")
        fmt = (date_format or "MDY").upper()
        if fmt == "YMD":
            year, month, day = a, b, c
        elif fmt == "DMY":
            day, month, year = a, b, c
        else:
            month, day, year = a, b, c
        try:
            year_value = int(year)
            if year_value < 100:
                year_value += 2000
            when = datetime(
                year_value, int(month), int(day),
                int(match.group("h")), int(match.group("m")), int(match.group("s")),
            )
            result["relay_time"] = when.isoformat()
        except ValueError:
            pass
    source = _TIME_SOURCE.search(text)
    if source is not None:
        result["time_source"] = source.group("value")
    return result


__all__ = [
    "parse_banner",
    "parse_cfg",
    "parse_fid",
    "parse_id_text",
    "parse_settings_file",
]
