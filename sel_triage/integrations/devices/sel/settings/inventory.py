"""Fleet inventory from saved SEL captures: one row per device."""

from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from sel_triage.core.diagnostics import Diagnostic
from .capture import latest_identity_capture, latest_settings_capture
from .files import parse_fid

DEFAULT_MAX_AGE_DAYS = 180.0
CSV_COLUMNS = (
    "site", "endpoint", "device", "model", "fid", "firmware_revision", "firmware_date",
    "bfid", "part_number", "serial_number", "device_id", "capture_date", "captures",
    "failed_captures", "flags",
)


def firmware_order_key(fid: str) -> Tuple[int, str, int]:
    """Sort key for FIDs of one model: revision, then date, then version."""

    parts = parse_fid(fid)

    def number(text: Optional[str]) -> int:
        try:
            return int((text or "")[1:])
        except ValueError:
            return -1

    return number(parts.get("revision")), parts.get("date") or "", number(parts.get("version"))


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _diagnostic(code: str, severity: str, description: str, evidence: Mapping[str, Any]) -> Dict[str, Any]:
    return Diagnostic(code, severity, description, evidence).as_dict()


def build_inventory(
    devices: List[Mapping[str, Any]],
    now: datetime,
    max_age_days: Optional[float] = None,
    thresholds_for: Optional[Callable[[str, Optional[str]], Mapping[str, float]]] = None,
) -> Dict[str, Any]:
    """Rows, findings and a summary for every device.

    ``max_age_days`` overrides the per-device ``sel_capture_max_age_days``
    threshold from ``thresholds_for(device, model)`` (default 180 days).
    """

    rows: List[Dict[str, Any]] = []
    for device in devices:
        captures = device.get("captures", [])
        latest = latest_identity_capture(device) or latest_settings_capture(device)
        identity = (latest or {}).get("identity") or {}
        firmware = identity.get("firmware") or {}
        fids = [run["identity"]["fid"] for run in captures if run.get("identity", {}).get("fid")]
        row: Dict[str, Any] = {
            "site": device.get("site"),
            "endpoint": device.get("endpoint"),
            "device": device["key"],
            "model": identity.get("model"),
            "fid": identity.get("fid"),
            "firmware_revision": firmware.get("revision"),
            "firmware_date": firmware.get("date"),
            "bfid": identity.get("bfid"),
            "part_number": identity.get("part_number"),
            "serial_number": identity.get("serial_number"),
            "device_id": identity.get("device_id"),
            "capture_date": (latest or {}).get("captured_at"),
            "captures": len(captures),
            "failed_captures": sum(1 for run in captures if run.get("status") == "failed"),
            "path": (latest or {}).get("path"),
            "flags": [],
        }
        if latest is None:
            row["flags"].append("no_successful_capture")
        if len(set(fids)) > 1:
            row["flags"].append("firmware_changed")
            row["previous_fids"] = sorted(set(fids) - {identity.get("fid")})
        limit = max_age_days
        if limit is None:
            configured = thresholds_for(device["key"], row["model"]) if thresholds_for else {}
            limit = float(configured.get("sel_capture_max_age_days", DEFAULT_MAX_AGE_DAYS))
        captured = _parse_time(row["capture_date"])
        if captured is not None:
            age = (now - captured).total_seconds() / 86400.0
            row["capture_age_days"] = round(age, 1)
            if age > limit:
                row["flags"].append("capture_stale")
                row["max_age_days"] = limit
        rows.append(row)

    newest: Dict[str, str] = {}
    for row in rows:
        if row["model"] and row["fid"]:
            best = newest.get(row["model"])
            if best is None or firmware_order_key(row["fid"]) > firmware_order_key(best):
                newest[row["model"]] = row["fid"]
    by_site_model: Dict[Tuple[Any, str], set] = defaultdict(set)
    for row in rows:
        if row["model"] and row["fid"] and row["site"]:
            by_site_model[(row["site"], row["model"])].add(row["fid"])

    findings: List[Dict[str, Any]] = []
    for row in rows:
        if row["model"] and row["fid"]:
            best = newest[row["model"]]
            if firmware_order_key(row["fid"]) < firmware_order_key(best):
                row["flags"].append("firmware_behind")
                row["newest_fid_seen"] = best
                findings.append(_diagnostic(
                    "firmware_behind", "info",
                    "Firmware is older than the newest firmware seen on this model in the captures.",
                    {"device": row["device"], "fid": row["fid"], "newest_fid_seen": best},
                ))
            site_fids = by_site_model.get((row["site"], row["model"]), set())
            if len(site_fids) > 1:
                row["flags"].append("mixed_firmware_at_site")
                findings.append(_diagnostic(
                    "mixed_firmware_at_site", "info",
                    "Devices of the same model at this site run different firmware.",
                    {"device": row["device"], "fid": row["fid"], "site_fids": sorted(site_fids)},
                ))
        if "firmware_changed" in row["flags"]:
            findings.append(_diagnostic(
                "firmware_changed", "info",
                "The FID differs between captures of this endpoint (firmware upgrade or a different device).",
                {"device": row["device"], "fid": row["fid"], "previous_fids": row["previous_fids"]},
            ))
        if "capture_stale" in row["flags"]:
            findings.append(_diagnostic(
                "capture_stale", "info",
                "The newest successful capture is older than the configured age.",
                {"device": row["device"], "capture_date": row["capture_date"],
                 "capture_age_days": row["capture_age_days"], "max_age_days": row["max_age_days"]},
            ))
        if "no_successful_capture" in row["flags"]:
            findings.append(_diagnostic(
                "no_successful_capture", "warning",
                "No capture of this endpoint returned an ID response or settings.",
                {"device": row["device"], "captures": row["captures"]},
            ))

    firmware_spread: Dict[str, Dict[str, int]] = defaultdict(dict)
    for row in rows:
        if row["model"] and row["fid"]:
            spread = firmware_spread[row["model"]]
            spread[row["fid"]] = spread.get(row["fid"], 0) + 1
    flag_counts = Counter(flag for row in rows for flag in row["flags"])
    summary = {
        "devices": len(rows),
        "sites": len({row["site"] for row in rows if row["site"]}),
        "capture_runs": sum(row["captures"] for row in rows),
        "failed_capture_runs": sum(row["failed_captures"] for row in rows),
        "models": dict(sorted(Counter(row["model"] for row in rows if row["model"]).items())),
        "firmware": {model: dict(sorted(spread.items())) for model, spread in sorted(firmware_spread.items())},
        "newest_firmware": dict(sorted(newest.items())),
        "flags": dict(sorted(flag_counts.items())),
    }
    return {"rows": rows, "findings": findings, "summary": summary}


def inventory_csv(result: Mapping[str, Any]) -> str:
    """CSV text of the inventory rows (flags joined with ';')."""

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in result.get("rows", []):
        values = dict(row)
        values["flags"] = ";".join(row.get("flags", []))
        writer.writerow({key: ("" if values.get(key) is None else values.get(key)) for key in CSV_COLUMNS})
    return buffer.getvalue()


__all__ = ["DEFAULT_MAX_AGE_DAYS", "build_inventory", "firmware_order_key", "inventory_csv"]
