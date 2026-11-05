"""sel-breaker-trend: breaker wear and operations over time, from archived BRE readings (offline).

Reads ``breaker.jsonl`` from every committed sweep (local or S3 store), one point per
device per sweep, and per breaker reports the latest wear and operation count, their rates
(per year, over the readings since the last counter reset), the projected date the wear
reaches the alarm threshold, and findings:

* ``wear_over_threshold`` / ``operations_over_threshold``: latest reading at or above the
  diagnostic thresholds (``breaker_wear_percent``, ``breaker_operation_count``; defaults
  80 % and 5000, overridable per model, site or device in ``diagnosticThresholds``).
* ``wear_reaches_threshold_soon``: projected to reach the wear threshold within the horizon.
* ``counters_reset``: wear or operations went down, or the reset date changed (someone
  reset or preloaded the monitor); rates use only the readings after the last reset.
* ``monitor_disabled``: the breaker monitor is off, so wear is not tracked.
* ``insufficient_history``: fewer than two readings ``min_days`` apart since the last reset.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from ..integrations.devices.sel.diagnostics import DEFAULT_THRESHOLDS
from . import records

DEFAULT_MIN_DAYS = 7.0
DEFAULT_HORIZON_DAYS = 365.0


def _time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def load_readings(archive, prefix: str) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Dict[str, Any]]]:
    """Breaker rows by device (one per sweep run, newest parser wins) and device identity from runs."""

    readings: Dict[Tuple[str, str], Dict[str, Any]] = {}
    identity: Dict[str, Dict[str, Any]] = {}
    for run_id in archive.list_children(prefix + "/normalized"):
        try:
            runs = records.from_jsonl(archive.get(records.normalized_key(prefix, run_id, "runs.jsonl")))
        except KeyError:
            continue  # uncommitted
        for row in runs:
            if row.get("kind") == "sweep" and row.get("name"):
                identity[row["device_key"]] = {"name": row["name"], "site": row.get("site"),
                                               "model": row.get("observed_model")}
        try:
            rows = records.from_jsonl(archive.get(records.normalized_key(prefix, run_id, "breaker.jsonl")))
        except KeyError:
            continue
        for row in rows:
            key = (row["device_key"], row.get("seen_run") or run_id)
            current = readings.get(key)
            if current is None or (row.get("breaker_parser_version") or 0) >= (current.get("breaker_parser_version") or 0):
                readings[key] = row
    by_device: Dict[str, List[Dict[str, Any]]] = {}
    for (device, _run), row in readings.items():
        by_device.setdefault(device, []).append(row)
    for rows in by_device.values():
        rows.sort(key=lambda r: r.get("read_at") or "")
    return by_device, identity


def _since_reset(points: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool]:
    """Readings after the last counter reset, and whether any reset was seen."""

    start, reset = 0, False
    for index in range(1, len(points)):
        before, after = points[index - 1], points[index]
        went_down = any(
            after.get(field) is not None and before.get(field) is not None and after[field] < before[field]
            for field in ("breaker_wear_percent", "operation_count")
        )
        new_reset = after.get("last_reset") and before.get("last_reset") and after["last_reset"] != before["last_reset"]
        if went_down or new_reset:
            start, reset = index, True
    return points[start:], reset


def _rate_per_year(points: List[Dict[str, Any]], field: str, min_days: float) -> Optional[float]:
    usable = [(p, _time(p.get("read_at"))) for p in points if p.get(field) is not None and _time(p.get("read_at"))]
    if len(usable) < 2:
        return None
    (first, t0), (last, t1) = usable[0], usable[-1]
    days = (t1 - t0).total_seconds() / 86400.0
    if days < min_days:
        return None
    return round((last[field] - first[field]) / days * 365.0, 3)


def trend_device(
    device_key: str,
    rows: List[Dict[str, Any]],
    meta: Mapping[str, Any],
    thresholds: Mapping[str, float],
    *,
    min_days: float = DEFAULT_MIN_DAYS,
    horizon_days: float = DEFAULT_HORIZON_DAYS,
) -> Dict[str, Any]:
    parsed = [row for row in rows if row.get("bre_parse") == "parsed"]
    latest = parsed[-1] if parsed else (rows[-1] if rows else {})
    limits = dict(DEFAULT_THRESHOLDS)
    limits.update(thresholds)
    segment, reset = _since_reset(parsed)
    wear_rate = _rate_per_year(segment, "breaker_wear_percent", min_days)
    ops_rate = _rate_per_year(segment, "operation_count", min_days)
    wear = latest.get("breaker_wear_percent")
    ops = latest.get("operation_count")
    projected = None
    if wear is not None and wear_rate and wear_rate > 0 and wear < limits["breaker_wear_percent"]:
        last_time = _time(latest.get("read_at"))
        if last_time is not None:
            years = (limits["breaker_wear_percent"] - wear) / wear_rate
            projected = (last_time + timedelta(days=years * 365.0)).date().isoformat()
    findings: List[Dict[str, Any]] = []
    if latest.get("monitor_enabled") is False:
        findings.append({"code": "monitor_disabled", "severity": "info"})
    if wear is not None and wear >= limits["breaker_wear_percent"]:
        findings.append({"code": "wear_over_threshold", "severity": "warning",
                         "wear_percent": wear, "threshold_percent": limits["breaker_wear_percent"]})
    elif projected is not None:
        days_left = (_time(projected + "T00:00:00+00:00") - _time(latest.get("read_at"))).days
        if days_left <= horizon_days:
            findings.append({"code": "wear_reaches_threshold_soon", "severity": "warning",
                             "projected_date": projected, "days": days_left})
    if ops is not None and ops >= limits["breaker_operation_count"]:
        findings.append({"code": "operations_over_threshold", "severity": "warning",
                         "operation_count": ops, "threshold_count": int(limits["breaker_operation_count"])})
    if reset:
        findings.append({"code": "counters_reset", "severity": "info"})
    if latest.get("monitor_enabled") is not False and wear_rate is None and ops_rate is None:
        findings.append({"code": "insufficient_history", "severity": "info", "readings_since_reset": len(segment)})
    return {
        "device_key": device_key,
        "name": meta.get("name"),
        "site": meta.get("site"),
        "model": meta.get("model"),
        "readings": len(rows),
        "first_read": rows[0].get("read_at") if rows else None,
        "last_read": latest.get("read_at"),
        "monitor_enabled": latest.get("monitor_enabled"),
        "wear_percent": wear,
        "wear_by_phase": latest.get("wear_percent"),
        "operation_count": ops,
        "last_reset": latest.get("last_reset"),
        "wear_rate_percent_per_year": wear_rate,
        "operation_rate_per_year": ops_rate,
        "projected_threshold_date": projected,
        "thresholds": {"breaker_wear_percent": limits["breaker_wear_percent"],
                       "breaker_operation_count": limits["breaker_operation_count"]},
        "findings": findings,
        "series": [{"read_at": r.get("read_at"), "wear_percent": r.get("breaker_wear_percent"),
                    "operation_count": r.get("operation_count")} for r in parsed],
    }


def run_trend(
    archive,
    prefix: str,
    *,
    thresholds_for: Callable[[Optional[str], Optional[str]], Mapping[str, float]] = lambda name, model: {},
    name: Optional[str] = None,
    site: Optional[str] = None,
    min_days: float = DEFAULT_MIN_DAYS,
    horizon_days: float = DEFAULT_HORIZON_DAYS,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    by_device, identity = load_readings(archive, prefix)
    devices = []
    for device_key, rows in by_device.items():
        meta = identity.get(device_key, {})
        if name is not None and meta.get("name") != name:
            continue
        if site is not None and site.casefold() not in (meta.get("site") or "").casefold():
            continue
        devices.append(trend_device(device_key, rows, meta, thresholds_for(meta.get("name"), meta.get("model")),
                                    min_days=min_days, horizon_days=horizon_days))
    rank = {"warning": 0, "info": 1}
    devices.sort(key=lambda d: (min((rank[f["severity"]] for f in d["findings"]), default=2),
                                -(d["wear_percent"] or 0), d["name"] or d["device_key"]))
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {
        "tool": "sel-breaker-trend",
        "ran_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ok": True,
        "devices": devices,
        "totals": {code: sum(1 for d in devices for f in d["findings"] if f["code"] == code)
                   for code in ("wear_over_threshold", "wear_reaches_threshold_soon", "operations_over_threshold",
                                "counters_reset", "monitor_disabled", "insufficient_history")},
    }


def render_lines(result: Mapping[str, Any]) -> List[str]:
    lines = ["  {0} breakers; totals: {1}".format(
        len(result.get("devices", [])),
        ", ".join("{0}={1}".format(k, v) for k, v in (result.get("totals") or {}).items() if v) or "none")]
    for device in result.get("devices", []):
        rate = device.get("wear_rate_percent_per_year")
        lines.append("  {0:<45} {1:<10} wear {2:>5}%  ops {3:>6}  rate {4}  {5}".format(
            (device.get("name") or device["device_key"])[:45], device.get("model") or "-",
            "-" if device.get("wear_percent") is None else "{0:g}".format(device["wear_percent"]),
            "-" if device.get("operation_count") is None else device["operation_count"],
            "-" if rate is None else "{0:+.1f}%/yr".format(rate),
            ", ".join(f["code"] for f in device["findings"]) or "ok"))
    return lines


__all__ = ["load_readings", "render_lines", "run_trend", "trend_device"]
