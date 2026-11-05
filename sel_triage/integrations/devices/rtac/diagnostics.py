"""Evidence-backed findings for RTAC web and REST API snapshots.

RTAC SOE timestamps were observed in UTC, so the recent window is measured
from the snapshot time in UTC.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional

from sel_triage.core.diagnostics import Diagnostic

from .parsers import POWER_UP_TAG, summarize_soe

DEFAULT_THRESHOLDS = {
    "rtac_recent_days": 30.0,
    "rtac_clock_drift_seconds": 300.0,
    "rtac_connection_failure_ratio": 0.05,
}
_FAILED_LOGIN = "SystemTags.Unsuccessful_Log_On_Attempt"
_SETTINGS_TAGS = {
    "SystemTags.User_Changed_Settings": "settings_changed",
    "SystemTags.User_Added": "user_added",
    "SystemTags.Device_Upgrade": "device_upgrade",
}
_MAX_LISTED = 10


def _limits(thresholds: Optional[Mapping[str, Any]]) -> Dict[str, float]:
    values = dict(DEFAULT_THRESHOLDS)
    for name in values:
        value = (thresholds or {}).get(name)
        if not isinstance(value, bool) and isinstance(value, (int, float)) and value >= 0:
            values[name] = float(value)
    return values


def _whole(value: float) -> Any:
    return int(value) if float(value).is_integer() else value


def _diagnostic(code: str, severity: str, description: str, evidence: Mapping[str, Any]) -> Dict[str, Any]:
    return Diagnostic(code, severity, description, evidence).as_dict()


def diagnose_rtac(
    events: List[Dict[str, Any]],
    alarms: List[Dict[str, Any]],
    home: Mapping[str, Any],
    now: datetime,
    thresholds: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, Any]]:
    limits = _limits(thresholds)
    days = limits["rtac_recent_days"]
    reference = now.astimezone(timezone.utc).replace(tzinfo=None)
    cutoff = (reference - timedelta(days=days)).isoformat()
    upper = reference.isoformat()
    recent = sorted((e for e in events if cutoff <= e["timestamp"] <= upper), key=lambda e: e["timestamp"])
    findings: List[Dict[str, Any]] = []

    if home.get("communication_active") is False:
        findings.append(_diagnostic(
            "rtac_communication_inactive", "warning",
            "The RTAC web interface does not report active communication with the device.", {}))

    if alarms:
        findings.append(_diagnostic(
            "rtac_active_alarms", "warning", "The RTAC alarm summary lists active alarms.",
            {"count": len(alarms), "alarms": [
                {k: a[k] for k in ("timestamp", "priority", "tag", "message")} for a in alarms[:_MAX_LISTED]]}))

    failed = [e for e in recent if e["tag"] == _FAILED_LOGIN]
    if failed:
        findings.append(_diagnostic(
            "rtac_failed_logins", "warning", "Failed login attempts were recorded in the recent SOE.",
            {"days": _whole(days), "count": len(failed), "latest": failed[-1]["timestamp"],
             "attempts": [{k: e[k] for k in ("timestamp", "message")} for e in failed[-_MAX_LISTED:]]}))

    changes = [
        {"timestamp": e["timestamp"], "kind": _SETTINGS_TAGS[e["tag"]], "message": e["message"]}
        for e in recent if e["tag"] in _SETTINGS_TAGS
    ]
    summary = summarize_soe(events)
    for item in summary.get("project_history", [])[1:]:
        if cutoff <= item["timestamp"] <= upper:
            changes.append({"timestamp": item["timestamp"], "kind": "project_or_firmware_changed",
                            "project": item["project"], "firmware": item["firmware"]})
    if changes:
        changes.sort(key=lambda c: c["timestamp"])
        findings.append(_diagnostic(
            "rtac_settings_changed", "info", "Settings, users, firmware or the running project changed recently.",
            {"days": _whole(days), "changes": changes[-_MAX_LISTED:]}))

    power_ups = [e for e in recent if e["tag"] == POWER_UP_TAG]
    if power_ups:
        findings.append(_diagnostic(
            "rtac_restarted", "info", "The RTAC powered up within the recent window.",
            {"days": _whole(days), "count": len(power_ups), "last_power_up": power_ups[-1]["timestamp"],
             "project": summary.get("project"), "firmware": summary.get("firmware")}))
    return findings


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def diagnose_rtac_api(
    status: Optional[Mapping[str, Any]],
    alarms: Optional[List[Mapping[str, Any]]],
    connections: Optional[List[Mapping[str, Any]]],
    now: datetime,
    thresholds: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Findings from the parsed REST API status, alarm summary and IED connections."""

    limits = _limits(thresholds)
    findings: List[Dict[str, Any]] = []
    status = status or {}

    if status.get("self_test") == "FAIL":
        findings.append(_diagnostic(
            "rtac_self_test_failed", "error", "The RTAC reports failed hardware self-tests.",
            {"failed": status.get("self_tests_failed", [])}))
    if status.get("online") is False or status.get("enabled") is False:
        findings.append(_diagnostic(
            "rtac_not_online", "error", "The RTAC reports that it is not online or not enabled.",
            {k: status.get(k) for k in ("online", "enabled", "project", "project_state")}))
    elif status.get("project_state") not in (None, "Running"):
        findings.append(_diagnostic(
            "rtac_project_not_running", "warning", "The active RTAC project is not in the Running state.",
            {"project": status.get("project"), "project_state": status.get("project_state")}))

    clock = _parse_time(status.get("clock"))
    if clock is not None:
        drift = abs((clock - now.astimezone(timezone.utc)).total_seconds())
        if drift > limits["rtac_clock_drift_seconds"]:
            findings.append(_diagnostic(
                "rtac_clock_unsynchronized", "warning", "The RTAC clock differs from the local clock by more than "
                "the configured threshold.",
                {"clock": status.get("clock"), "drift_seconds": _whole(round(drift, 1)),
                 "threshold_seconds": _whole(limits["rtac_clock_drift_seconds"]),
                 "time_source": status.get("time_source")}))

    active = [a for a in alarms or [] if a.get("state") == "Alarmed"]
    if active:
        findings.append(_diagnostic(
            "rtac_active_alarms", "warning", "The RTAC alarm summary lists active alarms.",
            {"count": len(active),
             "unacknowledged": sum(1 for a in active if a.get("acknowledgement") != "Acknowledged"),
             "alarms": [{k: a.get(k) for k in ("timestamp", "priority", "tag", "message", "acknowledgement")}
                        for a in active[:_MAX_LISTED]]}))

    offline = [c for c in connections or [] if c.get("status") == "Offline"]
    if offline:
        findings.append(_diagnostic(
            "rtac_ied_offline", "warning", "IED connections in the active project are offline.",
            {"count": len(offline), "connections": [
                {k: c.get(k) for k in ("name", "model", "egress", "service") if c.get(k) is not None}
                for c in offline[:_MAX_LISTED]]}))
    ratio = limits["rtac_connection_failure_ratio"]
    failing = [c for c in connections or []
               if c.get("status") != "Offline" and isinstance(c.get("failure_ratio"), float)
               and c["failure_ratio"] > ratio]
    if failing:
        failing.sort(key=lambda c: -c["failure_ratio"])
        findings.append(_diagnostic(
            "rtac_ied_message_failures", "warning",
            "IED connections have a message failure ratio above the configured threshold.",
            {"threshold_ratio": ratio, "count": len(failing), "connections": [
                {k: c.get(k) for k in ("name", "model", "failure_ratio", "failures", "successes")}
                for c in failing[:_MAX_LISTED]]}))
    return findings


__all__ = ["DEFAULT_THRESHOLDS", "diagnose_rtac", "diagnose_rtac_api"]
