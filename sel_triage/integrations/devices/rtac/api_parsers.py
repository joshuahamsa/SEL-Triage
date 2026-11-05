"""Normalize RTAC REST API responses (shapes from the R146 OpenAPI document).

Not yet checked against a live RTAC: no account with the "API Login" permission
was available when this was written. Tests use synthetic fixtures that follow
the documented schemas.
"""

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_id(data: Any) -> Dict[str, Any]:
    data = _dict(data)
    fid = _dict(data.get("FID"))
    version = _dict(fid.get("Version"))
    identity: Dict[str, Any] = {}
    if fid.get("Product"):
        identity["observed_model"] = str(fid["Product"]).upper()
    if fid.get("Raw"):
        identity["fid"] = fid["Raw"]
    if "Major" in version and "Minor" in version:
        identity["firmware_version"] = "{0}.{1}".format(_whole(version["Major"]), _whole(version["Minor"]))
    for source, target in (("BuildId", "build_id"), ("Date", "firmware_date"), ("Type", "firmware_type")):
        if fid.get(source):
            identity[target] = fid[source]
    if data.get("SerialNumber"):
        identity["serial_number"] = data["SerialNumber"]
    licensed = data.get("LicensedFeatures")
    if isinstance(licensed, list):
        identity["licensed_features"] = [
            {k: f.get(k) for k in ("Name", "Category", "Expired", "Expiry") if k in f}
            for f in licensed if isinstance(f, dict)
        ]
    return identity


def _whole(value: Any) -> Any:
    return int(value) if isinstance(value, float) and value.is_integer() else value


def _self_tests(tree: Any, prefix: str = "") -> Iterable[Tuple[str, str]]:
    for key, value in _dict(tree).items():
        name = "{0}.{1}".format(prefix, key) if prefix else key
        if isinstance(value, dict):
            yield from _self_tests(value, name)
        elif isinstance(value, str):
            yield name, value


def parse_status(data: Any) -> Dict[str, Any]:
    data = _dict(data)
    hardware = _dict(data.get("Hardware"))
    time = _dict(data.get("Time"))
    project = _dict(data.get("Project"))
    tests = dict(_self_tests(hardware.get("SelfTests")))
    failed = sorted(name for name, result in tests.items() if result != "Pass")
    status: Dict[str, Any] = {
        "online": data.get("Online"),
        "enabled": data.get("Enabled"),
        "clock": time.get("Value"),
        "time_source": time.get("Source"),
        "time_accuracy": time.get("Accuracy"),
        "boot_time": data.get("BootTime"),
        "up_time": data.get("UpTime"),
        "project": project.get("Name"),
        "project_state": project.get("State"),
        "project_modified": project.get("LastModifiedTimestamp"),
        "self_test": ("FAIL" if failed else "OK") if tests else None,
        "self_tests_failed": failed if tests else None,
        "temperature_c": _dict(hardware.get("Temperatures")).get("Mainboard"),
        "rtc_battery_v": hardware.get("RTCBatteryVoltage"),
        "users_logged_in": len(data["UsersLoggedIn"]) if isinstance(data.get("UsersLoggedIn"), list) else None,
    }
    for area in ("Memory", "Storage", "RAID"):
        block = _dict(data.get(area))
        used, free = block.get("UsedBytes"), block.get("AvailableBytes")
        if isinstance(used, int) and isinstance(free, int) and used + free > 0:
            status["{0}_used_percent".format(area.lower())] = round(100.0 * used / (used + free), 1)
    return {k: v for k, v in status.items() if v is not None}


def parse_alarms(items: Iterable[Any]) -> List[Dict[str, Any]]:
    """Alarm summary rows, oldest first, in a shape close to the web alarms."""

    alarms = []
    for item in items:
        item = _dict(item)
        if not item.get("TagName"):
            continue
        alarms.append({
            "timestamp": item.get("Timestamp"),
            "tag": item["TagName"],
            "state": item.get("AlarmState"),
            "acknowledgement": item.get("AcknowledgementState"),
            "priority": item.get("Priority"),
            "category": item.get("Category"),
            "message": item.get("Message"),
            "event_total": item.get("EventTotal"),
            "active_event_count": item.get("ActiveEventCount"),
        })
    return sorted(alarms, key=lambda a: str(a["timestamp"] or ""))


def active_alarms(alarms: Iterable[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    return [a for a in alarms if a.get("state") == "Alarmed"]


def parse_alarm_history(items: Iterable[Any]) -> List[Dict[str, Any]]:
    events = []
    for item in items:
        item = _dict(item)
        events.append({
            "timestamp": item.get("Timestamp"),
            "tag": item.get("TagName"),
            "event_type": item.get("EventType"),
            "state": item.get("AlarmState"),
            "priority": item.get("Priority"),
            "message": item.get("Message"),
        })
    return sorted(events, key=lambda e: str(e["timestamp"] or ""))


def _endpoint(entries: Any) -> Optional[str]:
    for entry in entries if isinstance(entries, list) else []:
        entry = _dict(entry)
        if entry.get("Physical") == "Serial":
            return entry.get("Interface")
        if entry.get("IPAddress"):
            port = entry.get("Port")
            return "{0}:{1}".format(entry["IPAddress"], port) if port else entry["IPAddress"]
    return None


def parse_connections(items: Any) -> List[Dict[str, Any]]:
    rows = []
    for item in items if isinstance(items, list) else []:
        item = _dict(item)
        counts = _dict(item.get("MessageCount"))
        status = _dict(counts.get("Status"))
        total = _dict(counts.get("Total"))
        successes, failures = status.get("Successes"), status.get("Failures")
        row = {
            "name": item.get("Name"),
            "status": item.get("Status"),
            "manufacturer": item.get("Manufacturer"),
            "model": item.get("Model"),
            "service": item.get("Service"),
            "egress": _endpoint(item.get("Egress")),
            "ingress": _endpoint(item.get("Ingress")),
            "successes": successes,
            "failures": failures,
            "sent": total.get("Sent"),
            "received": total.get("Received"),
        }
        if isinstance(successes, int) and isinstance(failures, int) and successes + failures > 0:
            row["failure_ratio"] = round(failures / float(successes + failures), 4)
        rows.append({k: v for k, v in row.items() if v is not None})
    return rows


def symbol_names(items: Any) -> List[str]:
    return [s["Name"] for s in items if isinstance(s, dict) and isinstance(s.get("Name"), str)] \
        if isinstance(items, list) else []


__all__ = [
    "active_alarms", "parse_alarm_history", "parse_alarms", "parse_connections", "parse_id", "parse_status",
    "symbol_names",
]
