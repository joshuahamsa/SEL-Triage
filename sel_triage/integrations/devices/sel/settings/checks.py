"""Rule-based checks over saved SEL settings captures (offline).

Rules are listed in ``RULES`` (code, severity, scope, description) and read
their key patterns, default values and lists from ``DEFAULT_RULE_DATA``. The
config section ``selSettingsChecks`` can disable rules and replace the data
(``factoryWearCurves``, ``defaultDeviceIds``, ``meterModels``); numeric
thresholds come from ``diagnosticThresholds`` like the live diagnostics.

Settings groups: FILE READ saves every group but not which one is active, so
group checks use group 1 unless another group is requested.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from sel_triage.core.diagnostics import Diagnostic
from ..diagnostics import _FACTORY_WEAR_CURVE, _factory_curve_sides
from .capture import latest_settings_capture

DEFAULT_THRESHOLDS = {
    "sel_capture_max_age_days": 180.0,
    # Shared with the live snapshot diagnostics.
    "clock_drift_seconds": 300.0,
    "sel_nominal_frequency_hz": 60.0,
}

DEFAULT_RULE_DATA: Dict[str, Any] = {
    # Wear curves that mean "never set for the installed breaker".
    "factoryWearCurves": {
        "sel_factory": dict(_FACTORY_WEAR_CURVE),
        # Seen on nearly every SEL-651R-2 in the SEL-Audit captures; treated as
        # that family's shipped default.
        "sel651r_common_default": {
            "COSP1": 10000.0, "COSP2": 20.0, "COSP3": 20.0,
            "KASP1": 0.10, "KASP2": 6.00, "KASP3": 6.00,
        },
    },
    # Relay/terminal IDs left at a factory value make events hard to attribute.
    "defaultDeviceIds": [
        "SEL-351", "SEL-351A", "SEL-351S", "SEL-651R", "651R", "SEL-651RA", "SEL-700G",
        "SEL-700GT", "SEL-735", "SEL-751", "SEL-751A", "SEL-851", "FEEDER 1", "STATION A",
        "RELAY 1",
    ],
    # Meters: no trip, protection-element or breaker-monitor rules.
    "meterModels": ["SEL-735"],
}

_RATIO_KEY = re.compile(r"^(CTR[A-Z]?|PTR[A-Z]?|CT[PN]\.Rat|VT[PS]\.Rat)$")
_CT_KEY = re.compile(r"^(CTR[A-Z]?|CT[PN]\.Rat)$")
_PHASE_ROTATION_KEYS = ("PHROT", "Sys.PhRot")
_FREQUENCY_KEYS = ("NFREQ", "FNOM", "Sys.FNom")
_UTC_OFFSET_KEYS = ("UTC_OFF", "Time.UTC_Ofs")
_DST_KEYS = ("DST_BEGM", "Time.DST_StrMo")
_ID_KEYS = ("RID", "TID", "MID", "Dev.Id")
_TRIP_KEY = re.compile(r"^(TR|TR[XY]|TR\d|TR3P|TR3X|TR[ABC]|Trip_\d+\.(Init|InitX|LocInit|RemInit))$")
_EMPTY_EQUATION = {"", "0", "NA"}
_MONITOR_ENABLE = re.compile(r"^EBMON[XY]?$")
# Element pickups (legacy dialect) and enables (SEL-851 dotted dialect).
# 50P32P / 50QFP / 50GRP style keys are directional thresholds, not elements.
_DIRECTIONAL = re.compile(r"^50[PQGN](32|F|R)P$")
_PICKUP = re.compile(r"^(?P<family>50|51|27|59|81|67)[A-Z0-9]*P$")
_ENABLE_851 = re.compile(r"^(?P<family>50|51|27|59|81|67|32)[A-Za-z0-9_]*\.Ena$")
_OVERCURRENT = ("50", "51", "67")
_SNTP_ENABLE = re.compile(r"^(ESNTP|Port_\w+\.SNTP_Ena)$")
_OFF = {"OFF", "N", "NO", "0", "NONE"}
_GROUP_CLASS = re.compile(r"^\d+$")
# Relay clocks are set to some local time; beyond +/-14 h no time zone explains the offset.
_MAX_ZONE_OFFSET_SECONDS = 14 * 3600

RULES: Tuple[Dict[str, str], ...] = (
    {"code": "breaker_monitor_default_curve", "severity": "info", "scope": "device",
     "description": "The breaker monitor is enabled with a factory/default wear curve rather than values for the installed breaker."},
    {"code": "breaker_monitor_disabled", "severity": "info", "scope": "device",
     "description": "The breaker monitor is disabled, so contact wear and trip counts are not tracked."},
    {"code": "ratio_missing", "severity": "warning", "scope": "device",
     "description": "No CT ratio setting was found in the checked group."},
    {"code": "ratio_unity", "severity": "info", "scope": "device",
     "description": "A CT or PT ratio is 1 (direct connection, or a ratio never set); metering is in secondary units."},
    {"code": "ratio_differs_between_groups", "severity": "info", "scope": "device",
     "description": "CT/PT ratios differ between settings groups; instrument transformers do not change with the group."},
    {"code": "phase_rotation_missing", "severity": "warning", "scope": "device",
     "description": "No phase rotation setting was found."},
    {"code": "phase_rotation_acb", "severity": "info", "scope": "device",
     "description": "Phase rotation is set to ACB. If the bus is really ABC, sequence quantities are swapped and a live "
                    "snapshot reports phase_sequence_reversed; confirm against the site one-line."},
    {"code": "trip_equations_empty", "severity": "warning", "scope": "device",
     "description": "Every trip equation in the checked group is empty or 0, so the relay cannot trip its breaker."},
    {"code": "protection_elements_off", "severity": "warning", "scope": "device",
     "description": "Every overcurrent, voltage and frequency element in the checked group is off."},
    {"code": "overcurrent_elements_off", "severity": "info", "scope": "device",
     "description": "Every overcurrent element in the checked group is off (voltage/frequency elements remain)."},
    {"code": "clock_free_running", "severity": "warning", "scope": "device",
     "description": "The relay reported an internal time source at login and SNTP is off: its clock is free-running."},
    {"code": "sntp_disabled", "severity": "info", "scope": "device",
     "description": "SNTP is off on every port; time comes from IRIG (not visible in settings) or the internal clock."},
    {"code": "clock_drift", "severity": "warning", "scope": "device",
     "description": "The relay clock at login differs from the capture time by more than the threshold beyond a whole-hour time-zone offset."},
    {"code": "nominal_frequency_unexpected", "severity": "warning", "scope": "device",
     "description": "Nominal frequency differs from the configured system frequency."},
    {"code": "default_device_id", "severity": "info", "scope": "device",
     "description": "A relay or terminal ID is still a factory value, which makes events and SER hard to attribute."},
    {"code": "phase_rotation_differs_site_peers", "severity": "warning", "scope": "site",
     "description": "Devices at the same site are set to different phase rotations."},
    {"code": "ratio_differs_site_peers", "severity": "info", "scope": "site",
     "description": "Devices of the same model at the same site use different CT/PT ratios."},
    {"code": "utc_offset_differs_site_peers", "severity": "info", "scope": "site",
     "description": "Devices at the same site use different UTC offsets, so their event times do not line up."},
    {"code": "dst_differs_site_peers", "severity": "info", "scope": "site",
     "description": "Devices at the same site disagree on daylight saving time, so their event times do not line up."},
)
_RULES_BY_CODE = {rule["code"]: rule for rule in RULES}


def rule_catalog() -> List[Dict[str, str]]:
    """Every rule with its code, severity, scope and description."""

    return [dict(rule) for rule in RULES]


def _rule_settings(config: Optional[Mapping[str, Any]]) -> Tuple[Dict[str, Any], set]:
    section = (config or {}).get("selSettingsChecks", {}) if isinstance(config, Mapping) else {}
    if not isinstance(section, Mapping):
        raise ValueError("selSettingsChecks must be an object")
    data = dict(DEFAULT_RULE_DATA)
    for name in ("factoryWearCurves", "defaultDeviceIds", "meterModels"):
        if name in section:
            data[name] = section[name]
    if not isinstance(data["factoryWearCurves"], Mapping):
        raise ValueError("selSettingsChecks.factoryWearCurves must be an object")
    disabled = section.get("disabledRules", [])
    if not isinstance(disabled, list):
        raise ValueError("selSettingsChecks.disabledRules must be a list")
    unknown = [code for code in disabled if code not in _RULES_BY_CODE]
    if unknown:
        raise ValueError("unknown SEL settings rule(s) in selSettingsChecks.disabledRules: {0}".format(
            ", ".join(sorted(map(str, unknown)))))
    return data, set(disabled)


def _thresholds(configured: Optional[Mapping[str, Any]]) -> Dict[str, float]:
    values = dict(DEFAULT_THRESHOLDS)
    for name in values:
        value = (configured or {}).get(name)
        if not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(float(value)) and value >= 0:
            values[name] = float(value)
    return values


def _finding(code: str, evidence: Mapping[str, Any]) -> Dict[str, Any]:
    rule = _RULES_BY_CODE[code]
    return Diagnostic(code, rule["severity"], rule["description"], evidence).as_dict()


def _group_classes(settings: Mapping[str, Mapping[str, str]]) -> List[str]:
    return sorted((name for name in settings if _GROUP_CLASS.match(name)), key=int)


def _lookup(settings: Mapping[str, Mapping[str, str]], keys: Iterable[str], group: str) -> Tuple[Optional[str], Optional[str]]:
    """(key, value) of the first key found in the group, then Global, then any class."""

    keys = tuple(keys)
    order = [group, "G"] + [name for name in sorted(settings) if name not in (group, "G")]
    for cls in order:
        values = settings.get(cls) or {}
        for key in keys:
            if key in values:
                return key, values[key]
    return None, None


def _number(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _is_meter(model: Optional[str], data: Mapping[str, Any]) -> bool:
    return bool(model) and any(str(model).startswith(prefix) for prefix in data.get("meterModels", []))


def _ratios(values: Mapping[str, str]) -> Dict[str, str]:
    return {key: value for key, value in values.items() if _RATIO_KEY.match(key)}


def _all_values(settings: Mapping[str, Mapping[str, str]]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for values in settings.values():
        merged.update(values)
    return merged


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _element_state(values: Mapping[str, str]) -> Tuple[Dict[str, bool], Dict[str, str]]:
    """Per element family, whether any element is on; plus the keys looked at."""

    families: Dict[str, bool] = {}
    seen: Dict[str, str] = {}
    for key, value in values.items():
        match = _ENABLE_851.match(key)
        if match is None and not _DIRECTIONAL.match(key):
            match = _PICKUP.match(key)
        if match is None:
            continue
        family = match.group("family")
        on = value.strip().upper() not in _OFF
        families[family] = families.get(family, False) or on
        seen[key] = value
    return families, seen


def check_run(
    run: Mapping[str, Any],
    config: Optional[Mapping[str, Any]] = None,
    thresholds: Optional[Mapping[str, Any]] = None,
    group: str = "1",
) -> List[Dict[str, Any]]:
    """Device-scope findings for one capture run's settings."""

    data, disabled = _rule_settings(config)
    limits = _thresholds(thresholds)
    settings: Mapping[str, Mapping[str, str]] = run.get("settings") or {}
    model = (run.get("identity") or {}).get("model")
    meter = _is_meter(model, data)
    group_values = settings.get(group) or {}
    merged = _all_values(settings)
    findings: List[Dict[str, Any]] = []

    def add(code: str, evidence: Mapping[str, Any]) -> None:
        if code not in disabled:
            findings.append(_finding(code, evidence))

    # Breaker monitor (reuses the live snapshot rule per known default curve).
    monitor_values = settings.get("G") or merged
    if not meter:
        for name, curve in data["factoryWearCurves"].items():
            sides = _factory_curve_sides(monitor_values, {k: float(v) for k, v in curve.items()})
            if sides:
                add("breaker_monitor_default_curve", {
                    "sides": sides, "curve": name,
                    "monitor_settings": {k: v for k, v in monitor_values.items()
                                         if re.match(r"^(EBMON|COSP[123]|KASP[123])[XY]?$", k)},
                })
                break
        enables = {k: v for k, v in monitor_values.items() if _MONITOR_ENABLE.match(k)}
        if enables and all(v.strip().upper() in _OFF for v in enables.values()):
            add("breaker_monitor_disabled", {"monitor_settings": enables})

    # CT/PT ratios.
    ratios = _ratios(group_values)
    if group_values and not any(_CT_KEY.match(key) for key in ratios):
        add("ratio_missing", {"group": group})
    unity = {key: value for key, value in ratios.items() if _number(value) == 1.0}
    if unity:
        add("ratio_unity", {"group": group, "ratios": unity})
    groups = _group_classes(settings)
    if len(groups) > 1:
        differing: Dict[str, Dict[str, str]] = {}
        all_keys = sorted({key for cls in groups for key in _ratios(settings[cls])})
        for key in all_keys:
            per_group = {cls: settings[cls][key] for cls in groups if key in settings[cls]}
            if len({_number(v) if _number(v) is not None else v for v in per_group.values()}) > 1:
                differing[key] = per_group
        if differing:
            add("ratio_differs_between_groups", {"ratios": differing})

    # Phase rotation.
    key, rotation = _lookup(settings, _PHASE_ROTATION_KEYS, group)
    if rotation is None:
        if settings:
            add("phase_rotation_missing", {})
    elif rotation.strip().upper() == "ACB":
        add("phase_rotation_acb", {"configured_rotation": rotation, "setting": key})

    # Trip equations and protection elements (protective relays only).
    if not meter:
        trips = {k: v for k, v in group_values.items() if _TRIP_KEY.match(k)}
        logic_trips = {k: v for cls, values in settings.items() if cls.startswith("L")
                       for k, v in values.items() if _TRIP_KEY.match(k)}
        if not trips:
            trips = logic_trips
        if trips and all(v.strip().upper() in _EMPTY_EQUATION for v in trips.values()):
            add("trip_equations_empty", {"group": group, "trip_equations": trips})
        families, seen = _element_state(group_values)
        if seen:
            if not any(families.values()):
                add("protection_elements_off", {"group": group, "elements_checked": len(seen)})
            elif any(f in families for f in _OVERCURRENT) and not any(
                families.get(f, False) for f in _OVERCURRENT
            ):
                add("overcurrent_elements_off", {
                    "group": group,
                    "elements_on": sorted(f for f, on in families.items() if on),
                })

    # Time source and clock.
    sntp = {k: v for values in settings.values() for k, v in values.items() if _SNTP_ENABLE.match(k)}
    sntp_on = any(v.strip().upper() not in _OFF for v in sntp.values())
    banner = run.get("banner") or {}
    source = str(banner.get("time_source") or "")
    if source.lower().startswith("int") and not sntp_on:
        add("clock_free_running", {"banner_time_source": source, "sntp": sntp})
    elif sntp and not sntp_on and not source:
        irig_key, irig = _lookup(settings, ("TIME_SRC", "IRIGC", "Time.IRIG_CtlBits"), group)
        evidence: Dict[str, Any] = {"sntp": sntp}
        if irig is not None:
            evidence[irig_key] = irig
        add("sntp_disabled", evidence)
    relay_time = _parse_time(banner.get("relay_time"))
    captured = _parse_time(run.get("captured_at"))
    if relay_time is not None and captured is not None:
        offset = int(round((relay_time - captured).total_seconds()))
        outside = abs(offset) > _MAX_ZONE_OFFSET_SECONDS
        drift = abs(offset) if outside else abs(offset - int(round(offset / 3600.0)) * 3600)
        if drift > limits["clock_drift_seconds"]:
            evidence = {
                "relay_time": banner["relay_time"], "captured_at": run["captured_at"],
                "offset_seconds": offset, "drift_seconds": drift,
                "threshold_seconds": limits["clock_drift_seconds"],
            }
            if outside:
                evidence["outside_time_zone_range"] = True
            add("clock_drift", evidence)

    # Nominal frequency.
    key, frequency = _lookup(settings, _FREQUENCY_KEYS, group)
    if frequency is not None and _number(frequency) is not None and _number(frequency) != limits["sel_nominal_frequency_hz"]:
        add("nominal_frequency_unexpected", {
            "setting": key, "value": frequency, "expected_hz": limits["sel_nominal_frequency_hz"],
        })

    # Factory device IDs.
    defaults = {str(value).strip().upper() for value in data.get("defaultDeviceIds", [])}
    left = {}
    for cls in [group, "G"]:
        for key in _ID_KEYS:
            value = (settings.get(cls) or {}).get(key)
            if value is not None and value.strip().upper() in defaults:
                left[key] = value
    if left:
        add("default_device_id", {"ids": left})
    return findings


def _site_findings(entries: List[Dict[str, Any]], disabled: set, group: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    by_site: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        if entry.get("site") and entry.get("_settings"):
            by_site[entry["site"]].append(entry)

    def add(code: str, evidence: Mapping[str, Any]) -> None:
        if code not in disabled:
            findings.append(_finding(code, evidence))

    for site, peers in sorted(by_site.items()):
        if len(peers) < 2:
            continue
        for code, keys in (
            ("phase_rotation_differs_site_peers", _PHASE_ROTATION_KEYS),
            ("utc_offset_differs_site_peers", _UTC_OFFSET_KEYS),
            ("dst_differs_site_peers", _DST_KEYS),
        ):
            values = {}
            for peer in peers:
                _, value = _lookup(peer["_settings"], keys, group)
                if value is not None:
                    values[peer["device"]] = value
            normalized = {v.strip().upper() for v in values.values()}
            if code == "dst_differs_site_peers":
                normalized = {"OFF" if v in ("OFF", "NA", "0") else "ON" for v in normalized}
            elif code == "utc_offset_differs_site_peers":
                normalized = {_number(v) for v in values.values()}
            if len(values) > 1 and len(normalized) > 1:
                add(code, {"site": site, "values": values})
        by_model: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for peer in peers:
            if peer.get("model"):
                by_model[peer["model"]].append(peer)
        for model, same in sorted(by_model.items()):
            if len(same) < 2:
                continue
            ratios = {peer["device"]: _ratios(peer["_settings"].get(group) or {}) for peer in same}
            shapes = {tuple(sorted((k, _number(v)) for k, v in r.items())) for r in ratios.values()}
            if len(shapes) > 1:
                add("ratio_differs_site_peers", {"site": site, "model": model, "ratios": ratios})
    return findings


def check_devices(
    devices: List[Mapping[str, Any]],
    config: Optional[Mapping[str, Any]] = None,
    thresholds_for: Optional[Callable[[str, Optional[str]], Mapping[str, float]]] = None,
    group: str = "1",
) -> Dict[str, Any]:
    """Run every enabled rule on each device's newest settings capture."""

    _, disabled = _rule_settings(config)
    entries: List[Dict[str, Any]] = []
    for device in devices:
        run = latest_settings_capture(device)
        entry: Dict[str, Any] = {
            "device": device["key"],
            "site": device.get("site"),
            "group": group,
        }
        if run is None:
            entry.update(status="no_settings", findings=[])
            entries.append(entry)
            continue
        identity = run.get("identity") or {}
        thresholds = thresholds_for(device["key"], identity.get("model")) if thresholds_for else None
        entry.update(
            status="checked",
            model=identity.get("model"),
            fid=identity.get("fid"),
            capture=run.get("path") or run.get("run"),
            captured_at=run.get("captured_at"),
            classes=sorted(run.get("settings") or {}),
            findings=check_run(run, config=config, thresholds=thresholds, group=group),
        )
        entry["_settings"] = run.get("settings") or {}
        entries.append(entry)
    site_findings = _site_findings(entries, disabled, group)
    for entry in entries:
        entry.pop("_settings", None)
    all_findings = [f for e in entries for f in e["findings"]] + site_findings
    summary = {
        "devices": len(entries),
        "devices_checked": sum(1 for e in entries if e["status"] == "checked"),
        "devices_without_settings": sum(1 for e in entries if e["status"] == "no_settings"),
        "devices_with_findings": sum(1 for e in entries if e["findings"]),
        "findings_by_code": dict(Counter(f["code"] for f in all_findings).most_common()),
        "findings_by_severity": dict(sorted(Counter(f["severity"] for f in all_findings).items())),
    }
    return {
        "group": group,
        "devices": entries,
        "site_findings": site_findings,
        "summary": summary,
        "rules": [rule["code"] for rule in RULES if rule["code"] not in disabled],
    }


__all__ = ["DEFAULT_RULE_DATA", "DEFAULT_THRESHOLDS", "RULES", "check_devices", "check_run", "rule_catalog"]
