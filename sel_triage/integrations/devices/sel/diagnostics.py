"""Deterministic diagnostics over normalized SEL snapshot fields."""

from __future__ import annotations

from datetime import datetime, timezone
import math
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from sel_triage.core.diagnostics import Diagnostic
from .adapters import models_match


DEFAULT_THRESHOLDS = {
    "clock_drift_seconds": 300.0,
    "phase_imbalance_percent": 10.0,
    "breaker_wear_percent": 80.0,
    "breaker_operation_count": 5000.0,
    "event_burst_count": 5.0,
    "event_burst_window_seconds": 600.0,
    "phase_sequence_ratio": 2.0,
    "recent_trip_days": 30.0,
    "event_burst_recent_days": 30.0,
}
_TRIP_WORD = re.compile(r"\bTRIP\b", re.IGNORECASE)
_MAX_LISTED_TRIPS = 10
# Below this negative-sequence voltage the bus is treated as de-energized.
_MIN_SEQUENCE_VOLTS = 50.0


def _diagnostic(
    code: str, severity: str, description: str, evidence: Mapping[str, Any]
) -> Dict[str, Any]:
    return Diagnostic(code, severity, description, evidence).as_dict()


def _thresholds(configured: Optional[Mapping[str, Any]]) -> Dict[str, float]:
    values = dict(DEFAULT_THRESHOLDS)
    if not isinstance(configured, Mapping):
        return values
    for name in values:
        value = configured.get(name)
        if (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
            and value >= 0
        ):
            values[name] = float(value)
    return values


def _now(value: Any) -> Optional[datetime]:
    if callable(value):
        value = value()
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    return value.astimezone(timezone.utc)


def _timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _errors(snapshot: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    errors = snapshot.get("errors")
    if not isinstance(errors, list):
        return []
    return [error for error in errors if isinstance(error, Mapping)]


def _model_fields(snapshot: Mapping[str, Any]) -> Tuple[Any, Any]:
    hint = snapshot.get("model_hint")
    observed = snapshot.get("observed_model")
    identity = snapshot.get("identity")
    if observed is None and isinstance(identity, Mapping):
        observed = identity.get("observed_model")
    return hint, observed


def _normalized_fields(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Accept a flat diagnostic input or a workflow's capability sections."""

    values = dict(snapshot)
    identity = snapshot.get("identity")
    if isinstance(identity, Mapping):
        values.update(identity)
    sections = snapshot.get("snapshot")
    if isinstance(sections, Mapping):
        for section in sections.values():
            if isinstance(section, Mapping):
                values.update(section)
    return values


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(float(value)) else None


def _whole(value: float) -> Any:
    return int(value) if float(value).is_integer() else value


def _breaker_details(snapshot: Mapping[str, Any], fields: Mapping[str, Any]) -> Mapping[str, Any]:
    # Flattened fields share one "details" key across sections, so prefer the
    # breaker section when a workflow snapshot is available.
    sections = snapshot.get("snapshot")
    if isinstance(sections, Mapping):
        breaker = sections.get("breaker")
        if isinstance(breaker, Mapping) and isinstance(breaker.get("details"), Mapping):
            return breaker["details"]
        return {}
    details = fields.get("details")
    return details if isinstance(details, Mapping) else {}


def _meter_details(snapshot: Mapping[str, Any], fields: Mapping[str, Any]) -> Mapping[str, Any]:
    sections = snapshot.get("snapshot")
    if isinstance(sections, Mapping):
        meter = sections.get("meter")
        if isinstance(meter, Mapping) and isinstance(meter.get("details"), Mapping):
            return meter["details"]
        return {}
    details = fields.get("details")
    return details if isinstance(details, Mapping) else {}


_MONITOR_SETTING = re.compile(r"^(EBMON|BKMON|COSP[123]|KASP[123])(X|Y)?$")
# SEL's factory breaker wear curve: (close/open operations, kA interrupted).
_FACTORY_WEAR_CURVE = {
    "COSP1": 10000.0,
    "COSP2": 150.0,
    "COSP3": 12.0,
    "KASP1": 1.2,
    "KASP2": 8.0,
    "KASP3": 20.0,
}
_TRIP_EQUATION = re.compile(r"^TR(?:[XY]|\d+)?$")


def _settings(snapshot: Mapping[str, Any]) -> Dict[str, str]:
    """Merge parsed SHO settings from every settings_* section."""

    merged: Dict[str, str] = {}
    sections = snapshot.get("snapshot")
    if not isinstance(sections, Mapping):
        return merged
    for name, section in sections.items():
        if not str(name).startswith("settings_") or not isinstance(section, Mapping):
            continue
        values = section.get("settings")
        if isinstance(values, Mapping):
            merged.update(
                (key, value) for key, value in values.items() if isinstance(value, str)
            )
    return merged


def _monitor_settings(settings: Mapping[str, str]) -> Dict[str, str]:
    return {
        key: value for key, value in settings.items() if _MONITOR_SETTING.match(key)
    }


def _factory_curve_sides(
    settings: Mapping[str, str], factory_curve: Mapping[str, float] = _FACTORY_WEAR_CURVE
) -> List[str]:
    """Breaker monitor sides ("X", "Y" or "") enabled with the factory curve.

    ``factory_curve`` lets offline settings checks test other known default
    curves with the same rule.
    """

    sides = []
    for side in ("", "X", "Y"):
        if settings.get("EBMON" + side) != "Y":
            continue
        try:
            curve = {
                name: float(settings[name + side]) for name in factory_curve
            }
        except (KeyError, ValueError):
            continue
        if curve == dict(factory_curve):
            sides.append(side)
    return sides


def _trip_equations(settings: Mapping[str, str]) -> Dict[str, str]:
    return {
        key: value
        for key, value in settings.items()
        if _TRIP_EQUATION.match(key) and value not in ("0", "NA")
    }


def _sequence_values(details: Mapping[str, Any]) -> Dict[str, Optional[float]]:
    """Positive/negative-sequence magnitudes from 735 or 700G meter details.

    The 735 reports V1, V2, I1 and 3I2; the 700G reports V1X, 3V2X, I1X and
    3I2X (3x the negative-sequence value) in its voltage/current tables.
    """

    def pick(table: str, *names: str) -> Tuple[Optional[float], str]:
        values = details.get(table)
        if not isinstance(values, Mapping):
            return None, ""
        for name in names:
            number = _number(values.get(name))
            if number is not None:
                return number, name
        return None, ""

    def negative(value: Optional[float], name: str) -> Optional[float]:
        return None if value is None else value / 3.0 if name.startswith("3") else value

    v1, _ = pick("sequence_magnitudes", "V1")
    if v1 is None:
        v1, _ = pick("voltages_v", "V1X")
    v2, name = pick("sequence_magnitudes", "V2", "3V2")
    if v2 is None:
        v2, name = pick("voltages_v", "3V2X")
    i1, _ = pick("sequence_magnitudes", "I1")
    if i1 is None:
        i1, _ = pick("currents_a", "I1X")
    i2, iname = pick("sequence_magnitudes", "I2", "3I2")
    if i2 is None:
        i2, iname = pick("currents_a", "3I2X")
    return {"v1": v1, "v2": negative(v2, name), "i1": i1, "i2": negative(i2, iname)}


def _naive(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _reference_time(fields: Mapping[str, Any], now: Any) -> Tuple[Optional[datetime], Optional[str]]:
    """The relay clock (history is in relay-local time), else the snapshot time."""

    reference = _naive(fields.get("clock"))
    if reference is not None:
        return reference, fields.get("clock")
    current = _now(now)
    if current is None:
        return None, None
    reference = current.replace(tzinfo=None)
    return reference, reference.isoformat()


def _recent_trips(fields: Mapping[str, Any], now: Any, days: float) -> Optional[Dict[str, Any]]:
    """Trip events within ``days`` of the relay clock (or now, if unavailable).

    History timestamps are in relay-local time, so the relay's own clock is the
    consistent reference; the snapshot time is only a fallback.
    """

    events = fields.get("events")
    if not isinstance(events, list):
        return None
    reference, reference_text = _reference_time(fields, now)
    if reference is None:
        return None
    trips = []
    for event in events:
        if not isinstance(event, Mapping) or not _TRIP_WORD.search(str(event.get("event_type", ""))):
            continue
        when = _naive(event.get("timestamp"))
        if when is None or when > reference or (reference - when).total_seconds() > days * 86400:
            continue
        entry = {
            "event_number": event.get("event_number"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
        }
        details = event.get("details")
        if isinstance(details, Mapping) and _number(details.get("current_a")) is not None:
            entry["current_a"] = details["current_a"]
        trips.append((when, entry))
    if not trips:
        return None
    trips.sort(key=lambda item: item[0], reverse=True)
    return {
        "days": _whole(days),
        "reference_time": reference_text,
        "trip_count": len(trips),
        "most_recent": trips[0][1]["timestamp"],
        "trips": [entry for _, entry in trips[:_MAX_LISTED_TRIPS]],
    }


def _busiest_event_window(
    events: Any, window_seconds: float, reference: Optional[datetime], recent_days: float
) -> Optional[Dict[str, Any]]:
    if not isinstance(events, list) or reference is None:
        return None
    timed = []
    for event in events:
        if not isinstance(event, Mapping) or not isinstance(event.get("timestamp"), str):
            continue
        try:
            when = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            continue
        when = when.replace(tzinfo=None)
        if when > reference or (reference - when).total_seconds() > recent_days * 86400:
            continue
        timed.append((when, event))
    timed.sort(key=lambda item: item[0])
    best: Optional[Tuple[int, int]] = None
    start = 0
    for end in range(len(timed)):
        while (timed[end][0] - timed[start][0]).total_seconds() > window_seconds:
            start += 1
        if best is None or end - start > best[1] - best[0]:
            best = (start, end)
    if best is None:
        return None
    window = [event for _, event in timed[best[0] : best[1] + 1]]
    types: Dict[str, int] = {}
    for event in window:
        name = str(event.get("event_type") or "")
        types[name] = types.get(name, 0) + 1
    return {
        "event_count": len(window),
        "first_event": window[0]["timestamp"],
        "last_event": window[-1]["timestamp"],
        "event_types": types,
    }


def _phase_measurement(
    phases: Any,
) -> Optional[Tuple[str, List[Mapping[str, Any]], List[float]]]:
    if not isinstance(phases, list) or len(phases) != 3:
        return None
    if not all(isinstance(phase, Mapping) for phase in phases):
        return None
    for field in ("current_a", "voltage_kv"):
        magnitudes = [phase.get(field) for phase in phases]
        if all(
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
            and value > 0
            for value in magnitudes
        ):
            return field, phases, [float(value) for value in magnitudes]
    return None


def _command_errors(errors: Iterable[Mapping[str, Any]]) -> Iterable[Dict[str, Any]]:
    for error in errors:
        if error.get("category") != "command_unavailable":
            continue
        evidence = {"capability": error.get("capability")}
        if "reachable" in error:
            evidence["reachable"] = error.get("reachable")
        yield evidence


def _error_categories(errors: Iterable[Mapping[str, Any]]) -> List[str]:
    categories = []
    for error in errors:
        category = error.get("category")
        if isinstance(category, str) and category and category not in categories:
            categories.append(category)
    return categories


def diagnose_snapshot(
    snapshot: Mapping[str, Any],
    now: Any,
    thresholds: Optional[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Return ordered, evidence-backed findings without operational advice."""

    if not isinstance(snapshot, Mapping):
        raise ValueError("snapshot must be a mapping")
    fields = _normalized_fields(snapshot)
    limits = _thresholds(thresholds)
    errors = _errors(snapshot)
    findings: List[Dict[str, Any]] = []

    if snapshot.get("reachable") is False:
        findings.append(
            _diagnostic(
                "device_unreachable",
                "error",
                "The device was not reachable during this snapshot.",
                {"reachable": False},
            )
        )

    for error in errors:
        if error.get("category") == "authentication_failed":
            evidence = {"category": "authentication_failed"}
            if "reachable" in error:
                evidence["reachable"] = error.get("reachable")
            findings.append(
                _diagnostic(
                    "authentication_failed",
                    "error",
                    "Access Level 1 authentication failed during this snapshot.",
                    evidence,
                )
            )
            break

    model_hint, observed_model = _model_fields(fields)
    identity = fields.get("identity")
    device_id = fields.get("device_id")
    if device_id is None and isinstance(identity, Mapping):
        device_id = identity.get("device_id")
    if (
        isinstance(model_hint, str)
        and isinstance(observed_model, str)
        and not models_match(model_hint, observed_model, device_id)
    ):
        findings.append(
            _diagnostic(
                "model_mismatch",
                "warning",
                "The configured model hint differs from the observed identity.",
                {
                    "model_hint": model_hint.strip().upper(),
                    "observed_model": observed_model.strip().upper(),
                },
            )
        )

    relay_clock = _timestamp(fields.get("clock"))
    reference_time = _now(now)
    if relay_clock is not None and reference_time is not None:
        drift = abs((relay_clock - reference_time).total_seconds())
        if drift > limits["clock_drift_seconds"]:
            measured_drift: Any = int(drift) if drift.is_integer() else drift
            evidence = {
                "clock": fields.get("clock"),
                "drift_seconds": measured_drift,
                "threshold_seconds": limits["clock_drift_seconds"],
            }
            if "time_source" in fields:
                evidence["time_source"] = fields.get("time_source")
            findings.append(
                _diagnostic(
                    "relay_clock_unsynchronized",
                    "warning",
                    "The measured relay clock drift exceeds the configured threshold.",
                    evidence,
                )
            )

    self_test = fields.get("self_test")
    if isinstance(self_test, str) and self_test.strip().upper() in {
        "FAIL",
        "FAILED",
        "ERROR",
    }:
        findings.append(
            _diagnostic(
                "self_test_failed",
                "error",
                "The normalized relay self-test result indicates failure.",
                {"self_test": self_test},
            )
        )

    if isinstance(self_test, str) and self_test.strip().upper() in {"WARN", "WARNING"}:
        evidence = {"self_test": self_test}
        sections = snapshot.get("snapshot")
        status = sections.get("status") if isinstance(sections, Mapping) else fields
        status_details = status.get("details") if isinstance(status, Mapping) else None
        if isinstance(status_details, Mapping) and isinstance(status_details.get("warning_items"), list):
            evidence["warning_items"] = list(status_details["warning_items"])
        findings.append(
            _diagnostic(
                "self_test_warning",
                "warning",
                "The relay's self-test reports one or more items in warning.",
                evidence,
            )
        )

    targets = fields.get("targets")
    asserted_trips = []
    if isinstance(targets, list):
        for target in targets:
            if not isinstance(target, Mapping) or target.get("asserted") is not True:
                continue
            name = target.get("name")
            if isinstance(name, str) and (
                name.strip().upper() == "TRIP"
                or name.strip().upper().startswith(("TRIP_", "TRIPLED"))
            ):
                asserted_trips.append(dict(target))
    if asserted_trips:
        findings.append(
            _diagnostic(
                "trip_target_asserted",
                "warning",
                "One or more normalized trip targets are asserted.",
                {"targets": asserted_trips},
            )
        )

    phase_measurement = _phase_measurement(fields.get("phases"))
    missing_measurements = []
    completed = snapshot.get("completed_capabilities")
    sections = snapshot.get("snapshot")
    capture_only = sorted(
        name
        for name, section in (sections.items() if isinstance(sections, Mapping) else ())
        if isinstance(section, Mapping) and section.get("capture_only") is True
    )
    meter_completed = "meter" not in capture_only and (
        (isinstance(completed, list) and "meter" in completed)
        or (isinstance(sections, Mapping) and "meter" in sections)
    )
    phases_present = "phases" in fields
    if (meter_completed or phases_present) and phase_measurement is None:
        missing_measurements.append("phases")
        measurement_evidence = {
            "capability": "meter",
            "field": "phases",
        }
        if phases_present:
            measurement_evidence["phases"] = fields.get("phases")
        else:
            measurement_evidence["available"] = False
        findings.append(
            _diagnostic(
                "missing_measurement",
                "warning",
                "A valid three-phase measurement set was not available.",
                measurement_evidence,
            )
        )
    if phase_measurement is not None:
        measurement, phases, magnitudes = phase_measurement
        imbalance = (max(magnitudes) - min(magnitudes)) / (
            sum(magnitudes) / 3.0
        ) * 100.0
        if imbalance > limits["phase_imbalance_percent"]:
            findings.append(
                _diagnostic(
                    "phase_imbalance",
                    "warning",
                    "The measured three-phase imbalance exceeds the configured threshold.",
                    {
                        "measurement": measurement,
                        "imbalance_percent": imbalance,
                        "threshold_percent": limits["phase_imbalance_percent"],
                        "phases": phases,
                    },
                )
            )

    settings = _settings(snapshot)
    monitor_settings = _monitor_settings(settings)
    trip_equations = _trip_equations(settings)

    wear = _number(fields.get("breaker_wear_percent"))
    if wear is not None and wear >= limits["breaker_wear_percent"]:
        evidence = {
            "breaker_wear_percent": wear,
            "threshold_percent": limits["breaker_wear_percent"],
        }
        per_phase = _breaker_details(snapshot, fields).get("wear_percent")
        if isinstance(per_phase, Mapping):
            evidence["wear_percent"] = dict(per_phase)
        if monitor_settings:
            evidence["monitor_settings"] = monitor_settings
        findings.append(
            _diagnostic(
                "breaker_wear_high",
                "warning",
                "Breaker contact wear reported by the relay's breaker monitor meets or exceeds the configured threshold.",
                evidence,
            )
        )

    operations = _number(fields.get("operation_count"))
    if operations is not None and operations >= limits["breaker_operation_count"]:
        evidence = {
            "operation_count": _whole(operations),
            "threshold_count": _whole(limits["breaker_operation_count"]),
        }
        if monitor_settings:
            evidence["monitor_settings"] = monitor_settings
        if trip_equations:
            evidence["trip_equations"] = trip_equations
        findings.append(
            _diagnostic(
                "breaker_operations_high",
                "warning",
                "The breaker monitor's trip count meets or exceeds the configured threshold.",
                evidence,
            )
        )

    factory_sides = _factory_curve_sides(settings)
    if factory_sides:
        findings.append(
            _diagnostic(
                "breaker_monitor_default_curve",
                "info",
                "The breaker monitor is enabled with SEL's factory wear curve rather "
                "than values for the installed breaker.",
                {
                    "sides": factory_sides,
                    "monitor_settings": monitor_settings,
                },
            )
        )

    sequence = _sequence_values(_meter_details(snapshot, fields))
    v1, v2 = sequence["v1"], sequence["v2"]
    if (
        v1 is not None
        and v2 is not None
        and v2 >= _MIN_SEQUENCE_VOLTS
        and v2 > limits["phase_sequence_ratio"] * v1
    ):
        evidence = {
            "positive_sequence_v": round(v1, 3),
            "negative_sequence_v": round(v2, 3),
            "threshold_ratio": limits["phase_sequence_ratio"],
        }
        if sequence["i1"] is not None and sequence["i2"] is not None:
            evidence["positive_sequence_a"] = round(sequence["i1"], 3)
            evidence["negative_sequence_a"] = round(sequence["i2"], 3)
        if "PHROT" in settings:
            evidence["configured_rotation"] = settings["PHROT"]
        findings.append(
            _diagnostic(
                "phase_sequence_reversed",
                "warning",
                "Negative-sequence voltage exceeds positive-sequence voltage; the configured "
                "phase rotation likely does not match the measured rotation.",
                evidence,
            )
        )

    recent = _recent_trips(fields, now, limits["recent_trip_days"])
    if recent is not None:
        findings.append(
            _diagnostic(
                "recent_trip",
                "warning",
                "The event history contains trips within the configured recent window.",
                recent,
            )
        )

    burst = _busiest_event_window(
        fields.get("events"),
        limits["event_burst_window_seconds"],
        _reference_time(fields, now)[0],
        limits["event_burst_recent_days"],
    )
    if burst is not None and burst["event_count"] >= limits["event_burst_count"]:
        burst["recent_days"] = _whole(limits["event_burst_recent_days"])
        burst["window_seconds"] = _whole(limits["event_burst_window_seconds"])
        burst["threshold_count"] = _whole(limits["event_burst_count"])
        findings.append(
            _diagnostic(
                "event_burst",
                "warning",
                "Many relay events were recorded within a short window of the recent event history.",
                burst,
            )
        )

    if capture_only:
        findings.append(
            _diagnostic(
                "capture_only_output",
                "info",
                "Output was saved as evidence but is not normalized for this model yet.",
                {"capabilities": capture_only},
            )
        )

    command_evidence = list(_command_errors(errors))
    for evidence in command_evidence:
        findings.append(
            _diagnostic(
                "command_unavailable",
                "warning",
                "A snapshot capability was unavailable for this device.",
                evidence,
            )
        )

    unavailable = snapshot.get("unavailable_capabilities")
    error_categories = _error_categories(errors)
    if errors or snapshot.get("partial") is True or unavailable or missing_measurements:
        evidence = {}
        if isinstance(unavailable, list) and unavailable:
            evidence["unavailable_capabilities"] = list(unavailable)
        if error_categories:
            evidence["error_categories"] = error_categories
        if missing_measurements:
            evidence["missing_measurements"] = missing_measurements
        if not evidence:
            evidence["partial"] = True
        evidence_or_session_errors = {"evidence_write_failed", "logout_failed"}
        if set(error_categories).intersection(evidence_or_session_errors):
            description = (
                "Snapshot completed with one or more evidence or session errors."
            )
        else:
            description = (
                "One or more snapshot capabilities or normalized "
                "measurements were incomplete."
            )
        findings.append(
            _diagnostic(
                "partial_snapshot",
                "warning",
                description,
                evidence,
            )
        )

    return findings


__all__ = ["DEFAULT_THRESHOLDS", "diagnose_snapshot"]
