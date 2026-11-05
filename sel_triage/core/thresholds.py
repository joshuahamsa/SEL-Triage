"""Per-device diagnostic threshold overrides from the config.

``diagnosticThresholds`` holds top-level values plus ``byModel``, ``bySite``
and ``byDevice`` sections; more specific sections win. Only overrides are
returned; the diagnostics module fills in its own defaults.
"""

import math
from typing import Any, Dict, Iterable, Mapping, Optional

LEVELS = ("byModel", "bySite", "byDevice")


def _checked(values: Any, known: Iterable[str], where: str) -> Dict[str, float]:
    if not isinstance(values, Mapping):
        raise ValueError("{0} must be an object".format(where))
    known = set(known)
    checked = {}
    for name, value in values.items():
        if name in LEVELS and where == "diagnosticThresholds":
            continue
        location = "" if where == "diagnosticThresholds" else " in {0}".format(where.replace("diagnosticThresholds.", ""))
        if name not in known:
            raise ValueError(
                "unknown diagnostic threshold '{0}'{1}; expected one of: {2}".format(
                    name, location, ", ".join(sorted(known))
                )
            )
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value < 0
        ):
            raise ValueError("diagnostic threshold '{0}'{1} must be a number >= 0".format(name, location))
        checked[name] = value
    return checked


def _section(config_section: Mapping[str, Any], level: str, key: Optional[str], known, fold_case=False):
    entries = config_section.get(level, {})
    if not isinstance(entries, Mapping):
        raise ValueError("{0} must be an object".format(level))
    found = {}
    for name, values in entries.items():
        checked = _checked(values, known, "{0}.{1}".format(level, name))
        matches = key is not None and (name.upper() == key.upper() if fold_case else name == key)
        if matches:
            found = checked
    return found


def resolve_thresholds(
    config: Mapping[str, Any],
    device_name: Optional[str],
    model_hint: Optional[str],
    known: Iterable[str],
) -> Dict[str, float]:
    """Return the threshold overrides that apply to one device."""

    known = tuple(known)
    section = config.get("diagnosticThresholds", {}) if isinstance(config, Mapping) else {}
    if section == {}:
        return {}
    resolved = _checked(section, known, "diagnosticThresholds")
    site = device_name.split("/", 1)[0] if isinstance(device_name, str) and "/" in device_name else None
    resolved.update(_section(section, "byModel", model_hint, known, fold_case=True))
    resolved.update(_section(section, "bySite", site, known))
    resolved.update(_section(section, "byDevice", device_name, known))
    return resolved


__all__ = ["resolve_thresholds"]
