"""Diff two saved SEL settings captures: drift on one device, or two peers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .capture import discover_devices, latest_settings_capture

# (class pattern, key pattern) pairs that change without a settings change.
VOLATILE = (
    # SEL-735 "Meter Energy Preload": accumulated energy registers.
    (r"E", r".*"),
    # SEL-735 time-of-use stream: one large value that changed between
    # back-to-back captures with no settings change.
    (r"TOU", r".*"),
)
# Keys that name or address one device; differences between peers are expected.
_IDENTITY_KEY = re.compile(
    r"^(RID|TID|MID|DEVID|CONAM|Dev\.(Id|Loc|CoName)|IPADDR\w*|IPSUBNET\w*|DEFRTR\w*|HOSTNAME\w*|"
    r"DNPADR\w*|DNPIP\w*|SLAVEID\w*|MAC\w*|[\w.]*\.IPAddr\w*|[\w.]*\.(Host|Addr|SrcAddr|SlaveID)\w*)$"
)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IDENTITY_FIELDS = ("fid", "bfid", "part_number", "serial_number", "device_id", "model")


def _summary(run: Mapping[str, Any]) -> Dict[str, Any]:
    identity = run.get("identity") or {}
    return {
        "run": run.get("path") or run.get("run"),
        "captured_at": run.get("captured_at"),
        "model": identity.get("model"),
        "fid": identity.get("fid"),
    }


def _matches(patterns: Iterable[Tuple[str, str]], cls: str, key: str) -> bool:
    return any(re.fullmatch(c, cls) and re.fullmatch(k, key) for c, k in patterns)


def diff_runs(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    same_device: bool,
    include_identity: bool = False,
    ignore: Iterable[str] = (),
) -> Dict[str, Any]:
    """Setting-by-setting differences from capture *a* to capture *b*.

    Volatile keys are always skipped; identity/address keys are skipped
    between different devices unless ``include_identity``. ``ignore`` adds
    key regular expressions to skip.
    """

    try:
        extra = [re.compile(pattern) for pattern in ignore]
    except re.error as exc:
        raise ValueError("invalid --ignore pattern: {0}".format(exc)) from None
    settings_a = a.get("settings") or {}
    settings_b = b.get("settings") or {}
    changes: List[Dict[str, Any]] = []
    ignored = {"volatile": 0, "identity": 0, "pattern": 0}
    for cls in sorted(set(settings_a) & set(settings_b)):
        values_a, values_b = settings_a[cls], settings_b[cls]
        for key in sorted(set(values_a) | set(values_b)):
            va, vb = values_a.get(key), values_b.get(key)
            if va == vb:
                continue
            if _matches(VOLATILE, cls, key):
                ignored["volatile"] += 1
                continue
            if not same_device and not include_identity and (
                _IDENTITY_KEY.match(key) or any(_IPV4.match(v or "") for v in (va, vb))
            ):
                ignored["identity"] += 1
                continue
            if any(pattern.fullmatch(key) for pattern in extra):
                ignored["pattern"] += 1
                continue
            changes.append({"class": cls, "key": key, "a": va, "b": vb})
    identity_a, identity_b = a.get("identity") or {}, b.get("identity") or {}
    identity_changes = {
        field: [identity_a.get(field), identity_b.get(field)]
        for field in _IDENTITY_FIELDS
        if identity_a.get(field) != identity_b.get(field)
        and (same_device or field not in ("device_id", "serial_number"))
    }
    notes = []
    if identity_a.get("model") and identity_b.get("model") and identity_a["model"] != identity_b["model"]:
        notes.append("models differ ({0} vs {1}); many settings will not line up".format(
            identity_a["model"], identity_b["model"]))
    return {
        "a": _summary(a),
        "b": _summary(b),
        "same_device": same_device,
        "identity_changes": identity_changes,
        "classes_only_in_a": sorted(set(settings_a) - set(settings_b)),
        "classes_only_in_b": sorted(set(settings_b) - set(settings_a)),
        "changes": changes,
        "ignored": ignored,
        "notes": notes,
        "summary": {
            "changed": sum(1 for c in changes if c["a"] is not None and c["b"] is not None),
            "only_in_a": sum(1 for c in changes if c["b"] is None),
            "only_in_b": sum(1 for c in changes if c["a"] is None),
        },
    }


def _one_device(path: Path) -> Dict[str, Any]:
    devices = discover_devices(path)
    if len(devices) != 1:
        raise ValueError("{0} holds {1} devices; give one device or capture folder".format(path, len(devices)))
    return devices[0]


def resolve_diff_inputs(
    a: Path, b: Optional[Path]
) -> Tuple[Dict[str, Any], Dict[str, Any], bool]:
    """Captures to compare, and whether both belong to the same device.

    A device folder means its newest settings capture; with no *b*, the
    device's two newest settings captures are compared (older first).
    """

    device_a = _one_device(Path(a))
    if b is None:
        runs = [run for run in device_a["captures"] if run.get("settings")]
        if len(runs) < 2:
            raise ValueError("{0} has fewer than two settings captures to compare".format(a))
        return runs[-2], runs[-1], True
    device_b = _one_device(Path(b))
    run_a = latest_settings_capture(device_a)
    run_b = latest_settings_capture(device_b)
    for path, run in ((a, run_a), (b, run_b)):
        if run is None:
            raise ValueError("{0} has no settings capture".format(path))
    return run_a, run_b, device_a["key"] == device_b["key"]


__all__ = ["VOLATILE", "diff_runs", "resolve_diff_inputs"]
