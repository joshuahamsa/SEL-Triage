"""sel-inventory and sel-settings: offline tools over saved SEL captures.

Nothing here contacts a device: inputs are SEL-Audit ``Reads`` folders or the
sel-triage evidence store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

from ..core.thresholds import resolve_thresholds
from ..integrations.devices.sel.settings.capture import discover_devices
from ..integrations.devices.sel.settings.checks import check_devices, rule_catalog
from ..integrations.devices.sel.settings.diff import diff_runs, resolve_diff_inputs
from ..integrations.devices.sel.settings.inventory import build_inventory


def _now(now: Any) -> datetime:
    if callable(now):
        now = now()
    if isinstance(now, datetime) and now.tzinfo is not None:
        return now.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _stamp(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _thresholds_for(config: Mapping[str, Any], names: Iterable[str]) -> Callable[[str, Optional[str]], Dict[str, float]]:
    names = tuple(names)

    def lookup(device: str, model: Optional[str]) -> Dict[str, float]:
        return resolve_thresholds(config, device, model, names)

    return lookup


def run_inventory(args, config, threshold_names, now=None) -> Dict[str, Any]:
    moment = _now(now)
    if args.max_age_days is not None and args.max_age_days < 0:
        raise ValueError("--max-age-days must be >= 0")
    devices = discover_devices(Path(args.path))
    result = build_inventory(
        devices, moment, max_age_days=args.max_age_days,
        thresholds_for=_thresholds_for(config, threshold_names),
    )
    return dict({"tool": "sel-inventory", "ran_at": _stamp(moment), "ok": True, "source": str(args.path)}, **result)


def run_check(args, config, threshold_names, now=None) -> Dict[str, Any]:
    moment = _now(now)
    devices = discover_devices(Path(args.path))
    result = check_devices(
        devices, config=config, thresholds_for=_thresholds_for(config, threshold_names), group=str(args.group),
    )
    return dict({"tool": "sel-settings-check", "ran_at": _stamp(moment), "ok": True, "source": str(args.path)}, **result)


def run_rules(now=None) -> Dict[str, Any]:
    return {"tool": "sel-settings-rules", "ran_at": _stamp(_now(now)), "ok": True, "rules": rule_catalog()}


def run_index(args, config, now=None) -> Dict[str, Any]:
    from ..integrations.devices.sel.settings.index import build_index, inventory_endpoints
    from .sel_capture import configured_paths

    moment = _now(now)
    default_root, default_db = configured_paths(config)
    root = Path(args.path).expanduser() if args.path else default_root
    db = Path(args.db).expanduser() if args.db else default_db
    result = build_index(root, db, rebuild=args.rebuild, now=moment, endpoints=inventory_endpoints(config))
    return dict({"tool": "sel-settings-index", "ran_at": _stamp(moment), "ok": True}, **result)


def run_diff(args, now=None) -> Dict[str, Any]:
    moment = _now(now)
    run_a, run_b, same = resolve_diff_inputs(Path(args.a), Path(args.b) if args.b else None)
    result = diff_runs(run_a, run_b, same_device=same, include_identity=args.include_identity, ignore=args.ignore or ())
    return dict({"tool": "sel-settings-diff", "ran_at": _stamp(moment), "ok": True}, **result)


__all__ = ["run_check", "run_diff", "run_index", "run_inventory", "run_rules"]
