"""sel-settings-capture: live, read-only capture of complete SEL settings (FILE READ / FILE SHOW).

The fleet orchestration ported from SEL-Audit ``cli_audit_rdb.py`` / ``cli_read_settings.py``:
devices come from the sel-triage inventory, credentials from the Keychain, one login per
device and never retried. Sites run in parallel, devices within a site one at a time; the
sweep stops when unreachable devices span several sites and the device network is down. Captures
land in SEL-Audit's ``<root>/<site>/<host>_<port>/<UTC stamp>/`` layout, so ``sel-inventory``
and ``sel-settings check|diff`` read them directly. It never opens or prompts for a VPN.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..core.errors import TriageError
from ..core.evidence import default_evidence_root
from ..core.inventory import DeviceTarget, resolve_device
from ..core.redaction import SecretFingerprintRedactor
from ..integrations.devices.sel.settings.capture import discover_devices
from ..integrations.devices.sel.settings.live import CaptureOptions, capture_settings
from ..sel_archive.device import SweepItem
from ..sel_archive.sweep import UnreachableGuard, fleet_items

DEFAULT_MAX_SITES_PARALLEL = 4
DEFAULT_UNREACHABLE_STOP_AFTER = 3
DEFAULT_READ_TIMEOUT_SECONDS = 60.0


def default_captures_root() -> Path:
    return default_evidence_root().parent / "sel-settings"


def default_index_path() -> Path:
    return default_evidence_root().parent / "sel-settings.sqlite"


def configured_paths(config: dict) -> tuple:
    """(captures root, index database) from ``selSettings`` or the defaults."""

    section = config.get("selSettings", {}) or {}
    root = Path(section.get("capturesDir") or default_captures_root()).expanduser()
    db = Path(section.get("indexPath") or default_index_path()).expanduser()
    return root, db


@dataclass
class CaptureDeps:
    network_up: Callable[[], bool]
    client_factory: Callable[[DeviceTarget], Any]
    secret_provider: Any
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    sleep: Callable[[float], None] = time.sleep


@dataclass(frozen=True)
class CaptureSettings:
    root: Path
    options: CaptureOptions = field(default_factory=CaptureOptions)
    max_sites_parallel: int = DEFAULT_MAX_SITES_PARALLEL
    unreachable_stop_after: int = DEFAULT_UNREACHABLE_STOP_AFTER
    max_age_days: Optional[float] = None


def folder_name(name: str) -> str:
    """A site name made safe as a folder name (SEL-Audit's rule)."""

    name = re.sub(r'[\\/:*?"<>|]', "_", name.strip())
    name = re.sub(r"\s+", " ", name)
    return name.strip(" .") or "(unnamed)"


def device_folder(root: Path, item: SweepItem) -> Path:
    return root / folder_name(item.site) / "{0}_{1}".format(item.target.host, item.target.port)


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def recent_captures(root: Path, now: datetime, max_age_days: float) -> Dict[str, str]:
    """``site/host_port`` -> newest ``ok`` capture time, for captures newer than *max_age_days*."""

    if not root.is_dir():
        return {}
    cutoff = now - timedelta(days=max_age_days)
    recent: Dict[str, str] = {}
    for device in discover_devices(root):
        for run in reversed(device["captures"]):
            if run.get("status") != "ok" or not run.get("captured_at"):
                continue
            when = datetime.strptime(run["captured_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if when >= cutoff:
                recent[device["key"]] = run["captured_at"]
            break
    return recent


def _error_text(error: BaseException) -> str:
    category = getattr(error, "category", None)
    lines = ["Error: {0}: {1}".format(type(error).__name__, error)]
    if category:
        lines.append("Category: {0}".format(category))
    return "\n".join(lines) + "\n"


def capture_device(item: SweepItem, settings: CaptureSettings, deps: CaptureDeps) -> Dict[str, Any]:
    """Log in once, capture every settings stream, log out. Never retries a login."""

    started = deps.clock()
    run_dir = device_folder(settings.root, item) / _stamp(started)
    row: Dict[str, Any] = {
        "device": item.target.name,
        "site": item.site,
        "path": str(run_dir.relative_to(settings.root)),
        "reachable": None,
        "ok": False,
    }
    client = None
    redactor: Optional[SecretFingerprintRedactor] = None
    try:
        client = deps.client_factory(item.target)
        secret = deps.secret_provider.get(item.target.credential_ref)
        try:
            redactor = SecretFingerprintRedactor(secret)
            identity = client.login(secret)
        finally:
            secret = None
        row["reachable"] = True
        row["observed_model"] = identity.observed_model
        manifest = capture_settings(
            client,
            run_dir,
            transcript=lambda: client.transcript,
            redact=redactor.redact,
            options=settings.options,
            sleep=deps.sleep,
        )
        row.update(
            ok=True,
            method=manifest["method"],
            files=sorted(manifest["files"]),
            skipped=[entry["file"] for entry in manifest["skipped"]],
        )
    except Exception as error:  # one device's failure never stops the sweep
        reachable = getattr(error, "reachable", None)
        row["reachable"] = row["reachable"] or reachable
        row["error_category"] = getattr(error, "category", None) or type(error).__name__
        row["error"] = str(error)
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
            transcript = client.transcript.decode("utf-8", "replace") if client is not None else ""
            if redactor is not None:
                transcript = redactor.redact(transcript)
            (run_dir / "ERROR.txt").write_text(_error_text(error) + "\n" + transcript, encoding="utf-8")
        except OSError:
            row.setdefault("warnings", []).append("error_file_not_written")
    finally:
        redactor = None
        if client is not None:
            try:
                client.logout()
            except Exception:
                row.setdefault("warnings", []).append("logout_failed")
    row["seconds"] = round((deps.clock() - started).total_seconds(), 1)
    return row


def select_items(config: dict, *, name: Optional[str] = None, site: Optional[str] = None) -> List[SweepItem]:
    if name is not None:
        target = resolve_device(config, name=name)
        if target.kind != "sel":
            raise ValueError("{0} is not an SEL device (kind {1})".format(name, target.kind))
        entry_site = next(
            (entry.get("site") for entry in config.get("devices", []) if entry.get("name") == name), None
        )
        return [SweepItem(entry_site or name.split("/", 1)[0], target)]
    return fleet_items(config, site)


def unique_endpoints(items: List[SweepItem]) -> Tuple[List[SweepItem], List[Dict[str, str]]]:
    """One item per ``host:port`` (first wins), so a device listed twice gets one login."""

    seen: Dict[Tuple[str, int], str] = {}
    keep: List[SweepItem] = []
    duplicates: List[Dict[str, str]] = []
    for item in items:
        endpoint = (item.target.host, item.target.port)
        if endpoint in seen:
            duplicates.append({"device": item.target.name, "same_endpoint_as": seen[endpoint]})
            continue
        seen[endpoint] = item.target.name
        keep.append(item)
    return keep, duplicates


def run_capture(config: dict, items: List[SweepItem], settings: CaptureSettings, deps: CaptureDeps) -> Dict[str, Any]:
    now = deps.clock()
    summary: Dict[str, Any] = {
        "tool": "sel-settings-capture",
        "ran_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ok": True,
        "root": str(settings.root),
        "skipped": None,
        "devices_selected": len(items),
        "devices_attempted": 0,
        "devices_captured": 0,
        "recent_skipped": [],
        "duplicate_endpoints": [],
        "stopped_early": False,
        "results": [],
        "failures": [],
    }
    items, summary["duplicate_endpoints"] = unique_endpoints(items)
    if not items:
        summary["skipped"] = "no_devices"
        return summary
    if not deps.network_up():
        summary.update(ok=False, skipped="network_unreachable",
                       fix="Restore access to the device network, then run sel-settings-capture again.")
        return summary
    if settings.max_age_days is not None:
        recent = recent_captures(settings.root, now, settings.max_age_days)
        keep = []
        for item in items:
            key = "{0}/{1}".format(folder_name(item.site), device_folder(settings.root, item).name)
            if key in recent:
                summary["recent_skipped"].append({"device": item.target.name, "captured_at": recent[key]})
            else:
                keep.append(item)
        items = keep

    by_site: Dict[str, List[SweepItem]] = {}
    for item in items:
        by_site.setdefault(item.site, []).append(item)
    stop = threading.Event()
    guard = UnreachableGuard(settings.unreachable_stop_after)
    tunnel_check = threading.Lock()

    def tunnel_down() -> bool:
        with tunnel_check:
            if stop.is_set():
                return True
            try:
                up = bool(deps.network_up())
            except Exception:
                up = False
            if up:
                guard.reset()
            return not up

    def work(site_items: List[SweepItem]) -> List[Dict[str, Any]]:
        rows = []
        for item in site_items:
            if stop.is_set():
                break
            row = capture_device(item, settings, deps)
            rows.append(row)
            if guard.observe(item.site, row["reachable"] is True) and tunnel_down():
                stop.set()
        return rows

    results: List[Dict[str, Any]] = []
    if by_site:
        with ThreadPoolExecutor(max_workers=max(1, settings.max_sites_parallel)) as pool:
            for rows in pool.map(work, list(by_site.values())):
                results.extend(rows)
    summary.update(
        results=results,
        devices_attempted=len(results),
        devices_captured=sum(1 for row in results if row["ok"]),
        stopped_early=stop.is_set(),
        failures=[
            {"device": row["device"], "category": row.get("error_category"), "path": row["path"]}
            for row in results
            if not row["ok"]
        ],
    )
    summary["ok"] = not summary["failures"] and not summary["stopped_early"]
    return summary


__all__ = [
    "CaptureDeps",
    "CaptureSettings",
    "capture_device",
    "configured_paths",
    "default_captures_root",
    "default_index_path",
    "folder_name",
    "recent_captures",
    "run_capture",
    "select_items",
    "unique_endpoints",
]
