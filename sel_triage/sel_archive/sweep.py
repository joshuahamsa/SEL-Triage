"""Opportunistic fleet sweep: preflight, site-parallel device reads, commit, state."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
import threading
from typing import Any, Callable, Dict, List, Optional

from ..core.inventory import DeviceTarget, resolve_device
from . import records
from .archive import commit_run
from .device import DeviceResult, SweepItem, sweep_device, utc_now
from .settings import ArchiveSettings
from .state import SweepState, open_state, sweep_lock


@dataclass
class SweepDeps:
    network_up: Callable[[], bool]
    aws_ok: Callable[[], bool]
    notify: Callable[[str], None]
    client_factory: Callable[[DeviceTarget], Any]
    secret_provider: Any
    archive: Any
    clock: Callable[[], datetime] = utc_now


def fleet_items(config: dict, site: Optional[str] = None, name: Optional[str] = None) -> List[SweepItem]:
    items = []
    for entry in config.get("devices", []):
        if entry.get("kind") != "sel":
            continue
        if name is not None and entry["name"] != name:
            continue
        name_ = entry["name"]
        entry_site = entry.get("site") or name_.split("/", 1)[0]
        if site is not None and site.casefold() not in entry_site.casefold():
            continue
        items.append(SweepItem(entry_site, resolve_device(config, name=name_)))
    return items


def order_items(items: List[SweepItem], state: SweepState) -> List[SweepItem]:
    def key(item: SweepItem):
        last = state.last_success(item.device_key)
        return (last is not None, last or "", item.target.name)

    return sorted(items, key=key)


class UnreachableGuard:
    """Stop when consecutive unreachable devices span ``limit`` different sites."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._sites: List[str] = []
        self._lock = threading.Lock()

    def observe(self, site: str, reachable: bool) -> bool:
        with self._lock:
            if reachable:
                self._sites.clear()
                return False
            self._sites.append(site)
            return len(set(self._sites)) >= self.limit

    def reset(self) -> None:
        with self._lock:
            self._sites.clear()


def _stale(state: SweepState, settings: ArchiveSettings, now: datetime) -> bool:
    latest = state.latest_success_any()
    if latest is None:
        return True
    last = datetime.strptime(latest, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=now.tzinfo)
    return (now - last).days >= settings.stale_notify_days


def _sweep_items(items, state, settings, deps):
    priors = {item.device_key: state.prior(item.device_key) for item in items}
    by_site: Dict[str, List[SweepItem]] = {}
    for item in items:
        by_site.setdefault(item.site, []).append(item)
    stop = threading.Event()
    guard = UnreachableGuard(settings.unreachable_stop_after)
    tunnel_check = threading.Lock()

    def tunnel_down() -> bool:
        # Dead devices sort first (never/oldest success), so a run of failures
        # is common while GP is fine: stop only if the tunnel is really gone.
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

    def work(site_items: List[SweepItem]) -> List[DeviceResult]:
        done = []
        for item in site_items:
            if stop.is_set():
                break
            result = sweep_device(
                item,
                priors[item.device_key],
                secret_provider=deps.secret_provider,
                client_factory=deps.client_factory,
                settings=settings,
                clock=deps.clock,
            )
            done.append(result)
            if guard.observe(item.site, result.run_row["reachable"] is True) and tunnel_down():
                stop.set()
        return done

    results: List[DeviceResult] = []
    with ThreadPoolExecutor(max_workers=settings.max_sites_parallel) as pool:
        for done in pool.map(work, list(by_site.values())):
            results.extend(done)
    return results, stop.is_set()


def _record_results(state, results, settings, run_id, finished_at) -> None:
    for result in results:
        if not result.success:
            continue
        key = result.item.device_key
        state.record(
            key,
            finished_at,
            max((r["device_ts"] for r in result.ser_rows), default=None),
            max((r["device_ts"] for r in result.history_rows), default=None),
            [
                (r["device_ts"], r["format"], records.raw_key(settings.prefix, key, run_id, r["raw_name"]))
                for r in result.report_rows
            ],
        )


def run_sweep(config: dict, settings: ArchiveSettings, deps: SweepDeps, state_path, site: Optional[str] = None,
              name: Optional[str] = None) -> Dict:
    now = deps.clock()
    summary: Dict[str, Any] = {
        "tool": "sel-event-sweep", "ok": True, "skipped": None, "run_id": None,
        "devices_attempted": 0, "devices_succeeded": 0, "devices_ok": 0,
        "stopped_early": False, "gaps": [], "errors": [], "uploaded": None, "notified": False,
    }
    with sweep_lock(state_path) as acquired:
        if not acquired:
            summary["skipped"] = "sweep_already_running"
            return summary
        conn = open_state(state_path)
        try:
            state = SweepState(conn)
            reason = None
            if not deps.network_up():
                reason = "network_unreachable"
            elif not deps.aws_ok():
                reason = "aws_session_invalid"
            if reason is not None:
                summary["skipped"] = reason
                if _stale(state, settings, now):
                    deps.notify(
                        "No SEL event sweep has succeeded in {0}+ days. Restore access to the device network"
                        " and AWS credentials, then run sel-event-sweep.".format(settings.stale_notify_days)
                    )
                    summary["notified"] = True
                return summary
            items = order_items(fleet_items(config, site, name), state)
            if not items:
                summary["skipped"] = "no_devices"
                return summary
            run_id = records.new_run_id(now)
            results, stopped = _sweep_items(items, state, settings, deps)
            summary["uploaded"] = commit_run(deps.archive, settings.prefix, run_id, results)
            _record_results(state, results, settings, run_id, records.iso_utc(deps.clock()))
            summary.update(
                run_id=run_id,
                devices_attempted=len(results),
                devices_succeeded=sum(1 for r in results if r.success),
                devices_ok=sum(1 for r in results if r.run_row["ok"]),
                stopped_early=stopped,
                gaps=[r.item.device_key for r in results if r.run_row["ser_gap"] or r.run_row["his_gap"]],
                errors=[
                    {"device_key": r.item.device_key, "category": r.run_row["error_category"]}
                    for r in results
                    if r.run_row["error_category"]
                ],
            )
            return summary
        finally:
            conn.close()
