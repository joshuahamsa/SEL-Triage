"""Sweep one SEL device: HIS, SER, then new event reports (raw and parsed)."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from ..core.errors import TriageError
from ..core.inventory import DeviceTarget
from ..integrations.devices.sel.adapters import adapter_for
from ..integrations.devices.sel.parsers import sel735
from ..integrations.devices.sel.parsers.common import nonempty_lines
from . import records
from .breaker import breaker_row, reads_breaker
from .event_reports import summarize
from .settings import ArchiveSettings
from .state import DevicePrior


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SweepItem:
    site: str
    target: DeviceTarget

    @property
    def device_key(self) -> str:
        return records.device_key(self.target.name)


@dataclass
class DeviceResult:
    item: SweepItem
    run_row: Dict[str, Any]
    raw: Dict[str, bytes] = field(default_factory=dict)
    ser_rows: List[Dict[str, Any]] = field(default_factory=list)
    history_rows: List[Dict[str, Any]] = field(default_factory=list)
    report_rows: List[Dict[str, Any]] = field(default_factory=list)
    # parsed per-event summaries; archive.commit_run adds the S3 key
    event_summaries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # BRE reading for breaker.jsonl (families with a breaker monitor)
    breaker: Optional[Dict[str, Any]] = None

    @property
    def success(self) -> bool:
        return self.run_row["reachable"] is True and "his.txt" in self.raw


def decode_payload(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace").replace("\x02", "").replace("\x03", "")


def parse_capability(adapter, capability: str, text: str, key: str) -> Tuple[Optional[List[Dict]], str]:
    try:
        parsed = adapter.parse(capability, text)
    except ValueError as exc:
        message = str(exc)
        if "unsupported capability" in message or "command_unavailable" in message:
            return None, "no_parser"
        return None, "parse_failed"
    except Exception:
        return None, "parse_failed"
    return list(parsed.get(key, [])), "parsed"


_DEVICE_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?$")


def valid_device_ts(value: Any) -> bool:
    """True for a real calendar ``YYYY-MM-DDTHH:MM:SS[.f]`` (rejects DMY/YMD mix-ups)."""

    match = _DEVICE_TS.match(value) if isinstance(value, str) else None
    if match is None:
        return False
    try:
        datetime(*(int(part) for part in match.groups()))
    except ValueError:
        return False
    return True


def shape_rows(items: List[Dict[str, Any]], shape: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Shape parsed items into rows, dropping any whose timestamp is not a real date."""

    rows = [shape(item) for item in items if valid_device_ts(item.get("timestamp"))]
    return rows, len(items) - len(rows)


def history_row(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "device_ts": event["timestamp"],
        "event_type": event["event_type"],
        "details": event.get("details", {}),
    }


def ser_row(record: Dict[str, Any]) -> Dict[str, Any]:
    return {"device_ts": record["timestamp"], "element": record["element"], "state": record["state"]}


def detect_gap(newest_stored: Optional[str], timestamps: List[str]) -> Optional[bool]:
    if newest_stored is None:
        return None
    if not timestamps:
        return False
    return min(timestamps) > newest_stored


def select_reports(
    events: List[Dict[str, Any]], archived: FrozenSet[Tuple[str, str]], limit: int,
    fmt: str = records.REPORT_FORMAT,
) -> Tuple[List[Dict[str, Any]], int]:
    pending = sorted(
        (e for e in events if (e["timestamp"], fmt) not in archived),
        key=lambda e: e["timestamp"],
    )
    return pending[:limit], len(pending)


def device_clock_offset(his_text: str, read_at: datetime) -> Optional[float]:
    clock = sel735._clock_fields(nonempty_lines(his_text), set()).get("clock")
    if clock is None:
        return None
    try:
        device = datetime.fromisoformat(clock)
    except ValueError:
        return None
    reference = read_at.astimezone(timezone.utc).replace(tzinfo=None)
    return round((device - reference).total_seconds(), 3)


def _base_row(item: SweepItem, started: datetime) -> Dict[str, Any]:
    return {
        "schema_version": records.SCHEMA_VERSION,
        "kind": "sweep",
        "device_key": item.device_key,
        "name": item.target.name,
        "site": item.site,
        "observed_model": None,
        "devid": None,
        "family": None,
        "parser_version": None,
        "started_at": records.iso_utc(started),
        "finished_at": None,
        "ok": False,
        "reachable": None,
        "error_category": None,
        "errors": [],
        "warnings": [],
        "clock_offset_s": None,
        "ser_rows": None,
        "his_rows": None,
        "ser_parse": None,
        "his_parse": None,
        "ser_gap": None,
        "his_gap": None,
        "reports_fetched": 0,
        "reports_pending": 0,
        "source_run_id": None,
    }


def _record_error(row: Dict[str, Any], exc: BaseException) -> None:
    if isinstance(exc, TriageError):
        category = exc.category
        if row["reachable"] is None and exc.reachable is not None:
            row["reachable"] = exc.reachable
    elif isinstance(exc, ValueError) and "unsupported observed SEL model" in str(exc):
        category = "unsupported_model"
    else:
        category = "sweep_failed"
    row["errors"].append(category)


def _newest(events: List[Dict[str, Any]]) -> Optional[str]:
    return max((e["timestamp"] for e in events), default=None)


_REJECTED = re.compile(rb"invalid command|\" unknown|command not found", re.IGNORECASE)


def _rejected(payload: bytes) -> bool:
    """A short reply that is only the device refusing the command (nothing to archive)."""

    return len(payload) < 400 and _REJECTED.search(payload) is not None


def _collect_reports(client, adapter, events, prior, settings, result) -> None:
    row = result.run_row
    fmt = records.report_format(row.get("observed_model"))
    capability = "cev" if fmt == "cev" else "eve"
    chosen, pending = select_reports(events, prior.archived, settings.events_per_run, fmt)
    fetched = []
    for event in chosen:
        try:
            payload = client.run_bytes(capability, event["event_number"])
        except TriageError as exc:
            # A timeout or oversize report closes the session; SER is already
            # archived, so record it and retry the reports next sweep.
            _record_error(row, exc)
            row["reports_pending"] = pending
            return
        if _rejected(payload):
            # the device does not know this report command: archive nothing, try again next sweep
            row["warnings"].append("report_command_rejected")
            break
        fetched.append((event, records.report_file_name(event["timestamp"], fmt), payload))
    if fetched:
        recheck, _ = parse_capability(
            adapter, "history", decode_payload(client.run_bytes("history")), "events"
        )
        if _newest(recheck or []) != _newest(events):
            row["warnings"].append("history_changed_during_sweep")
            fetched = []
    for event, name, payload in fetched:
        result.raw[name] = payload
        result.event_summaries[name] = summarize(payload, fmt)
        result.report_rows.append(
            {
                "device_ts": event["timestamp"],
                "format": fmt,
                "raw_name": name,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    row["reports_fetched"] = len(result.report_rows)
    row["reports_pending"] = pending - len(result.report_rows)


def _collect_ser(client, adapter, prior, result) -> bool:
    """Read SER; return False when the session was closed by the failure."""

    row = result.run_row
    try:
        payload = client.run_bytes("ser")
    except TriageError as exc:
        if exc.category not in ("command_unavailable", "response_too_large"):
            raise
        _record_error(row, exc)
        return exc.category == "command_unavailable"
    result.raw["ser.txt"] = payload
    parsed, status = parse_capability(adapter, "ser", decode_payload(payload), "records")
    row["ser_parse"] = status
    if status == "parse_failed":
        row["errors"].append("parse_failed")
    if parsed is not None:
        result.ser_rows, dropped = shape_rows(parsed, ser_row)
        if dropped and "invalid_device_ts" not in row["warnings"]:
            row["warnings"].append("invalid_device_ts")
        row["ser_rows"] = len(result.ser_rows)
        row["ser_gap"] = detect_gap(prior.newest_ser_ts, [r["device_ts"] for r in result.ser_rows])
    return True


def sweep_device(
    item: SweepItem,
    prior: DevicePrior,
    *,
    secret_provider: Any,
    client_factory: Callable[[DeviceTarget], Any],
    settings: ArchiveSettings,
    clock: Callable[[], datetime] = utc_now,
) -> DeviceResult:
    result = DeviceResult(item, _base_row(item, clock()))
    row = result.run_row
    client = None
    try:
        client = client_factory(item.target)
        secret = secret_provider.get(item.target.credential_ref)
        try:
            identity = client.login(secret)
        finally:
            secret = None
        row["reachable"] = True
        row["observed_model"] = identity.observed_model
        row["devid"] = getattr(identity, "device_id", None)
        adapter = adapter_for(identity.observed_model, item.target.model_hint).adapter
        row["family"] = adapter.family
        row["parser_version"] = records.PARSER_VERSIONS.get(adapter.family)

        his_payload = client.run_bytes("history")
        read_at = clock()
        result.raw["his.txt"] = his_payload
        his_text = decode_payload(his_payload)
        row["clock_offset_s"] = device_clock_offset(his_text, read_at)
        events, status = parse_capability(adapter, "history", his_text, "events")
        row["his_parse"] = status
        if status == "parse_failed":
            row["errors"].append("parse_failed")
        if events is not None:
            result.history_rows, dropped = shape_rows(events, history_row)
            if dropped:
                row["warnings"].append("invalid_device_ts")
            events = [e for e in events if valid_device_ts(e.get("timestamp"))]
            row["his_rows"] = len(events)
            row["his_gap"] = detect_gap(prior.newest_his_ts, [e["timestamp"] for e in events])
        session_open = _collect_ser(client, adapter, prior, result)
        if (
            session_open
            and events
            and adapter.family in settings.event_report_families
        ):
            _collect_reports(client, adapter, events, prior, settings, result)
        # BRE last: a slow BRE that closes the session cannot cost HIS, SER or reports
        if reads_breaker(adapter.family) and getattr(client, "state", "ACCESS1") == "ACCESS1":
            bre_payload = client.run_bytes("breaker")
            result.raw["bre.txt"] = bre_payload
            result.breaker = breaker_row(adapter, decode_payload(bre_payload), records.iso_utc(clock()))
    except Exception as exc:
        _record_error(row, exc)
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                row["errors"].append("logout_failed")
    row["finished_at"] = records.iso_utc(clock())
    row["ok"] = result.success and not row["errors"]
    row["error_category"] = row["errors"][0] if row["errors"] else None
    return result
