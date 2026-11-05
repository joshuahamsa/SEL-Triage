"""RTAC web snapshot: log in once, fetch the read-only reports, log out."""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from sel_triage.core.errors import TriageError
from sel_triage.core.evidence import EvidenceStore
from sel_triage.core.inventory import DeviceTarget
from sel_triage.core.output import build_sel_envelope

from . import parsers
from .diagnostics import diagnose_rtac
from .web import RtacWebClient

# (endpoint, evidence extension, media type)
_COLLECT = (
    ("soe", "csv", "text/csv"),
    ("alarms", "csv", "text/csv"),
    ("diagnostics", "txt", "text/plain; charset=utf-8"),
    ("ethernet_ieds", "html", "text/html; charset=utf-8"),
    ("serial_ieds", "html", "text/html; charset=utf-8"),
)
_PROVENANCE = {"source": "rtac-web", "access": "read-only"}


def _default_client(target: DeviceTarget) -> RtacWebClient:
    return RtacWebClient(target.host, target.port, timeout_seconds=float(target.timeout_seconds))


def _error(exc: Exception, capability: Optional[str] = None) -> Dict[str, Any]:
    if isinstance(exc, TriageError):
        error = exc.as_dict()
    else:
        error = {"category": "unexpected", "message": "RTAC snapshot step failed", "reachable": None}
    if capability is not None:
        error["capability"] = capability
    return error


def _store(store: Optional[EvidenceStore], result: Dict[str, Any], kind: str, text: str,
           extension: str, media_type: str, redactions) -> None:
    if store is None:
        return
    for value in redactions:
        text = text.replace(value, "[REDACTED]")
    try:
        result["evidence"].append(store.write_bytes(kind, text.encode("utf-8"), extension, media_type).as_dict())
    except Exception:
        result["errors"].append({"category": "evidence_write_failed", "message": "Evidence could not be written",
                                 "reachable": result["reachable"], "capability": kind})


def _collect_one(target, login_reader, root, run_id, client_factory, ran_at, thresholds) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "name": target.name, "kind": target.kind, "reachable": None, "ok": False, "partial": False,
        "identity": {}, "snapshot": {}, "diagnostics": [], "warnings": [], "errors": [], "evidence": [],
    }
    store = None
    client = None
    try:
        store = EvidenceStore(root, run_id, target.name)
    except Exception:
        result["errors"].append({"category": "evidence_write_failed",
                                 "message": "Evidence directory could not be created", "reachable": None})
    try:
        username, password = login_reader(target.credential_ref)
        client = client_factory(target)
        try:
            home = client.login(username, password)
        finally:
            password = None
        result["reachable"] = True
        redactions = tuple(client.redactions)
        _store(store, result, "home", home, "html", "text/html; charset=utf-8", redactions)
        result["identity"] = parsers.parse_home(home)
        raw: Dict[str, str] = {}
        for name, extension, media_type in _COLLECT:
            try:
                raw[name] = client.fetch(name)
            except TriageError as exc:
                result["errors"].append(_error(exc, name))
                continue
            _store(store, result, name, raw[name], extension, media_type, redactions)
        events = parsers.parse_soe(raw.get("soe", ""))
        alarms = parsers.parse_soe(raw.get("alarms", ""))
        if "soe" in raw:
            result["snapshot"]["soe"] = parsers.summarize_soe(events)
        if "alarms" in raw:
            result["snapshot"]["alarms"] = alarms
        for name in ("ethernet_ieds", "serial_ieds"):
            if name in raw:
                result["snapshot"][name] = parsers.parse_ied_table(raw[name])
        result["diagnostics"] = diagnose_rtac(events, alarms, result["identity"], ran_at, thresholds)
    except Exception as exc:
        error = _error(exc)
        result["errors"].append(error)
        if isinstance(exc, TriageError) and exc.reachable is not None:
            result["reachable"] = exc.reachable
    finally:
        if client is not None:
            client.logout()
        if store is not None:
            try:
                result["manifest"] = store.write_manifest().relative_to(root).as_posix()
            except Exception:
                result["errors"].append({"category": "evidence_write_failed",
                                         "message": "Evidence manifest could not be written",
                                         "reachable": result["reachable"]})
            finally:
                store.close()
    result["ok"] = result["reachable"] is True and not result["errors"]
    result["partial"] = result["reachable"] is True and bool(result["errors"]) and bool(result["snapshot"])
    return result


def run_rtac_snapshot(
    target: DeviceTarget,
    login_reader: Callable[[str], Any],
    evidence_root: Path,
    client_factory: Callable[[DeviceTarget], Any] = _default_client,
    now: Any = None,
    thresholds: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    ran_at = now() if callable(now) else now
    if ran_at is None:
        ran_at = datetime.now(timezone.utc)
    if ran_at.tzinfo is None:
        ran_at = ran_at.replace(tzinfo=timezone.utc)
    run_id = "{0}-{1}".format(ran_at.strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex[:12])
    result = _collect_one(target, login_reader, Path(evidence_root), run_id, client_factory, ran_at, thresholds)
    return build_sel_envelope("rtac-snapshot", ran_at.strftime("%Y-%m-%dT%H:%M:%SZ"), [result], [], _PROVENANCE)


__all__ = ["run_rtac_snapshot"]
