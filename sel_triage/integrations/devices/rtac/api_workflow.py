"""RTAC REST API snapshot: one token, read-only GETs, findings.

Each step is independent: a 403 (the account lacks that area's permission)
is recorded as an error for that step and the rest still run. A rejected
token request stops the snapshot and is never retried.
"""

import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from sel_triage.core.errors import TriageError
from sel_triage.core.evidence import EvidenceStore
from sel_triage.core.inventory import DeviceTarget
from sel_triage.core.output import build_sel_envelope

from . import api_parsers
from .api import RtacApiClient
from .diagnostics import diagnose_rtac_api

_PROVENANCE = {"source": "rtac-rest-api", "access": "read-only"}
# single-response reads, stored as returned
_READS = ("id", "status", "fingerprint", "connections", "system_settings", "projects", "symbol_groups")
# errors after which no further request is useful
_FATAL = ("route_or_tcp", "token_rejected")
MAX_TAGS = 2000
MAX_HISTORY_TAGS = 50


def _default_client(target: DeviceTarget) -> RtacApiClient:
    return RtacApiClient(target.host, target.port, timeout_seconds=float(target.timeout_seconds))


def _error(exc: Exception, capability: Optional[str] = None) -> Dict[str, Any]:
    if isinstance(exc, TriageError):
        error = exc.as_dict()
    else:
        error = {"category": "unexpected", "message": "RTAC API snapshot step failed", "reachable": None}
    if capability is not None:
        error["capability"] = capability
    return error


class _Evidence:
    def __init__(self, root: Path, run_id: str, name: str, result: Dict[str, Any]) -> None:
        self.result = result
        self.redactions: Sequence[str] = ()
        try:
            self.store: Optional[EvidenceStore] = EvidenceStore(root, run_id, name)
        except Exception:
            self.store = None
            result["errors"].append({"category": "evidence_write_failed",
                                     "message": "Evidence directory could not be created", "reachable": None})

    def write(self, kind: str, text: str, extension: str = "json", media_type: str = "application/json") -> None:
        if self.store is None:
            return
        for value in self.redactions:
            text = text.replace(value, "[REDACTED]")
        try:
            self.result["evidence"].append(self.store.write_bytes(kind, text.encode("utf-8"), extension,
                                                                  media_type).as_dict())
        except Exception:
            self.result["errors"].append({"category": "evidence_write_failed", "message": "Evidence could not be "
                                          "written", "reachable": self.result["reachable"], "capability": kind})

    def close(self, root: Path) -> None:
        if self.store is None:
            return
        try:
            self.result["manifest"] = self.store.write_manifest().relative_to(root).as_posix()
        except Exception:
            self.result["errors"].append({"category": "evidence_write_failed",
                                          "message": "Evidence manifest could not be written",
                                          "reachable": self.result["reachable"]})
        finally:
            self.store.close()


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _read_tags(client, filters: Sequence[str], evidence: _Evidence, result: Dict[str, Any], read_at: str) -> None:
    symbols: List[Dict[str, Any]] = []
    for pattern in filters:
        try:
            found = client.get("symbols", {"filter": pattern, "sort": "asc"})
        except TriageError as exc:
            result["errors"].append(_error(exc, "symbols"))
            continue
        if isinstance(found, list):
            symbols.extend(s for s in found if isinstance(s, dict) and isinstance(s.get("Name"), str))
    if not symbols:
        return
    unique: List[Dict[str, Any]] = []
    seen = set()
    for symbol in symbols:
        if symbol["Name"] not in seen:
            seen.add(symbol["Name"])
            unique.append(symbol)
    evidence.write("symbols", _dump(unique))
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["read_utc", "name", "type", "status", "value"])
    values = []
    for symbol in unique[:MAX_TAGS]:
        name = symbol["Name"]
        try:
            value = client.get("symbol", symbol=name)
            writer.writerow([read_at, name, symbol.get("Type"), "ok", json.dumps(value, sort_keys=True)])
            values.append({"name": name, "type": symbol.get("Type"), "value": value})
        except TriageError as exc:
            writer.writerow([read_at, name, symbol.get("Type"), exc.category, ""])
            if exc.category in _FATAL:
                result["errors"].append(_error(exc, "symbol"))
                break
    evidence.write("tag-values", out.getvalue(), "csv", "text/csv")
    result["snapshot"]["tags"] = {"filters": list(filters), "count": len(unique), "read": len(values),
                                  "truncated": len(unique) > MAX_TAGS, "values": values}


def _alarm_history(client, alarms: List[Dict[str, Any]], hours: float, ran_at: datetime,
                   evidence: _Evidence, result: Dict[str, Any]) -> None:
    since = (ran_at - timedelta(hours=hours)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tags = sorted({a["tag"] for a in alarms})[:MAX_HISTORY_TAGS]
    events: List[Dict[str, Any]] = []
    raw: Dict[str, Any] = {}
    for tag in tags:
        try:
            page = client.get_all("alarm_history", {"filter": "Timestamp=ge={0}".format(since)}, tag=tag)
        except TriageError as exc:
            result["errors"].append(_error(exc, "alarm_history"))
            if exc.category == "permission_denied" or exc.category in _FATAL:
                break
            continue
        raw[tag] = page["items"]
        events.extend(api_parsers.parse_alarm_history(page["items"]))
    if raw:
        evidence.write("alarm-history", _dump(raw))
        result["snapshot"]["alarm_history"] = {
            "since": since, "tags": len(raw), "tags_skipped": max(0, len({a["tag"] for a in alarms}) - len(tags)),
            "events": sorted(events, key=lambda e: str(e["timestamp"] or "")),
        }


def _collect_one(target, login_reader, credential_service, root, run_id, client_factory, ran_at, thresholds,
                 tag_filters, alarm_history_hours) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "name": target.name, "kind": target.kind, "reachable": None, "ok": False, "partial": False,
        "identity": {}, "snapshot": {}, "diagnostics": [], "warnings": [], "errors": [], "evidence": [],
    }
    evidence = _Evidence(root, run_id, target.name, result)
    client = None
    try:
        username, password = login_reader(credential_service or target.credential_ref)
        client = client_factory(target)
        try:
            token = client.login(username, password)
        finally:
            password = None
        result["reachable"] = True
        evidence.redactions = tuple(client.redactions)
        evidence.write("token-scope", _dump(token))
        result["snapshot"]["token"] = {k: token.get(k) for k in ("TokenType", "ExpiresIn", "Scope")}

        raw: Dict[str, Any] = {}
        for name in _READS:
            try:
                raw[name] = client.get(name)
            except TriageError as exc:
                if exc.category in _FATAL:
                    raise
                result["errors"].append(_error(exc, name))
                continue
            evidence.write(name.replace("_", "-"), _dump(raw[name]))
        alarms: Optional[List[Dict[str, Any]]] = None
        try:
            page = client.get_all("alarms")
            evidence.write("alarms", _dump(page["items"]))
            alarms = api_parsers.parse_alarms(page["items"])
            result["snapshot"]["alarms"] = {"total": page["total"], "truncated": page["truncated"],
                                            "active": api_parsers.active_alarms(alarms)}
        except TriageError as exc:
            result["errors"].append(_error(exc, "alarms"))

        if "id" in raw:
            result["identity"] = api_parsers.parse_id(raw["id"])
        if isinstance(raw.get("fingerprint"), str):
            result["identity"]["fingerprint"] = raw["fingerprint"]
        status = api_parsers.parse_status(raw["status"]) if "status" in raw else None
        if status is not None:
            result["snapshot"]["status"] = status
        connections = api_parsers.parse_connections(raw["connections"]) if "connections" in raw else None
        if connections is not None:
            result["snapshot"]["connections"] = connections
        if isinstance(raw.get("system_settings"), dict):
            result["snapshot"]["system_settings"] = raw["system_settings"]

        if alarm_history_hours and alarms:
            _alarm_history(client, alarms, alarm_history_hours, ran_at, evidence, result)
        if tag_filters:
            _read_tags(client, tag_filters, evidence, result, ran_at.strftime("%Y-%m-%dT%H:%M:%SZ"))
        result["diagnostics"] = diagnose_rtac_api(status, alarms, connections, ran_at, thresholds)
    except Exception as exc:
        result["errors"].append(_error(exc))
        if isinstance(exc, TriageError) and exc.reachable is not None:
            result["reachable"] = exc.reachable
    finally:
        if client is not None:
            client.logout()
        evidence.close(root)
    result["ok"] = result["reachable"] is True and not result["errors"]
    result["partial"] = result["reachable"] is True and bool(result["errors"]) and bool(result["snapshot"])
    return result


def run_rtac_api_snapshot(
    target: DeviceTarget,
    login_reader: Callable[[str], Any],
    evidence_root: Path,
    client_factory: Callable[[DeviceTarget], Any] = _default_client,
    now: Any = None,
    thresholds: Optional[Mapping[str, Any]] = None,
    tag_filters: Sequence[str] = (),
    alarm_history_hours: Optional[float] = None,
    credential_service: Optional[str] = None,
) -> Dict[str, Any]:
    ran_at = now() if callable(now) else now
    if ran_at is None:
        ran_at = datetime.now(timezone.utc)
    if ran_at.tzinfo is None:
        ran_at = ran_at.replace(tzinfo=timezone.utc)
    run_id = "{0}-{1}".format(ran_at.strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex[:12])
    result = _collect_one(target, login_reader, credential_service, Path(evidence_root), run_id, client_factory,
                          ran_at, thresholds, tuple(tag_filters), alarm_history_hours)
    return build_sel_envelope("rtac-api-snapshot", ran_at.strftime("%Y-%m-%dT%H:%M:%SZ"), [result], [], _PROVENANCE)


__all__ = ["MAX_TAGS", "run_rtac_api_snapshot"]
