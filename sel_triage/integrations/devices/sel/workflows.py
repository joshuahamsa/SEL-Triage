"""Bounded, read-only SEL collection workflows."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import uuid
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from sel_triage.core.errors import TriageError
from sel_triage.core.evidence import EvidenceStore, default_evidence_root
from sel_triage.core.inventory import DeviceTarget
from sel_triage.core.output import build_sel_envelope
from sel_triage.core.redaction import SecretFingerprintRedactor
from sel_triage.transports.telnet import TelnetTransport

from .adapters import adapter_for
from .adapters.base import EventSelector
from .client import SelClient
from .commands import COMMANDS_BY_FAMILY
from .diagnostics import diagnose_snapshot


SNAPSHOT_CAPABILITIES = ("status", "meter", "breaker", "target", "history")
# Opt-in: settings add several long reads to the fast snapshot.
SETTINGS_CAPABILITIES = (
    "settings_global",
    "settings_group",
    "settings_logic",
    "settings_report",
)
ABSOLUTE_EVENT_LIMIT = 10
_DEVICE_PROVENANCE = {
    "source": "sel-device",
    "transport_security": "plaintext",
    "access_level": 1,
    "read_only": True,
}


def _utc_now(now: Any) -> datetime:
    value = now() if callable(now) else now
    if value is None:
        value = datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise ValueError("now must be a datetime or callable returning one")
    if value.tzinfo is None:
        raise ValueError("now must include timezone information")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id(value: datetime) -> str:
    return "{0}-{1}".format(
        value.strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex[:12]
    )


def _default_client_factory(target: DeviceTarget) -> SelClient:
    transport = TelnetTransport(
        target.host,
        target.port,
        connect_timeout=target.timeout_seconds,
        read_timeout=target.timeout_seconds,
    )
    return SelClient(transport)


def _target_result(target: DeviceTarget) -> Dict[str, Any]:
    return {
        "name": target.name,
        "ok": False,
        "partial": False,
        "reachable": None,
        "transport_security": "plaintext",
        "model_hint": target.model_hint,
        "identity": None,
        "snapshot": {},
        "completed_capabilities": [],
        "unavailable_capabilities": [],
        "diagnostics": [],
        "warnings": [],
        "errors": [],
        "evidence": [],
        "manifest": None,
        "provenance": dict(_DEVICE_PROVENANCE),
    }


def _error(exc: Exception, capability: Optional[str] = None) -> Dict[str, Any]:
    if isinstance(exc, TriageError):
        result = exc.as_dict()
    elif isinstance(exc, ValueError) and "unsupported observed SEL model" in str(exc):
        result = {
            "category": "unsupported_model",
            "message": str(exc),
            "reachable": True,
        }
    else:
        result = {
            "category": "unexpected",
            "message": "Unexpected snapshot failure",
            "reachable": None,
        }
    if capability is not None:
        result["capability"] = capability
    return result


def _command_unavailable(capability: str, family: str) -> Dict[str, Any]:
    return {
        "category": "command_unavailable",
        "message": "Snapshot capability unavailable for SEL family {0}".format(
            family
        ),
        "reachable": True,
        "capability": capability,
    }


def _append_once(values: List[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _client_capabilities(client: Any, family: str) -> Sequence[str]:
    client_family = getattr(client, "family", family)
    policy = tuple(COMMANDS_BY_FAMILY.get(client_family, {}))
    declared = getattr(client, "capabilities", None)
    if isinstance(declared, (tuple, list, set, frozenset)):
        declared_set = {
            value for value in declared if isinstance(value, str)
        }
        return tuple(value for value in policy if value in declared_set)
    return policy


def _write_evidence(
    store: Optional[EvidenceStore],
    result: Dict[str, Any],
    capability: str,
    raw_text: str,
) -> None:
    if store is None:
        return
    try:
        reference = store.write_text(capability, raw_text)
        result["evidence"].append(reference.as_dict())
    except Exception:
        result["errors"].append(
            {
                "category": "evidence_write_failed",
                "message": "Evidence could not be written",
                "reachable": result["reachable"],
                "capability": capability,
            }
        )


def _identity_dict(
    adapter: Any, identity: Any, raw_text: str
) -> Dict[str, Any]:
    parsed = adapter.parse("identity", raw_text)
    if "observed_model" not in parsed:
        parsed["observed_model"] = getattr(identity, "observed_model", None)
    if "device_id" not in parsed and getattr(identity, "device_id", None) is not None:
        parsed["device_id"] = identity.device_id
    return parsed


def _collect_one(
    target: DeviceTarget,
    secret_provider: Any,
    evidence_root: Path,
    run_id: str,
    client_factory: Callable[[DeviceTarget], Any],
    now: datetime,
    thresholds: Optional[Mapping[str, Any]],
    include_settings: bool = False,
) -> Dict[str, Any]:
    result = _target_result(target)
    client = None
    secret: Optional[str] = None
    redactor: Optional[SecretFingerprintRedactor] = None
    store: Optional[EvidenceStore] = None

    try:
        try:
            store = EvidenceStore(evidence_root, run_id, target.name)
        except Exception:
            result["errors"].append(
                {
                    "category": "evidence_write_failed",
                    "message": "Evidence directory could not be created",
                    "reachable": None,
                }
            )

        client = client_factory(target)
        secret = secret_provider.get(target.credential_ref)
        try:
            identity = client.login(secret)
            redactor = SecretFingerprintRedactor(secret)
        finally:
            secret = None
        result["reachable"] = True

        raw_identity = redactor.redact(getattr(identity, "raw_text", ""))
        _write_evidence(store, result, "identity", raw_identity)
        result["identity"] = {
            "observed_model": identity.observed_model,
            "device_id": getattr(identity, "device_id", None),
        }

        selection = adapter_for(identity.observed_model, target.model_hint)
        adapter = selection.adapter
        if selection.warning is not None:
            result["warnings"].append(dict(selection.warning))
        result["identity"] = _identity_dict(adapter, identity, raw_identity)

        adapter_capabilities = set(adapter.capabilities)
        executable_capabilities = set(
            _client_capabilities(client, adapter.family)
        )
        selected = [
            capability
            for capability in SNAPSHOT_CAPABILITIES
            if capability in adapter_capabilities
            and capability in executable_capabilities
        ]
        if include_settings:
            for capability in SETTINGS_CAPABILITIES:
                if (
                    capability in adapter_capabilities
                    and capability in executable_capabilities
                ):
                    selected.append(capability)
                else:
                    _append_once(result["unavailable_capabilities"], capability)
                    result["warnings"].append(
                        {
                            "code": "settings_unavailable",
                            "capability": capability,
                            "message": (
                                "Settings retrieval is not supported for the "
                                "{0} family"
                            ).format(adapter.family),
                        }
                    )
        not_applicable = set(getattr(adapter, "not_applicable", ()))
        for capability in SNAPSHOT_CAPABILITIES:
            if capability in selected or capability in not_applicable:
                continue
            _append_once(result["unavailable_capabilities"], capability)
            result["errors"].append(
                _command_unavailable(capability, adapter.family)
            )

        for position, capability in enumerate(selected):
            try:
                raw_text = client.run(capability)
            except TriageError as exc:
                result["errors"].append(_error(exc, capability))
                if exc.category == "command_unavailable":
                    _append_once(result["unavailable_capabilities"], capability)
                    continue
                for remaining in selected[position:]:
                    _append_once(result["unavailable_capabilities"], remaining)
                break
            except Exception as exc:
                result["errors"].append(_error(exc, capability))
                for remaining in selected[position:]:
                    _append_once(result["unavailable_capabilities"], remaining)
                break

            raw_text = redactor.redact(raw_text)
            _write_evidence(store, result, capability, raw_text)
            try:
                normalized = adapter.parse(capability, raw_text)
            except Exception:
                result["errors"].append(
                    {
                        "category": "parse_warning",
                        "message": "Capability response could not be normalized",
                        "reachable": True,
                        "capability": capability,
                    }
                )
                _append_once(result["unavailable_capabilities"], capability)
                continue
            result["snapshot"][capability] = normalized
            result["completed_capabilities"].append(capability)
    except Exception as exc:
        error = _error(exc)
        result["errors"].append(error)
        if isinstance(exc, TriageError):
            result["reachable"] = exc.reachable
        elif result["reachable"] is None:
            result["reachable"] = error.get("reachable")
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                result["errors"].append(
                    {
                        "category": "logout_failed",
                        "message": "The SEL session did not close cleanly",
                        "reachable": result["reachable"],
                    }
                )
        if store is not None:
            try:
                manifest = store.write_manifest()
                result["manifest"] = manifest.relative_to(evidence_root).as_posix()
            except Exception:
                result["errors"].append(
                    {
                        "category": "evidence_write_failed",
                        "message": "Evidence manifest could not be written",
                        "reachable": result["reachable"],
                    }
                )
            finally:
                store.close()
        secret = None
        redactor = None

    diagnostic_input = dict(result)
    diagnostic_input["observed_model"] = (
        result["identity"].get("observed_model")
        if isinstance(result["identity"], Mapping)
        else None
    )
    result["diagnostics"] = diagnose_snapshot(
        diagnostic_input, now=now, thresholds=thresholds
    )
    has_result = bool(
        result["identity"]
        or result["snapshot"]
        or result["completed_capabilities"]
        or result["evidence"]
    )
    result["ok"] = (
        result["reachable"] is True
        and result["identity"] is not None
        and not result["errors"]
    )
    result["partial"] = not result["ok"] and has_result
    return result


def run_snapshot(
    targets: Iterable[DeviceTarget],
    secret_provider: Any,
    evidence_root: Path,
    client_factory: Callable[[DeviceTarget], Any] = _default_client_factory,
    now: Any = None,
    thresholds: Optional[Mapping[str, Any]] = None,
    include_settings: bool = False,
) -> Dict[str, Any]:
    """Collect a fixed fast snapshot independently for each SEL target.

    ``include_settings`` also reads the relay's settings (SHO) where the
    family supports it.
    """

    ran_at = _utc_now(now)
    root = Path(evidence_root)
    run_id = _run_id(ran_at)
    results = [
        _collect_one(
            target,
            secret_provider,
            root,
            run_id,
            client_factory,
            ran_at,
            thresholds,
            include_settings,
        )
        for target in targets
    ]
    return build_sel_envelope(
        "sel-snapshot",
        _iso(ran_at),
        results,
        [],
        _DEVICE_PROVENANCE,
    )


_SER_ROW = re.compile(br"^\s*\d+\s+")


def _positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("{0} must be a positive integer".format(field))
    return value


def _payload_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\x02", "").replace("\x03", "")


def _bounded_ser(data: bytes, limit: int) -> tuple:
    """Keep the SER heading, newest data rows, and terminal prompt."""

    lines = data.splitlines(keepends=True)
    row_indexes = [
        index for index, line in enumerate(lines) if _SER_ROW.match(line)
    ]
    available = len(row_indexes)
    if available <= limit:
        return data, available, available, False

    first = row_indexes[0]
    last = row_indexes[-1]
    selected = [lines[index] for index in row_indexes[-limit:]]
    trailers = [
        line for line in lines[last + 1 :] if line.strip() == b"=>"
    ]
    bounded = b"".join(lines[:first] + selected + trailers)
    return bounded, limit, available, True


def _artifact(
    reference: Any,
    kind: str,
    event_format: str,
    capability: str,
    argument: Optional[int],
    retrieved_at: str,
) -> Dict[str, Any]:
    result = reference.as_dict()
    result.update(
        {
            "kind": kind,
            "format": event_format,
            "recipe": {
                "capability": capability,
                "argument": argument,
            },
            "retrieved_at": retrieved_at,
        }
    )
    return result


def _event_target_result(
    target: DeviceTarget,
    selected: EventSelector,
    maximum: int,
    ser_row_limit: int,
) -> Dict[str, Any]:
    return {
        "name": target.name,
        "ok": False,
        "partial": False,
        "reachable": None,
        "model_hint": target.model_hint,
        "transport_security": "plaintext",
        "source_identity": None,
        "selection": {
            "mode": selected.mode,
            "count": selected.count,
            "event_number": selected.event_number,
            "event_format": selected.event_format,
            "event_reports": None,
            "hard_event_limit": maximum,
            "absolute_event_limit": ABSOLUTE_EVENT_LIMIT,
        },
        "ser": {
            "limit": ser_row_limit,
            "rows_returned": 0,
            "rows_available": 0,
            "truncated": False,
        },
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "manifest": None,
        "provenance": dict(_DEVICE_PROVENANCE),
    }


def _event_error(
    exc: Exception,
    stage: str,
    capability: Optional[str] = None,
    argument: Optional[int] = None,
) -> Dict[str, Any]:
    if isinstance(exc, TriageError):
        result = exc.as_dict()
    elif isinstance(exc, ValueError) and "unsupported observed SEL model" in str(exc):
        result = {
            "category": "unsupported_model",
            "message": str(exc),
            "reachable": True,
        }
    elif isinstance(exc, ValueError) and "command_unavailable" in str(exc):
        result = {
            "category": "command_unavailable",
            "message": str(exc),
            "reachable": True,
        }
    else:
        result = {
            "category": "event_collection_failed",
            "message": "Unexpected SEL event collection failure",
            "reachable": None,
        }
    result["stage"] = stage
    if capability is not None:
        result["capability"] = capability
    if argument is not None:
        result["argument"] = argument
    return result


def _finalize_event_result(
    target_result: Dict[str, Any], ran_at_text: str
) -> Dict[str, Any]:
    selection = target_result["selection"]
    if selection.get("event_reports") is False:
        requested = 2  # HIS and SER
    else:
        requested = selection["count"] + 1
    target_result["ok"] = (
        target_result["reachable"] is True
        and target_result["source_identity"] is not None
        and len(target_result["artifacts"]) == requested
        and not target_result["errors"]
    )
    target_result["partial"] = not target_result["ok"] and bool(
        target_result["source_identity"] or target_result["artifacts"]
    )
    return build_sel_envelope(
        "sel-collect-events",
        ran_at_text,
        [target_result],
        [],
        _DEVICE_PROVENANCE,
    )


def event_failure_result(
    target: DeviceTarget, ran_at_text: str, exc: Exception
) -> Dict[str, Any]:
    """Return a safe failed collection envelope for an orchestration boundary."""

    selected = EventSelector.latest()
    target_result = _event_target_result(
        target, selected, ABSOLUTE_EVENT_LIMIT, 500
    )
    target_result["errors"].append(_event_error(exc, "orchestration"))
    return _finalize_event_result(target_result, ran_at_text)


def collect_events(
    target: DeviceTarget,
    selector: Optional[EventSelector] = None,
    ser_limit: int = 500,
    hard_event_limit: int = 10,
    secret_provider: Any = None,
    client_factory: Callable[[DeviceTarget], Any] = _default_client_factory,
    evidence_root: Optional[Path] = None,
    now: Any = None,
) -> Dict[str, Any]:
    """Collect capture-backed SEL event reports and a locally bounded SER.

    Families without an event report recipe (``adapter.ser_only_events``)
    return HIS and SER instead, with an ``event_reports_unavailable`` warning.
    """

    selected = EventSelector.latest() if selector is None else selector
    if not isinstance(selected, EventSelector):
        raise ValueError("selector must be an EventSelector")
    maximum = _positive_integer(hard_event_limit, "hard event limit")
    ser_row_limit = _positive_integer(ser_limit, "SER limit")
    if maximum > ABSOLUTE_EVENT_LIMIT:
        raise ValueError(
            "hard event limit exceeds the absolute maximum of {0}".format(
                ABSOLUTE_EVENT_LIMIT
            )
        )
    if selected.count > maximum:
        raise ValueError(
            "requested event count exceeds the configured hard maximum of {0}".format(
                maximum
            )
        )
    if selected.count > ABSOLUTE_EVENT_LIMIT:
        raise ValueError(
            "requested event count exceeds the absolute maximum of {0}".format(
                ABSOLUTE_EVENT_LIMIT
            )
        )
    if secret_provider is None or not callable(getattr(secret_provider, "get", None)):
        raise ValueError("secret provider must provide get()")
    if not callable(client_factory):
        raise ValueError("client factory must be callable")

    ran_at = _utc_now(now)
    ran_at_text = _iso(ran_at)
    root = default_evidence_root() if evidence_root is None else Path(evidence_root)
    store: Optional[EvidenceStore] = None
    client = None
    secret: Optional[str] = None
    result = _event_target_result(target, selected, maximum, ser_row_limit)
    stage = "evidence_setup"
    capability: Optional[str] = None
    argument: Optional[int] = None

    try:
        store = EvidenceStore(root, _run_id(ran_at), target.name)
        stage = "client_setup"
        client = client_factory(target)
        stage = "secret_lookup"
        secret = secret_provider.get(target.credential_ref)
        stage = "authentication"
        try:
            identity = client.login(secret)
        finally:
            secret = None
        result["reachable"] = True
        result["source_identity"] = {
            "observed_model": identity.observed_model,
            "device_id": getattr(identity, "device_id", None),
        }
        stage = "adapter_selection"
        selection = adapter_for(identity.observed_model, target.model_hint)
        adapter = selection.adapter
        if selection.warning is not None:
            result["warnings"].append(dict(selection.warning))

        requests = adapter.event_requests(selected)
        ser_only = adapter.ser_only_events
        result["selection"]["event_reports"] = not ser_only
        executable = set(_client_capabilities(client, adapter.family))
        required = {"history", "ser"} if ser_only else {selected.event_format, "ser"}
        unavailable = sorted(required.difference(executable))
        if unavailable:
            raise ValueError(
                "command_unavailable for {0} family: {1}".format(
                    adapter.family, ", ".join(unavailable)
                )
            )

        if ser_only:
            result["warnings"].append(
                {
                    "code": "event_reports_unavailable",
                    "message": (
                        "{0} has no event report recipe yet; collected HIS and "
                        "SER only"
                    ).format(identity.observed_model),
                }
            )
            stage = "history_retrieval"
            capability = "history"
            argument = None
            history_payload = client.run_bytes("history")
            stage = "history_evidence"
            history_reference = store.write_bytes(
                "history",
                history_payload,
                extension="his",
                media_type="text/plain; charset=utf-8",
            )
            result["artifacts"].append(
                _artifact(
                    history_reference,
                    "history",
                    "his",
                    "history",
                    None,
                    ran_at_text,
                )
            )
            stage = "history_parse"
            parsed_history = adapter.parse("history", _payload_text(history_payload))
            result["history"] = {"events": parsed_history.get("events", [])}

        for position, request in enumerate(requests, start=1):
            stage = "event_retrieval"
            capability = request.capability
            argument = request.argument
            payload = client.run_bytes(request.capability, request.argument)
            stage = "event_evidence"
            reference = store.write_bytes(
                "event-{0}".format(position),
                payload,
                extension=request.extension,
            )
            result["artifacts"].append(
                _artifact(
                    reference,
                    "event",
                    request.event_format,
                    request.capability,
                    request.argument,
                    ran_at_text,
                )
            )

        stage = "ser_retrieval"
        capability = "ser"
        argument = None
        ser_payload = client.run_bytes("ser")
        bounded_ser, returned, available, truncated = _bounded_ser(
            ser_payload, ser_row_limit
        )
        result["ser"].update(
            {
                "rows_returned": returned,
                "rows_available": available,
                "truncated": truncated,
            }
        )
        try:
            parsed_ser = adapter.parse("ser", _payload_text(bounded_ser))
        except ValueError:
            parsed_ser = None  # this family has no SER parser yet
        if parsed_ser is not None:
            result["ser"]["records"] = parsed_ser.get("records", [])
            result["ser"]["element_summary"] = parsed_ser.get("element_summary", {})
        stage = "ser_evidence"
        ser_reference = store.write_bytes(
            "ser",
            bounded_ser,
            extension="ser",
            media_type="text/plain; charset=utf-8",
        )
        result["artifacts"].append(
            _artifact(
                ser_reference,
                "ser",
                "ser",
                "ser",
                None,
                ran_at_text,
            )
        )
    except Exception as exc:
        error = _event_error(exc, stage, capability, argument)
        result["errors"].append(error)
        if isinstance(exc, TriageError):
            result["reachable"] = exc.reachable
        elif result["reachable"] is None:
            result["reachable"] = error.get("reachable")
    finally:
        secret = None
        if client is not None:
            try:
                client.logout()
            except Exception:
                result["errors"].append(
                    {
                        "category": "logout_failed",
                        "message": "The SEL event session did not close cleanly",
                        "reachable": result["reachable"],
                        "stage": "logout",
                    }
                )
        if store is not None:
            try:
                result["manifest"] = (
                    store.write_manifest().relative_to(root).as_posix()
                )
            except Exception:
                result["errors"].append(
                    {
                        "category": "evidence_write_failed",
                        "message": "Event evidence manifest could not be written",
                        "reachable": result["reachable"],
                        "stage": "manifest",
                    }
                )
            finally:
                store.close()

    return _finalize_event_result(result, ran_at_text)


__all__ = [
    "ABSOLUTE_EVENT_LIMIT",
    "EventSelector",
    "SETTINGS_CAPABILITIES",
    "SNAPSHOT_CAPABILITIES",
    "collect_events",
    "event_failure_result",
    "run_snapshot",
]
