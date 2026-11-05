"""Per-event summaries of archived SEL event reports (``EVE n``), for event_reports.jsonl.

Parsed with the vendored event-report package. A report that does not parse yields a row
with ``report_parse = "parse_failed"`` and the error, so one odd report never stops a sweep.
"""

from typing import Any, Dict

from ..integrations.devices.sel.eventreport.analysis import digital_transitions
from ..integrations.devices.sel.eventreport.cev_parser import parse_cev_text
from ..integrations.devices.sel.eventreport.eve_parser import EveParseError, parse_eve_bytes
from . import records


def summarize(payload: bytes, fmt: str = "eve") -> Dict[str, Any]:
    """Event identity, type, targets and reported fault currents from one EVE or CEV response."""

    try:
        if fmt == "cev":
            event = parse_cev_text(payload.decode("latin-1"), source_bytes=payload)
        else:
            event = parse_eve_bytes(payload)
    except (EveParseError, ValueError, IndexError, KeyError) as error:
        return {"report_parse": "parse_failed", "report_error": str(error)[:300]}
    meta = event.metadata
    try:
        transitions = len(digital_transitions(event))
    except (StopIteration, ValueError):
        transitions = None
    return {
        "report_parse": "parsed",
        "report_error": None,
        "event_number": meta.event_number,
        "event_time": meta.timestamp,
        "time_source": meta.time_source,
        "event_type": meta.event_type or None,
        # SEL prints $$$$$$$ when it could not compute a fault location
        "location": None if not meta.location or set(meta.location) == {"$"} else meta.location,
        "shot": meta.shot,
        "targets": list(meta.targets),
        "fid": meta.firmware_id,
        "reported_currents": dict(event.reported_currents),
        "nominal_frequency_hz": event.nominal_frequency_hz,
        "samples_per_cycle": event.samples_per_cycle,
        "sample_count": len(event.samples),
        "analog_channels": [channel.name for channel in event.analog_channels],
        "digital_signal_count": len(event.digital_signals),
        "digital_transition_count": transitions,
        "warnings": list(event.warnings),
    }


def report_row(device_key: str, s3_key: str, sha256: str, device_ts: str, payload: bytes,
               fmt: str = "eve") -> Dict[str, Any]:
    return dict(
        {
            "schema_version": records.SCHEMA_VERSION,
            "device_key": device_key,
            "device_ts": device_ts,
            "s3_key": s3_key,
            "sha256": sha256,
            "report_parser_version": records.REPORT_PARSER_VERSION,
        },
        **summarize(payload, fmt),
    )


__all__ = ["report_row", "summarize"]
