"""Re-parse archived HIS/SER raw text and event reports with the current parsers (no device access).

Archived ``EVE`` reports (listed in ``reports.jsonl``) whose summary is missing from every
``event_reports.jsonl``, or was written by an older ``REPORT_PARSER_VERSION``, are summarized
again into the reparse run's ``event_reports.jsonl``.

Each source sweep run that gains rows gets its own reparse run, so run rows stay
unique per (run_id, device_key). Every row carries ``seen_run`` (the sweep that
actually read it) so downstream loaders keep true first/last-seen provenance. A
(source run, device) already reparsed at the current parser version is skipped,
which makes repeated reparses a no-op.
"""

from typing import Dict, List, Optional, Set, Tuple

from ..integrations.devices.sel.adapters import adapter_for
from . import records
from .device import decode_payload, history_row, parse_capability, ser_row, shape_rows, utc_now
from .breaker import breaker_row, reads_breaker
from .event_reports import report_row

_NDJSON = "application/x-ndjson"
_TARGETS = (
    ("his.txt", "history", "events", "his_parse", history_row, "history"),
    ("ser.txt", "ser", "records", "ser_parse", ser_row, "ser"),
)


def _committed_runs(archive, prefix: str) -> List[Tuple[str, List[Dict]]]:
    runs = []
    for run_id in archive.list_children(prefix + "/normalized"):
        try:
            rows = records.from_jsonl(archive.get(records.normalized_key(prefix, run_id, "runs.jsonl")))
        except KeyError:
            continue  # uncommitted run
        runs.append((run_id, rows))
    return runs


def _already_reparsed(runs: List[Tuple[str, List[Dict]]]) -> Dict[Tuple[str, str], int]:
    done: Dict[Tuple[str, str], int] = {}
    for _run_id, rows in runs:
        for row in rows:
            if row.get("kind") == "reparse" and row.get("source_run_id"):
                key = (row["source_run_id"], row["device_key"])
                done[key] = max(done.get(key, 0), row.get("parser_version") or 0)
    return done


def _summarized(archive, prefix: str, runs: List[Tuple[str, List[Dict]]]) -> Set[str]:
    """SHA-256 of every report already summarized at the current report parser version."""

    done: Set[str] = set()
    for run_id, _rows in runs:
        try:
            rows = records.from_jsonl(archive.get(records.normalized_key(prefix, run_id, "event_reports.jsonl")))
        except KeyError:
            continue
        for row in rows:
            if (row.get("report_parser_version") or 0) >= records.REPORT_PARSER_VERSION and row.get("sha256"):
                done.add(row["sha256"])
    return done


def _reparse_reports(archive, prefix: str, source_run: str, summarized: Set[str],
                     devices: Optional[Set[str]]) -> Dict[str, List[Dict]]:
    """Summaries for the source run's archived reports not yet summarized, by device."""

    try:
        listed = records.from_jsonl(archive.get(records.normalized_key(prefix, source_run, "reports.jsonl")))
    except KeyError:
        return {}
    out: Dict[str, List[Dict]] = {}
    for item in listed:
        sha = item.get("sha256")
        if not sha or sha in summarized or (devices is not None and item["device_key"] not in devices):
            continue
        try:
            payload = archive.get(item["s3_key"])
        except KeyError:
            continue
        row = report_row(item["device_key"], item["s3_key"], sha, item.get("device_ts"), payload,
                         item.get("format") or "eve")
        row["seen_run"] = source_run
        out.setdefault(item["device_key"], []).append(row)
        summarized.add(sha)
    return out


def _breakers_done(archive, prefix: str, runs: List[Tuple[str, List[Dict]]]) -> Set[Tuple[str, str]]:
    """(device_key, sweep run) pairs whose BRE is already parsed at the current breaker version."""

    done: Set[Tuple[str, str]] = set()
    for run_id, _rows in runs:
        try:
            rows = records.from_jsonl(archive.get(records.normalized_key(prefix, run_id, "breaker.jsonl")))
        except KeyError:
            continue
        for row in rows:
            if (row.get("breaker_parser_version") or 0) >= records.BREAKER_PARSER_VERSION:
                done.add((row["device_key"], row.get("seen_run") or run_id))
    return done


def _reparse_breaker(archive, prefix: str, source_run: str, device: str, adapter, started: Optional[str],
                     done: Set[Tuple[str, str]]) -> Optional[Dict]:
    if not reads_breaker(adapter.family) or (device, source_run) in done:
        return None
    try:
        data = archive.get(records.raw_key(prefix, device, source_run, "bre.txt"))
    except KeyError:
        return None
    row = breaker_row(adapter, decode_payload(data), started or "")
    row.update(schema_version=records.SCHEMA_VERSION, device_key=device, seen_run=source_run)
    done.add((device, source_run))
    return row


def _reports_only_row(row: Dict, adapter, current: int) -> Dict:
    return {
        "schema_version": records.SCHEMA_VERSION, "kind": "reparse", "source_run_id": row["run_id_source"],
        "device_key": row["device_key"], "name": row.get("name"), "site": row.get("site"),
        "observed_model": row["observed_model"], "devid": row.get("devid"), "family": adapter.family,
        "parser_version": current, "ok": True, "reachable": None, "error_category": None, "errors": [],
        "warnings": [], "clock_offset_s": None, "ser_gap": None, "his_gap": None, "reports_fetched": 0,
        "reports_pending": 0, "his_parse": None, "ser_parse": None, "his_rows": None, "ser_rows": None,
    }


def _reparse_row(archive, prefix, source_run, row, adapter, current, out) -> Optional[Dict]:
    stale_version = (row.get("parser_version") or 0) < current
    reparsed = {"his_parse": None, "ser_parse": None, "his_rows": None, "ser_rows": None}
    produced = False
    for name, capability, key, flag, shape, bucket in _TARGETS:
        if row.get(flag) == "parsed" and not stale_version:
            continue
        try:
            data = archive.get(records.raw_key(prefix, row["device_key"], source_run, name))
        except KeyError:
            continue
        parsed, status = parse_capability(adapter, capability, decode_payload(data), key)
        reparsed[flag] = status
        if parsed is None:
            continue
        shaped, _dropped = shape_rows(parsed, shape)
        reparsed[flag.replace("_parse", "_rows")] = len(shaped)
        common = {
            "schema_version": records.SCHEMA_VERSION,
            "device_key": row["device_key"],
            "parser_version": current,
            "seen_run": source_run,
        }
        out[bucket].extend(dict(common, **item) for item in shaped)
        produced = True
    if not produced:
        return None
    return dict(
        {
            "schema_version": records.SCHEMA_VERSION,
            "kind": "reparse",
            "source_run_id": source_run,
            "device_key": row["device_key"],
            "name": row.get("name"),
            "site": row.get("site"),
            "observed_model": row["observed_model"],
            "devid": row.get("devid"),
            "family": adapter.family,
            "parser_version": current,
            "ok": True,
            "reachable": None,
            "error_category": None,
            "errors": [],
            "warnings": [],
            "clock_offset_s": None,
            "ser_gap": None,
            "his_gap": None,
            "reports_fetched": 0,
            "reports_pending": 0,
        },
        **reparsed,
    )


def _write_run(archive, prefix: str, run_id: str, out: Dict[str, List[Dict]], run_rows: List[Dict]) -> None:
    for group in (out["ser"], out["history"], out.get("event_reports", []), out.get("breakers", []), run_rows):
        for item in group:
            item["run_id"] = run_id
    archive.put(records.normalized_key(prefix, run_id, "ser.jsonl"), records.to_jsonl(out["ser"]), _NDJSON)
    archive.put(records.normalized_key(prefix, run_id, "history.jsonl"), records.to_jsonl(out["history"]), _NDJSON)
    archive.put(records.normalized_key(prefix, run_id, "reports.jsonl"), b"", _NDJSON)
    archive.put(records.normalized_key(prefix, run_id, "event_reports.jsonl"),
                records.to_jsonl(out.get("event_reports", [])), _NDJSON)
    archive.put(records.normalized_key(prefix, run_id, "breaker.jsonl"),
                records.to_jsonl(out.get("breakers", [])), _NDJSON)
    archive.put(records.normalized_key(prefix, run_id, "runs.jsonl"), records.to_jsonl(run_rows), _NDJSON)


def reparse(archive, prefix: str, *, clock=utc_now, family: Optional[str] = None, since: Optional[str] = None) -> Dict:
    runs = _committed_runs(archive, prefix)
    done = _already_reparsed(runs)
    result = {
        "tool": "sel-event-reparse", "ok": True, "run_ids": [], "runs_scanned": 0,
        "devices_reparsed": 0, "ser_rows": 0, "history_rows": 0, "event_reports": 0, "breakers": 0,
    }
    summarized = _summarized(archive, prefix, runs)
    breakers_done = _breakers_done(archive, prefix, runs)
    for source_run, rows in runs:
        if since is not None and source_run < since:
            continue
        result["runs_scanned"] += 1
        out: Dict[str, List[Dict]] = {"ser": [], "history": [], "event_reports": [], "breakers": []}
        run_rows: List[Dict] = []
        seen: Set[str] = set()
        for row in rows:
            if row.get("kind") != "sweep" or not row.get("observed_model") or row["device_key"] in seen:
                continue
            try:
                adapter = adapter_for(row["observed_model"]).adapter
            except ValueError:
                continue
            if family is not None and adapter.family != family:
                continue
            current = records.PARSER_VERSIONS.get(adapter.family, 0)
            if done.get((source_run, row["device_key"]), -1) >= current:
                continue
            run_row = _reparse_row(archive, prefix, source_run, row, adapter, current, out)
            if run_row is not None:
                seen.add(row["device_key"])
                run_rows.append(run_row)
        eligible = {}
        for row in rows:
            if row.get("kind") != "sweep" or not row.get("observed_model"):
                continue
            try:
                adapter = adapter_for(row["observed_model"]).adapter
            except ValueError:
                continue
            if family is None or adapter.family == family:
                eligible.setdefault(row["device_key"], (row, adapter))
        by_device = _reparse_reports(archive, prefix, source_run, summarized, set(eligible))
        for device, (row, adapter) in sorted(eligible.items()):
            breaker = _reparse_breaker(archive, prefix, source_run, device, adapter, row.get("finished_at"),
                                       breakers_done)
            if breaker is not None:
                out["breakers"].append(breaker)
                by_device.setdefault(device, [])
        for device, report_rows in sorted(by_device.items()):
            out["event_reports"].extend(report_rows)
            if device not in seen:
                row, adapter = eligible[device]
                run_rows.append(_reports_only_row(dict(row, run_id_source=source_run), adapter,
                                                  records.PARSER_VERSIONS.get(adapter.family, 0)))
                seen.add(device)
        if not run_rows:
            continue
        now = clock()
        for run_row in run_rows:
            run_row["started_at"] = run_row["finished_at"] = records.iso_utc(now)
        run_id = records.new_run_id(now)
        _write_run(archive, prefix, run_id, out, run_rows)
        result["run_ids"].append(run_id)
        result["devices_reparsed"] += len(run_rows)
        result["ser_rows"] += len(out["ser"])
        result["history_rows"] += len(out["history"])
        result["event_reports"] += len(out["event_reports"])
        result["breakers"] += len(out["breakers"])
    return result
