"""SQLite index of saved SEL settings captures, for fleet-wide queries (offline).

The capture folders stay the source of truth; this index is derived from them and can be
rebuilt at any time. Indexing is incremental: a run whose files are unchanged since it was
indexed is skipped, a changed run is re-read, and a run whose folder is gone is dropped.
Several capture roots (the sel-triage captures folder and SEL-Audit ``Reads``) can share
one database, so a device's history spans both.

Device identity: ``device_key`` is the folder's ``<site>/<host>_<port>`` (provenance). When the
caller passes the device inventory, a capture whose ``<host>_<port>`` matches a configured
device gets that device's name and site in ``device`` / ``device_site``; otherwise ``device``
is the folder key. The ``latest_*`` views group by ``device``, so captures filed under
different site spellings (SEL-Audit vs the inventory) form one history.

Tables
    captures(capture_id, root, path, device_key, device, device_site, site, endpoint, run,
             captured_at, status,
             source, method, model, fid, firmware_revision, firmware_date, part_number,
             serial_number, device_id, relay_type, error, setting_count,
             unparsed_line_count, fingerprint, indexed_at)
    settings(capture_id, class, key, value)          -- values as parsed, secrets redacted
    device_commands(capture_id, command, description) -- the device's HELP list (advertised
                                                          commands; HELP omits privileged ones)
    manual_commands(model, manual_date, verb, command, min_access_level, access_levels, kind,
                    description, page)                 -- SEL manual command summaries
    manual_firmware(model, manual_date, revision, fid, date, command_changes)
Views
    latest_captures   newest ``ok`` capture per device
    latest_settings   the settings of those captures
    latest_commands   the newest HELP list per device (``help_status = 'ok'``)
    device_command_reference  each device's manual command list (by model, newest manual)
    device_firmware_reference each device's firmware vs the manual's revision history
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .capture import _device_of, _run_dirs, load_capture_run
from .help import parse_help
from ..reference import load_reference, reference_model

SCHEMA_VERSION = 4

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS captures (
    capture_id INTEGER PRIMARY KEY,
    root TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    device_key TEXT NOT NULL,
    device TEXT NOT NULL,
    device_site TEXT,
    site TEXT,
    endpoint TEXT,
    run TEXT,
    captured_at TEXT,
    status TEXT,
    source TEXT,
    method TEXT,
    model TEXT,
    fid TEXT,
    firmware_revision TEXT,
    firmware_date TEXT,
    part_number TEXT,
    serial_number TEXT,
    device_id TEXT,
    relay_type TEXT,
    error TEXT,
    setting_count INTEGER,
    unparsed_line_count INTEGER,
    help_status TEXT,
    help_command_count INTEGER,
    manual_model TEXT,
    fingerprint TEXT NOT NULL,
    indexed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS captures_device ON captures (device, captured_at);
CREATE TABLE IF NOT EXISTS settings (
    capture_id INTEGER NOT NULL REFERENCES captures (capture_id) ON DELETE CASCADE,
    class TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    PRIMARY KEY (capture_id, class, key)
);
CREATE INDEX IF NOT EXISTS settings_key ON settings (key, class);
CREATE TABLE IF NOT EXISTS device_commands (
    capture_id INTEGER NOT NULL REFERENCES captures (capture_id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    description TEXT,
    PRIMARY KEY (capture_id, command)
);
CREATE TABLE IF NOT EXISTS manual_commands (
    model TEXT NOT NULL,
    manual_date TEXT,
    verb TEXT NOT NULL,
    command TEXT NOT NULL,
    min_access_level TEXT,
    access_levels TEXT,
    kind TEXT,
    description TEXT,
    page INTEGER
);
CREATE INDEX IF NOT EXISTS manual_commands_model ON manual_commands (model, verb);
CREATE TABLE IF NOT EXISTS manual_firmware (
    model TEXT NOT NULL,
    manual_date TEXT,
    revision TEXT,
    fid TEXT,
    date TEXT,
    command_changes TEXT
);
CREATE INDEX IF NOT EXISTS manual_firmware_fid ON manual_firmware (fid);
CREATE VIEW IF NOT EXISTS device_command_reference AS
    SELECT l.device, l.device_site, l.model, l.fid, l.firmware_revision, m.manual_date,
           m.verb, m.command, m.min_access_level, m.access_levels, m.kind, m.description
    FROM latest_captures l JOIN manual_commands m ON m.model = l.manual_model;
CREATE VIEW IF NOT EXISTS device_firmware_reference AS
    SELECT l.device, l.device_site, l.model, l.manual_model, l.fid, l.firmware_revision,
           (SELECT MAX(f.manual_date) FROM manual_firmware f WHERE f.model = l.manual_model) AS manual_date,
           (SELECT f.revision FROM manual_firmware f WHERE f.model = l.manual_model
              ORDER BY CAST(SUBSTR(f.revision, 2) AS INTEGER) DESC LIMIT 1) AS manual_latest_revision,
           EXISTS (SELECT 1 FROM manual_firmware f WHERE f.fid = l.fid) AS fid_in_manual,
           (SELECT f.command_changes FROM manual_firmware f WHERE f.fid = l.fid LIMIT 1) AS command_changes
    FROM latest_captures l;
CREATE VIEW IF NOT EXISTS latest_commands AS
    SELECT c.device, c.device_site, c.model, c.fid, c.firmware_revision, c.captured_at, d.command, d.description
    FROM captures c JOIN device_commands d ON d.capture_id = c.capture_id
    WHERE c.capture_id = (
        SELECT c2.capture_id FROM captures c2
        WHERE c2.device = c.device AND c2.help_status = 'ok'
        ORDER BY c2.captured_at DESC, c2.capture_id DESC LIMIT 1);
CREATE VIEW IF NOT EXISTS latest_captures AS
    SELECT c.* FROM captures c
    WHERE c.status = 'ok'
      AND c.capture_id = (
          SELECT c2.capture_id FROM captures c2
          WHERE c2.device = c.device AND c2.status = 'ok'
          ORDER BY c2.captured_at DESC, c2.capture_id DESC LIMIT 1);
CREATE VIEW IF NOT EXISTS latest_settings AS
    SELECT l.device, l.device_site, l.device_key, l.model, l.fid, l.captured_at, s.class, s.key, s.value
    FROM latest_captures l JOIN settings s ON s.capture_id = l.capture_id;
"""


def connect(db_path: Path) -> Tuple[sqlite3.Connection, bool]:
    """Open (creating) the index; a database from another schema version is reset (it is derived)."""

    db_path = Path(db_path).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    reset = False
    has_meta = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'").fetchone()
    if has_meta:
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        if row is None or row[0] != str(SCHEMA_VERSION):
            conn.executescript(
                "DROP VIEW IF EXISTS device_firmware_reference; DROP VIEW IF EXISTS device_command_reference;"
                "DROP TABLE IF EXISTS manual_commands; DROP TABLE IF EXISTS manual_firmware;"
                "DROP VIEW IF EXISTS latest_commands; DROP VIEW IF EXISTS latest_settings;"
                "DROP VIEW IF EXISTS latest_captures; DROP TABLE IF EXISTS device_commands;"
                "DROP TABLE IF EXISTS settings; DROP TABLE IF EXISTS captures; DROP TABLE IF EXISTS meta;"
            )
            reset = True
    conn.executescript(_SCHEMA)
    conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    conn.commit()
    return conn, reset


def inventory_endpoints(config: Mapping[str, Any]) -> Dict[str, Tuple[str, Optional[str]]]:
    """``<host>_<port>`` -> (device name, site) for configured SEL devices (first entry wins)."""

    endpoints: Dict[str, Tuple[str, Optional[str]]] = {}
    for entry in config.get("devices", []) or []:
        if entry.get("kind") != "sel" or not entry.get("host") or not entry.get("port"):
            continue
        name = entry.get("name")
        site = entry.get("site") or (name.split("/", 1)[0] if name else None)
        endpoints.setdefault("{0}_{1}".format(entry["host"], entry["port"]), (name, site))
    return endpoints


def _fingerprint(run_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in run_dir.iterdir() if p.is_file()):
        stat = path.stat()
        digest.update("{0}\0{1}\0{2}\n".format(path.name, stat.st_size, stat.st_mtime_ns).encode())
    return digest.hexdigest()


def _method(run_dir: Path, run: Dict[str, Any]) -> Optional[str]:
    manifest = run_dir / "manifest.json"
    if manifest.is_file():
        try:
            return json.loads(manifest.read_text(encoding="utf-8")).get("method")
        except (OSError, ValueError):
            return None
    return "sho" if run.get("source") == "evidence" else None


def _help(run_dir: Path) -> Optional[Dict[str, Any]]:
    path = run_dir / "HELP.txt"
    if not path.is_file():
        return None
    return parse_help(path.read_text(encoding="utf-8", errors="replace"))


def _row(root: Path, run_dir: Path, run: Dict[str, Any], fingerprint: str, now: str,
         endpoints: Mapping[str, Tuple[str, Optional[str]]]) -> Dict[str, Any]:
    evidence = run.get("source") == "evidence"
    device = _device_of(run_dir, evidence)
    identity = run.get("identity") or {}
    firmware = identity.get("firmware") or {}
    known = endpoints.get(device["endpoint"]) if not evidence else None
    return {
        "root": str(root),
        "path": str(run_dir),
        "device_key": device["key"],
        "device": known[0] if known else device["key"],
        "device_site": known[1] if known else device["site"],
        "site": device["site"],
        "endpoint": device["endpoint"],
        "run": run.get("run"),
        "captured_at": run.get("captured_at"),
        "status": run.get("status"),
        "source": run.get("source"),
        "method": _method(run_dir, run),
        "model": identity.get("model"),
        "fid": identity.get("fid"),
        "firmware_revision": firmware.get("revision"),
        "firmware_date": firmware.get("date"),
        "part_number": identity.get("part_number"),
        "serial_number": identity.get("serial_number"),
        "device_id": identity.get("device_id"),
        "relay_type": run.get("relay_type"),
        "error": run.get("error"),
        "setting_count": sum(len(values) for values in (run.get("settings") or {}).values()),
        "unparsed_line_count": run.get("unparsed_line_count", 0),
        "help_status": None,
        "help_command_count": None,
        "manual_model": reference_model(identity.get("model") or run.get("relay_type")),
        "fingerprint": fingerprint,
        "indexed_at": now,
    }


def build_index(
    root: Path,
    db_path: Path,
    *,
    rebuild: bool = False,
    now: Optional[datetime] = None,
    endpoints: Optional[Mapping[str, Tuple[str, Optional[str]]]] = None,
) -> Dict[str, Any]:
    """Index every capture run under *root* into *db_path*; returns counts.

    *endpoints* (see :func:`inventory_endpoints`) names devices; a run whose stored device
    name differs from the current inventory's is re-indexed."""

    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("capture folder not found: {0}".format(root))
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = {"root": str(root), "db": str(Path(db_path).expanduser()), "indexed": 0, "unchanged": 0,
               "removed": 0, "failed": 0, "captures": 0, "devices": 0, "settings_rows": 0,
               "matched_to_inventory": 0, "schema_reset": False}
    endpoints = dict(endpoints or {})
    conn, summary["schema_reset"] = connect(db_path)
    try:
        with conn:
            if rebuild:
                conn.execute("DELETE FROM captures WHERE root = ?", (str(root),))
            _load_reference(conn)
            known = {
                path: (capture_id, fingerprint, device)
                for capture_id, path, fingerprint, device in conn.execute(
                    "SELECT capture_id, path, fingerprint, device FROM captures WHERE root = ?", (str(root),))
            }
            seen = set()
            for run_dir in _run_dirs(root):
                path = str(run_dir)
                seen.add(path)
                fingerprint = _fingerprint(run_dir)
                existing = known.get(path)
                endpoint = _device_of(run_dir, False)["endpoint"]
                expected = endpoints[endpoint][0] if endpoint in endpoints else None
                if existing is not None and existing[1] == fingerprint and (expected is None or existing[2] == expected):
                    summary["unchanged"] += 1
                    continue
                try:
                    run = load_capture_run(run_dir)
                except (OSError, ValueError, UnicodeError):
                    summary["failed"] += 1
                    continue
                if existing is not None:
                    conn.execute("DELETE FROM captures WHERE capture_id = ?", (existing[0],))
                row = _row(root, run_dir, run, fingerprint, stamp, endpoints)
                help_result = _help(run_dir)
                if help_result is not None:
                    row["help_status"] = "rejected" if help_result["rejected"] else (
                        "ok" if help_result["commands"] else "empty")
                    row["help_command_count"] = len(help_result["commands"])
                cursor = conn.execute(
                    "INSERT INTO captures ({0}) VALUES ({1})".format(
                        ", ".join(row), ", ".join("?" for _ in row)),
                    tuple(row.values()),
                )
                conn.executemany(
                    "INSERT OR REPLACE INTO settings (capture_id, class, key, value) VALUES (?, ?, ?, ?)",
                    _setting_rows(cursor.lastrowid, run.get("settings") or {}),
                )
                if help_result is not None:
                    conn.executemany(
                        "INSERT OR REPLACE INTO device_commands (capture_id, command, description) VALUES (?, ?, ?)",
                        [(cursor.lastrowid, c["command"], c["description"]) for c in help_result["commands"]],
                    )
                summary["indexed"] += 1
            for path, (capture_id, _fp, _device) in known.items():
                if path not in seen:
                    conn.execute("DELETE FROM captures WHERE capture_id = ?", (capture_id,))
                    summary["removed"] += 1
        summary["captures"], summary["devices"] = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT device) FROM captures").fetchone()
        summary["matched_to_inventory"] = conn.execute(
            "SELECT COUNT(DISTINCT device) FROM captures WHERE device <> device_key").fetchone()[0]
        summary["settings_rows"] = conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0]
    finally:
        conn.close()
    return summary


def _load_reference(conn: sqlite3.Connection) -> None:
    """Replace the manual tables from the packaged reference (newest manual per model for commands)."""

    conn.execute("DELETE FROM manual_commands")
    conn.execute("DELETE FROM manual_firmware")
    newest: Dict[str, str] = {}
    seen_fids = set()
    for doc in load_reference():
        model, date = doc["model"], doc.get("manual_date")
        if model not in newest:
            newest[model] = date
            conn.executemany(
                "INSERT INTO manual_commands VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(model, date, c["command"].split()[0].upper(), c["command"], c.get("min_access_level"), ",".join(c.get("access_levels") or []),
                  c.get("kind"), c.get("description"), c.get("page")) for c in doc.get("commands", [])],
            )
        for entry in doc.get("firmware", []):
            key = entry.get("fid") or (model, entry.get("revision"), date)
            if key in seen_fids:
                continue
            seen_fids.add(key)
            conn.execute(
                "INSERT INTO manual_firmware VALUES (?, ?, ?, ?, ?, ?)",
                (model, date, entry.get("revision"), entry.get("fid"), entry.get("date"),
                 json.dumps(entry.get("command_changes") or [])),
            )


def _setting_rows(capture_id: int, settings: Dict[str, Dict[str, Any]]) -> Iterable[tuple]:
    for cls, values in settings.items():
        for key, value in values.items():
            yield capture_id, str(cls), str(key), None if value is None else str(value)


__all__ = ["SCHEMA_VERSION", "build_index", "connect", "inventory_endpoints"]
