"""Find and load saved SEL settings captures (offline).

Two layouts are recognized:

* SEL-Audit ``Reads/<site>/<ip_port>/<YYYYMMDDTHHMMSSZ>/`` FILE READ runs
  (``ID.txt``, ``CFG.TXT``, ``set_*.txt``, ``transcript.txt``, or
  ``ERROR.txt`` for a failed run);
* sel-triage evidence ``<run>/<device-slug>/`` folders from ``sel-snapshot``
  (``identity.txt`` and ``settings-*.txt`` in the SHO dialect).

A device is the ``<site>/<ip_port>`` folder (or the evidence device slug);
its captures are sorted oldest first.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from sel_triage.core.redaction import redact_settings
from ..parsers.common import parse_settings
from .files import parse_banner, parse_cfg, parse_id_text, parse_settings_file

_RUN_STAMP = re.compile(r"^(?P<stamp>\d{8}T\d{6}Z)", re.IGNORECASE)
_ERROR_TYPE = re.compile(r"Error:\s*(?P<type>[A-Za-z_][A-Za-z0-9_]*)")
_FILE_READ_MARKERS = ("ID.txt", "CFG.TXT", "ERROR.txt")
_EVIDENCE_MARKERS = ("identity.txt",)
_EVIDENCE_CLASSES = {"global": "G", "logic": "L1", "report": "R", "front": "F"}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _stamp(name: str) -> Optional[str]:
    match = _RUN_STAMP.match(name)
    if match is None:
        return None
    try:
        when = datetime.strptime(match.group("stamp").upper(), "%Y%m%dT%H%M%SZ")
    except ValueError:
        return None
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_file_read_run(path: Path) -> bool:
    return any((path / name).is_file() for name in _FILE_READ_MARKERS) or any(path.glob("set_*.txt"))


def _is_evidence_run(path: Path) -> bool:
    return any((path / name).is_file() for name in _EVIDENCE_MARKERS) or any(path.glob("settings-*.txt"))


def _status(identity: Mapping[str, Any], settings: Mapping[str, Any], failed: bool) -> str:
    if settings:
        return "ok" if identity else "settings_only"
    if identity:
        return "identity_only"
    return "failed" if failed else "empty"


def _load_file_read(path: Path) -> Dict[str, Any]:
    run: Dict[str, Any] = {
        "run": path.name,
        "captured_at": _stamp(path.name),
        "source": "file_read",
        "identity": {},
        "settings": {},
        "banner": {},
    }
    if (path / "ID.txt").is_file():
        run["identity"] = parse_id_text(_read(path / "ID.txt"))
    if (path / "CFG.TXT").is_file():
        cfg = parse_cfg(_read(path / "CFG.TXT"))
        if cfg.get("relay_type"):
            run["relay_type"] = cfg["relay_type"]
        if cfg.get("classes"):
            run["classes"] = cfg["classes"]
        if not run["identity"] and cfg.get("fid"):
            run["identity"] = parse_id_text('"FID={0}"'.format(cfg["fid"]))
    unparsed = 0
    for settings_path in sorted(path.glob("set_*.txt")):
        parsed = parse_settings_file(_read(settings_path))
        cls = parsed["class"] or settings_path.stem[4:]
        run["settings"][cls] = parsed["settings"]
        unparsed += len(parsed["unparsed_lines"])
    if unparsed:
        run["unparsed_line_count"] = unparsed
    failed = (path / "ERROR.txt").is_file()
    if failed:
        match = _ERROR_TYPE.search(_read(path / "ERROR.txt"))
        run["error"] = match.group("type") if match else "capture_failed"
    if (path / "transcript.txt").is_file():
        date_format = _first(run["settings"], ("DATE_F", "Time.DateFormat")) or "MDY"
        run["banner"] = parse_banner(_read(path / "transcript.txt"), date_format)
    run["status"] = _status(run["identity"], run["settings"], failed)
    return run


def _load_evidence(path: Path) -> Dict[str, Any]:
    run: Dict[str, Any] = {
        "run": "{0}/{1}".format(path.parent.name, path.name),
        "captured_at": _stamp(path.parent.name),
        "source": "evidence",
        "identity": {},
        "settings": {},
        "banner": {},
    }
    if (path / "identity.txt").is_file():
        run["identity"] = parse_id_text(_read(path / "identity.txt"))
    for settings_path in sorted(path.glob("settings-*.txt")):
        kind = settings_path.stem[len("settings-"):]
        parsed = parse_settings(_read(settings_path))
        if kind == "group":
            cls = str(parsed.get("group") or 1)
        else:
            cls = _EVIDENCE_CLASSES.get(kind, kind.upper())
        run["settings"].setdefault(cls, {}).update(redact_settings(parsed["settings"]))
    run["status"] = _status(run["identity"], run["settings"], False)
    return run


def _first(settings: Mapping[str, Mapping[str, str]], keys: Iterable[str]) -> Optional[str]:
    for values in settings.values():
        for key in keys:
            if key in values:
                return values[key]
    return None


def load_capture_run(path: Path) -> Dict[str, Any]:
    """Load one capture run folder (FILE READ or evidence layout)."""

    path = Path(path)
    if _is_evidence_run(path) and not _is_file_read_run(path):
        return _load_evidence(path)
    return _load_file_read(path)


def _run_dirs(root: Path) -> List[Path]:
    if _is_file_read_run(root) or _is_evidence_run(root):
        return [root]
    found = []
    for child in sorted(root.rglob("*")):
        if child.is_dir() and (_is_file_read_run(child) or _is_evidence_run(child)):
            found.append(child)
    return found


def _device_of(run_dir: Path, evidence: bool) -> Dict[str, Optional[str]]:
    if evidence:
        return {"key": run_dir.name, "site": None, "endpoint": run_dir.name}
    endpoint = run_dir.parent.name
    site = run_dir.parent.parent.name or None
    key = "{0}/{1}".format(site, endpoint) if site else endpoint
    return {"key": key, "site": site, "endpoint": endpoint}


def discover_devices(path: Path) -> List[Dict[str, Any]]:
    """Every device under *path* (corpus root, site, device or run folder)."""

    root = Path(path).expanduser()
    if not root.is_dir():
        raise ValueError("capture folder not found: {0}".format(path))
    devices: Dict[str, Dict[str, Any]] = {}
    for run_dir in _run_dirs(root):
        run = load_capture_run(run_dir)
        evidence = run["source"] == "evidence"
        device = _device_of(run_dir, evidence)
        try:
            run["path"] = str(run_dir.relative_to(root))
        except ValueError:
            run["path"] = run_dir.name
        if run["path"] == ".":
            run["path"] = run_dir.name
        entry = devices.setdefault(device["key"], dict(device, captures=[]))
        entry["captures"].append(run)
    for entry in devices.values():
        entry["captures"].sort(key=lambda run: (run.get("captured_at") or "", run["run"]))
    return [devices[key] for key in sorted(devices)]


def latest_identity_capture(device: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Newest capture with a parsed ``ID`` response."""

    for run in reversed(device.get("captures", [])):
        if run.get("identity"):
            return run
    return None


def latest_settings_capture(device: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Newest capture with parsed settings."""

    for run in reversed(device.get("captures", [])):
        if run.get("settings"):
            return run
    return None


__all__ = [
    "discover_devices",
    "latest_identity_capture",
    "latest_settings_capture",
    "load_capture_run",
]
