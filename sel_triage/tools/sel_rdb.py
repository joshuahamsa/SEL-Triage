"""sel-rdb: SEL .rdb relay databases from settings captures, and reading them (local files only).

* ``pack CAPTURE``: one capture folder -> ``.rdb`` (subset mode: the settings the relay
  returned; ``--template X.rdb``: overlaid onto a full-schema QuickSet export of the same FID).
* ``pack-all [ROOT]``: the newest good capture of every device -> ``<out>/<site>/<label>.rdb``;
  ``--templates DIR`` holds ``<FID>.rdb`` files, used where the FID matches (the SEL-Audit
  ``cli_audit_rdb`` fleet packer, without the relay reads: run ``sel-settings-capture`` first).
* ``read RDB``: relays, classes and settings; ``--extract DIR`` dumps raw streams,
  ``--as-capture DIR`` writes a relay as a capture folder for ``sel-settings diff``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from ..integrations.devices.sel.rdb.pack import pack_rdb
from ..integrations.devices.sel.rdb.read import extract_streams, read_rdb, write_capture
from ..integrations.devices.sel.settings.capture import discover_devices, latest_settings_capture
from .sel_capture import folder_name


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label(name: str) -> str:
    """QuickSet device label: plain ASCII, no path characters (max 60)."""

    text = re.sub(r"[^A-Za-z0-9 ._()-]+", "_", name).strip(" ._")
    return (text or "relay")[:60]


def run_pack(capture: Path, *, out: Optional[Path] = None, template: Optional[Path] = None,
             device_name: Optional[str] = None) -> Dict[str, Any]:
    capture = Path(capture).expanduser()
    if not (capture / "CFG.TXT").is_file():
        raise ValueError("not a capture folder (no CFG.TXT): {0}".format(capture))
    name = _label(device_name or capture.parent.name)
    out = Path(out).expanduser() if out else capture.parent / "{0}.rdb".format(name)
    streams = pack_rdb(capture, str(out), name, template_rdb=str(template) if template else None)
    return {"tool": "sel-rdb-pack", "ran_at": _now(), "ok": True, "capture": str(capture), "rdb": str(out),
            "device": name, "mode": "template" if template else "subset", "streams": len(streams)}


def _templates(folder: Optional[Path]) -> Dict[str, Path]:
    if folder is None:
        return {}
    return {path.stem: path for path in sorted(Path(folder).expanduser().glob("*.rdb"))}


def run_pack_all(root: Path, out_dir: Path, *, templates: Optional[Path] = None,
                 endpoints: Mapping[str, Tuple[str, Optional[str]]] = None) -> Dict[str, Any]:
    endpoints = endpoints or {}
    by_fid = _templates(templates)
    packed, skipped, failed = [], [], []
    for device in discover_devices(Path(root).expanduser()):
        run = latest_settings_capture(device)
        if run is None:
            skipped.append({"device": device["key"], "reason": "no_settings_capture"})
            continue
        capture = Path(root).expanduser() / run["path"]
        known = endpoints.get(device["endpoint"])
        label = _label(known[0].split("/", 1)[-1] if known else device["endpoint"])
        site = folder_name((known[1] if known else None) or device["site"] or "unknown")
        fid = (run.get("identity") or {}).get("fid")
        template = by_fid.get(fid) if fid else None
        target = Path(out_dir).expanduser() / site / "{0}.rdb".format(label)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            pack_rdb(capture, str(target), label, template_rdb=str(template) if template else None)
        except (OSError, ValueError) as error:
            failed.append({"device": device["key"], "error": str(error)})
            continue
        packed.append({"device": device["key"], "captured_at": run.get("captured_at"), "fid": fid,
                       "mode": "template" if template else "subset", "rdb": str(target)})
    return {"tool": "sel-rdb-pack-all", "ran_at": _now(), "ok": not failed, "root": str(root), "out": str(out_dir),
            "packed": packed, "skipped": skipped, "failed": failed}


def run_read(rdb: Path, *, extract: Optional[Path] = None, as_capture: Optional[Path] = None,
             device: Optional[str] = None, include_settings: bool = False) -> Dict[str, Any]:
    result = read_rdb(Path(rdb).expanduser())
    out: Dict[str, Any] = {"tool": "sel-rdb-read", "ran_at": _now(), "ok": True, "rdb": result["path"]}
    out["relays"] = [
        {k: v for k, v in relay.items() if include_settings or k != "settings"} for relay in result["relays"]
    ]
    if extract is not None:
        out["extracted"] = extract_streams(Path(rdb).expanduser(), Path(extract).expanduser())
    if as_capture is not None:
        names = [relay["device"] for relay in result["relays"]]
        chosen = device or (names[0] if len(names) == 1 else None)
        if chosen is None:
            raise ValueError("the .rdb holds several relays ({0}); pass --device".format(", ".join(names)))
        out["capture"] = str(write_capture(Path(rdb).expanduser(), chosen, Path(as_capture).expanduser()))
    return out


def render_lines(result: Mapping[str, Any]) -> list:
    tool = result.get("tool")
    if tool == "sel-rdb-pack":
        return ["  {0} ({1}, {2} streams) -> {3}".format(result["device"], result["mode"], result["streams"], result["rdb"])]
    if tool == "sel-rdb-pack-all":
        lines = ["  packed {0}, skipped {1}, failed {2} -> {3}".format(
            len(result["packed"]), len(result["skipped"]), len(result["failed"]), result["out"])]
        lines += ["  FAILED {0}: {1}".format(item["device"], item["error"]) for item in result["failed"]]
        return lines
    lines = []
    for relay in result.get("relays", []):
        lines.append("  {0}  {1}  {2}  classes {3}  settings {4}".format(
            relay["device"], relay.get("relay_type") or "-", relay.get("fid") or "-",
            ",".join(relay["classes"]), relay["setting_count"]))
    if result.get("capture"):
        lines.append("  capture folder: {0}".format(result["capture"]))
    return lines


__all__ = ["render_lines", "run_pack", "run_pack_all", "run_read"]
