"""Read SEL ``.rdb`` relay databases (offline).

A ``.rdb`` is an OLE2 compound file holding one folder per relay::

    Relays/<Device>/Misc/Cfg.txt      class list ([INFO] RELAYTYPE, FID...)
    Relays/<Device>/Misc/Device.txt   the label QuickSet shows
    Relays/<Device>/Misc/Version      firmware / save note
    Relays/<Device>/set_<class>.txt   settings streams (data lines end 0x1C CR LF; padded with 0x1A)

``read_rdb`` parses each relay's settings into the same ``{class: {key: value}}`` shape as
a ``FILE READ`` capture (secrets redacted); ``write_capture`` turns one relay back into a
capture-layout folder (``CFG.TXT``, ``set_<class>.txt``) so ``sel-settings check|diff`` can
compare a QuickSet database with what a relay reports. Reading needs the ``[rdb]`` extra.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from ..settings.files import parse_cfg, parse_settings_file
from .pack import read_ole_streams

_FS = b"\x1c"
_SUB = b"\x1a"


def _plain(stream: bytes) -> bytes:
    """A settings stream as the relay's own file: no record separators or EOF padding."""

    return stream.replace(_FS, b"").rstrip(_SUB)


def relays(streams: Dict[str, bytes]) -> Dict[str, Dict[str, bytes]]:
    """``{device label: {stream name relative to the relay folder: bytes}}``."""

    out: Dict[str, Dict[str, bytes]] = {}
    for path, data in streams.items():
        parts = path.split("/", 2)
        if len(parts) == 3 and parts[0] == "Relays":
            out.setdefault(parts[1], {})[parts[2]] = data
    return out


def read_rdb(path: Path) -> Dict[str, Any]:
    by_relay = relays(read_ole_streams(str(path)))
    result: List[Dict[str, Any]] = []
    for device, streams in sorted(by_relay.items()):
        cfg_bytes = streams.get("Misc/Cfg.txt", b"")
        cfg = parse_cfg(cfg_bytes.decode("ascii", "replace")) if cfg_bytes else {}
        settings: Dict[str, Dict[str, str]] = {}
        unparsed = 0
        for name, data in sorted(streams.items()):
            if "/" in name or not name.lower().startswith("set_") or not name.lower().endswith(".txt"):
                continue
            parsed = parse_settings_file(_plain(data).decode("latin-1"))
            settings[parsed["class"] or name[4:-4]] = parsed["settings"]
            unparsed += len(parsed["unparsed_lines"])
        result.append({
            "device": device,
            "relay_type": cfg.get("relay_type"),
            "fid": cfg.get("fid"),
            "classes": sorted(settings),
            "setting_count": sum(len(values) for values in settings.values()),
            "unparsed_line_count": unparsed,
            "version": streams.get("Misc/Version", b"").decode("latin-1", "replace").strip() or None,
            "streams": sorted(streams),
            "settings": settings,
        })
    return {"path": str(path), "relays": result}


def write_capture(path: Path, device: str, out_dir: Path) -> Path:
    """Write one relay of a ``.rdb`` as a capture folder (``CFG.TXT`` + ``set_*.txt``)."""

    streams = relays(read_ole_streams(str(path))).get(device)
    if streams is None:
        raise ValueError("no relay named {0!r} in {1}".format(device, path))
    out_dir.mkdir(parents=True, exist_ok=True)
    if "Misc/Cfg.txt" in streams:
        (out_dir / "CFG.TXT").write_bytes(streams["Misc/Cfg.txt"].rstrip(_SUB))
    for name, data in streams.items():
        if "/" not in name and name.lower().startswith("set_") and name.lower().endswith(".txt"):
            target = "SET_HMI.TXT" if name.upper() == "SET_HMI.TXT" else "set_{0}".format(name[4:])
            (out_dir / target).write_bytes(_plain(data))
    return out_dir


def extract_streams(path: Path, out_dir: Path) -> List[str]:
    """Dump every stream to a mirrored folder tree (raw bytes), as the Lowes extract.py did."""

    written = []
    for name, data in read_ole_streams(str(path)).items():
        target = out_dir.joinpath(*name.split("/"))
        if out_dir.resolve() not in target.resolve().parents:
            raise ValueError("stream path escapes the output folder: " + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written.append(name)
    return sorted(written)


__all__ = ["extract_streams", "read_rdb", "relays", "write_capture"]
