"""Assemble a SEL ``.rdb`` relay database from a ``FILE READ`` capture.

Ported from SEL-Audit ``relay_tools/rdb_pack.py``; captures now come from
``sel-settings-capture`` (same ``Reads`` layout).

``cli_read_settings.py`` captures the relay's stored streams (``CFG.TXT``,
``set_*.txt``) under ``Reads/``. This module turns such a capture into a
loadable ``.rdb`` in either of two modes:

* **subset** -- pack exactly the streams the relay returned. Faithful to the
  relay, but it contains only the settings that apply to this unit's installed
  hardware and enabled functions (the relay omits
  inapplicable settings; QuickSet's full schema includes them).
* **template** -- overlay the captured values onto a full-schema template
  ``.rdb`` (a genuine QuickSet export for the same relay FID), producing a
  complete database identical in shape to a QuickSet READ.

Two format details matter:

* ``.rdb`` settings streams terminate each *data* line with ``0x1C`` then
  CRLF; the relay's own ``set_*.txt`` files use a plain CRLF.
  :func:`add_record_terminators` converts between the two. ``Cfg.txt`` is the
  exception -- its ``[CLASSES]`` rows use plain CRLF -- so it is never
  transformed.
* streams live under ``Relays/<DeviceName>/...``; the device name is the label
  QuickSet shows in its tree.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from .ole_writer import write_ole

_FS = b"\x1c"  # record separator that ends each .rdb data line
_CRLF = b"\r\n"


def _is_data_line(line: bytes) -> bool:
    """True for a ``KEY,"VALUE"`` settings row (not an ``[INFO]``/``[group]``)."""
    return b',"' in line and not line.startswith(b"[")


def _is_settings_stream(name: str) -> bool:
    """True for a settings stream file (``set_1.txt`` ... ``set_R.txt``, ``SET_HMI.TXT``).

    These share the ``[INFO]``/``[group]``/record-terminated form, so they are
    converted and overlaid the same way. ``CFG.TXT`` and ``ID.txt`` are not.
    """
    lower = name.lower()
    return lower.startswith("set_") and lower.endswith(".txt")


def _split_lines(stream: bytes) -> list[bytes]:
    """Split a settings stream into lines, dropping record separators."""
    body = stream.replace(_FS, b"")
    lines = body.split(_CRLF)
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def add_record_terminators(stream: bytes) -> bytes:
    """Convert a relay-native ``set_*.txt`` to ``.rdb`` form.

    Each ``KEY,"VALUE"`` data line gains a trailing ``0x1C``; the ``[INFO]``
    block and ``[group]`` header keep a plain CRLF. Any existing ``0x1C``
    bytes are normalised away first, so the function is idempotent.
    """
    out = bytearray()
    for line in _split_lines(stream):
        out += line
        if _is_data_line(line):
            out += _FS
        out += _CRLF
    return bytes(out)


def _data_key(line: bytes) -> bytes:
    """The setting name from a ``KEY,"VALUE"`` data line."""
    return line.split(b",", 1)[0]


def overlay_set_stream(template: bytes, capture: bytes) -> bytes:
    """Overlay captured values onto a full-schema template settings stream.

    The template's structure and key set are preserved (so the result stays a
    complete, QuickSet-shaped stream). Every data line whose key also appears
    in the capture takes the capture's value; keys absent from the capture --
    settings for hardware/functions this unit lacks -- keep the template's
    default. The output is in ``.rdb`` form (``0x1C`` terminators).
    """
    captured = {
        _data_key(line): line
        for line in _split_lines(capture)
        if _is_data_line(line)
    }
    out = bytearray()
    for line in _split_lines(template):
        if _is_data_line(line):
            out += captured.get(_data_key(line), line) + _FS + _CRLF
        else:
            out += line + _CRLF
    return bytes(out)


def read_ole_streams(rdb_path: str) -> dict[str, bytes]:
    """Read every stream of an existing ``.rdb`` into a ``{path: bytes}`` map (needs the [rdb] extra)."""
    try:
        import olefile
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise ValueError("reading a .rdb needs olefile: pip install -e '.[rdb]'") from error
    if not olefile.isOleFile(str(rdb_path)):
        raise ValueError("not an OLE2 .rdb file: {0}".format(rdb_path))
    ole = olefile.OleFileIO(str(rdb_path))
    try:
        return {
            "/".join(parts): ole.openstream(parts).read()
            for parts in ole.listdir(streams=True, storages=False)
        }
    finally:
        ole.close()


def _synth_version(relaytype: str) -> bytes:
    """Synthesise a ``Misc/Version`` stream for subset-mode packing."""
    when = dt.datetime.now().strftime("%m/%d/%Y at %I:%M:%S %p")
    return (
        f"Saved with sel-triage sel-rdb pack\r\n"
        f"Relay type: {relaytype}\r\n"
        f"Saved on {when}\r\n"
    ).encode("ascii", "replace")


def _relaytype(cfg: bytes) -> str:
    """Pull ``RELAYTYPE`` from a ``CFG.TXT`` ``[INFO]`` block."""
    for line in _split_lines(cfg):
        if line.startswith(b"RELAYTYPE="):
            return line.split(b"=", 1)[1].decode("ascii", "replace")
    return "SEL"


def pack_subset(capture_dir: Path, device_name: str) -> dict[str, bytes]:
    """Build ``.rdb`` streams from a capture alone (relay's applicable settings).

    Args:
        capture_dir: A ``Reads/.../<timestamp>`` folder holding ``CFG.TXT`` and
            ``set_*.txt``.
        device_name: Folder/label for the relay inside the ``.rdb``.

    Returns:
        A ``{stream_path: bytes}`` map ready for :func:`relay_tools.ole_writer.write_ole`.
    """
    base = f"Relays/{device_name}"
    cfg = (capture_dir / "CFG.TXT").read_bytes()
    streams: dict[str, bytes] = {
        f"{base}/Misc/Cfg.txt": cfg,  # used verbatim -- never gets 0x1C
        f"{base}/Misc/DatabaseVersion.txt": b"1.1\r\n",
        f"{base}/Misc/Device.txt": device_name.encode("ascii", "replace"),
        f"{base}/Misc/Version": _synth_version(_relaytype(cfg)),
    }
    for set_file in sorted(capture_dir.iterdir()):
        if set_file.is_file() and _is_settings_stream(set_file.name):
            streams[f"{base}/{set_file.name}"] = add_record_terminators(
                set_file.read_bytes()
            )
    return streams


def pack_with_template(
    capture_dir: Path, template_rdb: str, device_name: str
) -> dict[str, bytes]:
    """Build full-schema ``.rdb`` streams by overlaying a capture onto a template.

    The template's complete stream set (including ``SET_HMI.TXT`` and the
    ``Misc`` metadata) is cloned under ``device_name``; every ``set_*.txt``
    stream is overlaid with the capture's current values.

    Args:
        capture_dir: A ``Reads/.../<timestamp>`` capture folder.
        template_rdb: Path to a genuine ``.rdb`` for the same relay FID.
        device_name: Folder/label for the relay inside the new ``.rdb``.

    Returns:
        A ``{stream_path: bytes}`` map ready for :func:`relay_tools.ole_writer.write_ole`.
    """
    template = read_ole_streams(template_rdb)
    # The template stores everything under Relays/<its device name>/...
    template_device = next(
        (p.split("/", 2)[1] for p in template if p.startswith("Relays/")), None
    )
    if template_device is None:
        raise ValueError(f"{template_rdb} has no Relays/<device>/ streams")

    streams: dict[str, bytes] = {}
    for path, data in template.items():
        new_path = path.replace(
            f"Relays/{template_device}/", f"Relays/{device_name}/", 1
        )
        name = path.rsplit("/", 1)[-1]
        captured = capture_dir / name
        if _is_settings_stream(name) and captured.exists():
            data = overlay_set_stream(data, captured.read_bytes())
        elif name == "Device.txt":
            data = device_name.encode("ascii", "replace")
        streams[new_path] = data
    return streams


def pack_rdb(
    capture_dir: Path,
    out_path: str,
    device_name: str,
    *,
    template_rdb: str | None = None,
) -> dict[str, bytes]:
    """Pack a capture into a ``.rdb`` file.

    Uses template mode when ``template_rdb`` is given, otherwise subset mode.
    Returns the stream map that was written (useful for inspection/tests).
    """
    if template_rdb:
        streams = pack_with_template(capture_dir, template_rdb, device_name)
    else:
        streams = pack_subset(capture_dir, device_name)
    write_ole(out_path, streams)
    return streams
