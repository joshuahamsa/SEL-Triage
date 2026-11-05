"""Live SEL settings capture: ``ID`` + ``FILE READ`` (or ``FILE SHOW``) of every settings stream.

Ported from SEL-Audit ``cli_read_settings.py`` (the field-proven QuickSet-equivalent
read). For a logged-in Access Level 1 session it saves, in SEL-Audit's capture layout
so the offline ``sel-inventory`` / ``sel-settings`` tools read it unchanged:

    <run_dir>/ID.txt         the ID response
    <run_dir>/CFG.TXT        settings class list
    <run_dir>/set_<C>.txt    one stream per class in CFG.TXT [CLASSES]
    <run_dir>/SET_HMI.TXT    front-panel stream (relays; not listed in CFG.TXT)
    <run_dir>/HELP.txt       the device's command list at Access Level 1 (``HELP``)
    <run_dir>/transcript.txt the login/ID exchange (redacted)
    <run_dir>/manifest.json  SHA-256 and size per file, method, skipped streams

Only ``FILE READ`` / ``FILE SHOW`` of ``CFG.TXT`` and ``SET_<class>.TXT`` (the command
policy rejects any other name) and, last, ``HELP`` are sent; nothing is written to the device.
SEL-735 meters accept ``FILE READ`` but their XMODEM sender aborts before a
cross-network ``C`` can arrive, so the 735 family uses the ``FILE SHOW`` text dump.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional

from sel_triage.core.errors import TriageError

from ..commands import SETTINGS_FILENAME

SHOW_FAMILIES = frozenset({"sel735"})
# Families whose manuals list HELP (700G, 751/751A, 851). The 351, 651 and 735 have no
# help command (their command list comes from the manual reference only).
HELP_FAMILIES = frozenset({"sel700g", "sel751", "sel851"})

# A trailing prompt frame: ``\x02\r\n=>\x03`` (or ``=>>``/``=``).
_PROMPT_FRAME = re.compile(r"\x02\s*(=>>|=>|=)\s*\x03\s*$")
_SHOW_ERRORS = {"invalid file name", "command requires more parameters"}


class FileShowError(Exception):
    """The device answered ``FILE SHOW`` with an error instead of file content."""


@dataclass(frozen=True)
class CaptureOptions:
    pause_seconds: float = 0.3
    block_timeout: float = 10.0
    start_retries: int = 15
    hmi_start_retries: int = 4
    settle_seconds: float = 8.0
    use_show: Optional[bool] = None  # None: FILE SHOW for SHOW_FAMILIES only
    capture_help: bool = True


def cfg_classes(cfg: bytes) -> List[str]:
    """Setting class codes in ``CFG.TXT`` ``[CLASSES]`` (rows ``G,"Label"`` or ``"G","Label"``)."""

    classes: List[str] = []
    in_classes = False
    for line in cfg.decode("ascii", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_classes = line.upper() == "[CLASSES]"
            continue
        if in_classes and "," in line:
            code = line.split(",", 1)[0].strip().strip('"')
            if code:
                classes.append(code)
    return classes


def extract_show_payload(raw: bytes, filename: str) -> bytes:
    """Strip the command echo and SEL STX/ETX framing from a ``FILE SHOW`` response.

    The body sits in the first ``\\x02`` ... ``\\x03`` frame; the prompt comes back in
    its own frame. Line endings are returned as CRLF, like a ``FILE READ`` copy.
    """

    text = raw.decode("ascii", errors="replace").replace("\r\n", "\n")
    text = _PROMPT_FRAME.sub("", text)
    if "\x02" in text and "\x03" in text:
        start = text.index("\x02") + 1
        end = text.index("\x03", start)
        body = text[start:end]
    else:
        body = text
    body = body.lstrip("\n")
    head = body.lstrip().split("\n", 1)[0].strip().lower()
    if head in _SHOW_ERRORS:
        raise FileShowError("FILE SHOW {0}: {1}".format(filename, head))
    return body.encode("ascii", errors="replace").replace(b"\n", b"\r\n")


def _write(run_dir: Path, name: str, data: bytes, files: Dict[str, Dict[str, Any]]) -> None:
    (run_dir / name).write_bytes(data)
    files[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def capture_settings(
    client: Any,
    run_dir: Path,
    *,
    transcript: Callable[[], bytes] = lambda: b"",
    redact: Callable[[str], str] = lambda text: text,
    options: CaptureOptions = CaptureOptions(),
    sleep: Callable[[float], None] = time.sleep,
) -> Dict[str, Any]:
    """Capture every settings stream from a logged-in client into *run_dir*.

    ``CFG.TXT`` is required (its failure fails the capture); a settings stream that
    will not transfer is skipped and listed, as SEL-Audit did. Returns the manifest.
    """

    identity = client.identity
    if identity is None:
        raise TriageError("settings capture needs a logged-in session", category="session_state", reachable=None)
    run_dir.mkdir(parents=True, exist_ok=True)
    use_show = options.use_show if options.use_show is not None else client.family in SHOW_FAMILIES
    files: Dict[str, Dict[str, Any]] = {}
    skipped: List[Dict[str, str]] = []

    _write(run_dir, "ID.txt", identity.raw_text.encode("utf-8", "replace"), files)
    _write(run_dir, "transcript.txt", redact(transcript().decode("utf-8", "replace")).encode("utf-8"), files)

    def read(name: str, start_retries: int) -> bytes:
        if use_show:
            return extract_show_payload(client.run_bytes("file_show", name), name)
        return client.read_file(
            name,
            start_retries=start_retries,
            block_timeout=options.block_timeout,
            settle_seconds=options.settle_seconds,
        )

    cfg = read("CFG.TXT", options.start_retries)
    _write(run_dir, "CFG.TXT", cfg, files)
    classes = cfg_classes(cfg)

    streams = [("set_{0}.txt".format(code), options.start_retries) for code in classes]
    if not use_show:
        streams.append(("SET_HMI.TXT", options.hmi_start_retries))
    for name, retries in streams:
        if not SETTINGS_FILENAME.fullmatch(name):
            skipped.append({"file": name, "reason": "unexpected_class_code"})
            continue
        if options.pause_seconds:
            sleep(options.pause_seconds)
        try:
            data = read(name, retries)
        except FileShowError as error:
            skipped.append({"file": name, "reason": str(error)})
            continue
        except TriageError as error:
            if error.category != "file_transfer_failed":
                raise
            skipped.append({"file": name, "reason": str(error)})
            continue
        _write(run_dir, name, data, files)

    # HELP last: a device that rejects or times out on it closes the session, and the
    # settings are already saved by then.
    if options.capture_help and client.family in HELP_FAMILIES:
        try:
            _write(run_dir, "HELP.txt", client.run_bytes("help"), files)
        except TriageError as error:
            skipped.append({"file": "HELP.txt", "reason": "{0}: {1}".format(error.category, error)})

    manifest = {
        "tool": "sel-settings-capture",
        "method": "file_show" if use_show else "file_read",
        "observed_model": identity.observed_model,
        "fid": identity.firmware_id,
        "family": client.family,
        "classes": classes,
        "files": files,
        "skipped": skipped,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


__all__ = [
    "CaptureOptions",
    "FileShowError",
    "HELP_FAMILIES",
    "SHOW_FAMILIES",
    "capture_settings",
    "cfg_classes",
    "extract_show_payload",
]
