"""sel-visualize: offline reports for retrieved SEL EVE / CEV event files (no device access).

Runs the vendored event-report package (ported from sel-visualizer) in-process: each input
gets ``report.html`` (self-contained interactive plots and phasors), ``analog.csv``,
``digital.csv``, ``metadata.json`` and a byte-identical ``source.eve`` / ``source.cev``.
A directory input contributes every ``.eve`` / ``.cev`` file in it. With several inputs each
gets ``<output-dir>/<file stem>/``. An existing output folder is only replaced with
``--overwrite`` and only when it holds nothing but generated artifacts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import Any, Dict, List, Tuple

from sel_triage.core.output import build_sel_envelope
from sel_triage.integrations.devices.sel.eventreport.eve_parser import EveParseError
from sel_triage.integrations.devices.sel.eventreport.exporters import export_data
from sel_triage.integrations.devices.sel.eventreport.html_renderer import render_html
from sel_triage.integrations.devices.sel.eventreport.parser import parse_event

ARTIFACTS = {"report.html", "analog.csv", "digital.csv", "metadata.json", "source.eve", "source.cev"}
EVENT_SUFFIXES = {".eve", ".cev"}
_PROVENANCE = {"source": "local-event-files", "network_access": False, "external_process": False}


class OutputCollision(ValueError):
    pass


def _ran_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def discover(inputs: List[str]) -> List[Path]:
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("at least one EVE or CEV input file is required")
    found: List[Path] = []
    for value in inputs:
        item = Path(value)
        if not item.exists():
            raise ValueError("event input does not exist: {0}".format(item))
        if item.is_dir():
            files = sorted(
                (p for p in item.iterdir() if p.is_file() and p.suffix.lower() in EVENT_SUFFIXES),
                key=lambda p: p.name.lower(),
            )
            if not files:
                raise ValueError("directory contains no EVE or CEV files: {0}".format(item))
            found.extend(files)
        elif item.suffix.lower() not in EVENT_SUFFIXES:
            raise ValueError("inputs must be EVE or CEV files")
        else:
            found.append(item)
    unique: List[Path] = []
    for path in found:
        resolved = path.resolve()
        if resolved not in unique:
            unique.append(resolved)
    return unique


def destinations(files: List[Path], output: Path) -> List[Tuple[Path, Path]]:
    if len(files) == 1:
        return [(files[0], output)]
    stems = [path.stem for path in files]
    if len(set(stems)) != len(stems):
        raise OutputCollision("multiple inputs have the same filename stem")
    return [(path, output / path.stem) for path in files]


def _prepare_output(path: Path, overwrite: bool) -> None:
    if not path.exists():
        path.mkdir(parents=True)
        return
    entries = {entry.name for entry in path.iterdir()}
    if not entries:
        return
    if not overwrite:
        raise OutputCollision("output already exists: {0}".format(path))
    unknown = entries - ARTIFACTS
    if unknown:
        raise OutputCollision(
            "refusing to overwrite a folder holding other files: {0}".format(", ".join(sorted(unknown))))
    for entry in path.iterdir():
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def run(inputs: List[str], output_dir: str, overwrite: bool = False) -> Dict[str, Any]:
    """Build a report folder per event file; one bad file does not stop the others."""

    if not isinstance(output_dir, str) or not output_dir:
        raise ValueError("output directory must be a nonempty path")
    files = discover(inputs)
    pairs = destinations(files, Path(output_dir).expanduser())
    ran_at = _ran_at()
    reports: List[str] = []
    events: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for source, destination in pairs:
        try:
            _prepare_output(destination, overwrite)
            event = parse_event(source)
            export_data(event, destination)
            report = render_html(event, destination / "report.html")
        except OutputCollision as error:
            errors.append({"category": "output_exists", "message": str(error), "input": str(source)})
            continue
        except (OSError, EveParseError, ValueError) as error:
            errors.append({"category": "event_parse_failed", "message": str(error), "input": str(source)})
            continue
        reports.append(str(report))
        meta = event.metadata
        events.append({
            "input": str(source),
            "output": str(destination),
            "station": meta.station,
            "device": meta.device,
            "firmware_id": meta.firmware_id,
            "event_number": meta.event_number,
            "timestamp": meta.timestamp,
            "event_type": meta.event_type,
            "samples_per_cycle": event.samples_per_cycle,
            "samples": len(event.samples),
            "warnings": list(event.warnings),
        })
    target = {
        "name": "sel-event-report",
        "ok": not errors,
        "partial": bool(errors) and bool(reports),
        "input_files": [str(path) for path in files],
        "reports": reports,
        "events": events,
        "errors": errors,
        "provenance": dict(_PROVENANCE),
    }
    return build_sel_envelope("sel-visualize", ran_at, [target], [], _PROVENANCE)


__all__ = ["ARTIFACTS", "OutputCollision", "destinations", "discover", "run"]
