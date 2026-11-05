from __future__ import annotations

from dataclasses import asdict, dataclass
import csv
import hashlib
import json
from pathlib import Path

from .analysis import digital_transitions, is_asserted, sample_times_ms
from .model import EventRecord


@dataclass(frozen=True)
class ExportManifest:
    analog_csv: Path
    digital_csv: Path
    metadata_json: Path
    source_event: Path


def metadata_dict(event: EventRecord) -> dict:
    times = sample_times_ms(event)
    return {
        "schema_version": 1,
        **asdict(event.metadata),
        "nominal_frequency_hz": event.nominal_frequency_hz,
        "samples_per_cycle": event.samples_per_cycle,
        "sample_count": len(event.samples),
        "time_start_ms": times[0],
        "time_end_ms": times[-1],
        "analog_channels": [asdict(channel) for channel in event.analog_channels],
        "digital_signals": [signal.name for signal in event.digital_signals],
        "reported_currents": dict(event.reported_currents),
        "warnings": list(event.warnings),
        "transitions": [asdict(item) for item in digital_transitions(event)],
        "source_sha256": hashlib.sha256(event.source_bytes).hexdigest(),
    }


def export_data(event: EventRecord, output_dir: Path) -> ExportManifest:
    output_dir.mkdir(parents=True, exist_ok=True)
    times = sample_times_ms(event)
    analog_path = output_dir / "analog.csv"
    names = [channel.name for channel in event.analog_channels]
    with analog_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_index", "time_ms", "trigger", *names])
        writer.writeheader()
        for sample, time_ms in zip(event.samples, times):
            writer.writerow({
                "sample_index": sample.index,
                "time_ms": f"{time_ms:.9f}",
                "trigger": int(sample.trigger),
                **sample.analog,
            })
    digital_path = output_dir / "digital.csv"
    with digital_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_index", "time_ms", "signal", "state", "raw_state"])
        writer.writeheader()
        for signal in event.digital_signals:
            for sample, time_ms, raw in zip(event.samples, times, signal.raw_states):
                state = is_asserted(raw)
                writer.writerow({
                    "sample_index": sample.index,
                    "time_ms": f"{time_ms:.9f}",
                    "signal": signal.name,
                    "state": "" if state is None else int(state),
                    "raw_state": raw,
                })
    metadata_path = output_dir / "metadata.json"
    metadata_path.write_text(json.dumps(metadata_dict(event), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    source_suffix = ".cev" if event.source_path.suffix.lower() == ".cev" else ".eve"
    source_path = output_dir / f"source{source_suffix}"
    source_path.write_bytes(event.source_bytes)
    return ExportManifest(analog_path, digital_path, metadata_path, source_path)
