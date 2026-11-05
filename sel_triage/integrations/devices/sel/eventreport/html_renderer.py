from __future__ import annotations

import json
from pathlib import Path

from .analysis import sample_times_ms
from .exporters import metadata_dict
from .model import EventRecord


def _report_payload(event: EventRecord) -> dict:
    times = sample_times_ms(event)
    return {
        "metadata": metadata_dict(event),
        "channels": [
            {"name": channel.name, "quantity": channel.quantity, "unit": channel.unit}
            for channel in event.analog_channels
        ],
        "samples": [
            {"index": sample.index, "time": time_ms, "trigger": sample.trigger, "analog": dict(sample.analog)}
            for sample, time_ms in zip(event.samples, times)
        ],
        "digital": [
            {"name": signal.name, "states": list(signal.raw_states)} for signal in event.digital_signals
        ],
    }


def render_html(event: EventRecord, output_path: Path) -> Path:
    template = Path(__file__).with_name("report_template.html").read_text(encoding="utf-8")
    payload = json.dumps(_report_payload(event), separators=(",", ":"), ensure_ascii=True).replace("</", "<\\/")
    output_path.write_text(template.replace("__EVENT_DATA__", payload), encoding="utf-8")
    return output_path
