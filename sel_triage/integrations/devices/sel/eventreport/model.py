from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class Channel:
    name: str
    quantity: str
    unit: str


@dataclass(frozen=True)
class Sample:
    index: int
    group: int
    analog: Mapping[str, float]
    raw_suffix: str
    trigger: bool


@dataclass(frozen=True)
class DigitalSignal:
    name: str
    section: str
    raw_position: int
    raw_states: tuple[str, ...]


@dataclass(frozen=True)
class EventMetadata:
    station: str
    device: str
    firmware_id: str
    event_number: int
    timestamp: str
    time_source: str
    event_type: str = ""
    location: str = ""
    shot: int | None = None
    targets: tuple[str, ...] = ()


@dataclass(frozen=True)
class EventRecord:
    source_path: Path
    source_bytes: bytes
    metadata: EventMetadata
    nominal_frequency_hz: float
    samples_per_cycle: int
    analog_channels: tuple[Channel, ...]
    samples: tuple[Sample, ...]
    digital_signals: tuple[DigitalSignal, ...] = ()
    reported_currents: Mapping[str, float] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
