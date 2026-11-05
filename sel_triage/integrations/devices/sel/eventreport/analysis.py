from __future__ import annotations

from dataclasses import dataclass
import cmath
import math

from .model import EventRecord


@dataclass(frozen=True)
class Phasor:
    rms: float
    angle_degrees: float


@dataclass(frozen=True)
class DigitalTransition:
    signal: str
    time_ms: float
    asserted: bool
    raw_state: str


def sample_times_ms(event: EventRecord) -> tuple[float, ...]:
    trigger = next(sample.index for sample in event.samples if sample.trigger)
    interval_ms = 1000.0 / (event.nominal_frequency_hz * event.samples_per_cycle)
    return tuple((sample.index - trigger) * interval_ms for sample in event.samples)


def phasor_at(event: EventRecord, channel: str, sample_index: int) -> Phasor | None:
    count = event.samples_per_cycle
    start = sample_index - count + 1
    if start < 0 or sample_index >= len(event.samples):
        return None
    values = [event.samples[i].analog[channel] for i in range(start, sample_index + 1)]
    coefficient = sum(value * cmath.exp(-2j * math.pi * k / count) for k, value in enumerate(values))
    peak = 2.0 * abs(coefficient) / count
    return Phasor(peak / math.sqrt(2.0), math.degrees(cmath.phase(coefficient)))


def is_asserted(raw_state: str) -> bool | None:
    if raw_state == ".":
        return False
    if raw_state.strip():
        return True
    return None


def digital_transitions(event: EventRecord) -> tuple[DigitalTransition, ...]:
    times = sample_times_ms(event)
    output: list[DigitalTransition] = []
    for signal in event.digital_signals:
        previous: bool | None = False
        for time_ms, raw in zip(times, signal.raw_states):
            state = is_asserted(raw)
            if state is not None and state != previous:
                output.append(DigitalTransition(signal.name, time_ms, state, raw))
                previous = state
    return tuple(output)
