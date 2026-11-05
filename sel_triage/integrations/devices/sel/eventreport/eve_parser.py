from __future__ import annotations

import re
from dataclasses import replace
import statistics
from pathlib import Path

from .model import Channel, DigitalSignal, EventMetadata, EventRecord, Sample


class EveParseError(ValueError):
    """Raised when an EVE report cannot be interpreted safely."""


NUMBER = re.compile(r"[-+]?\d+(?:\.\d+)?")


def parse_eve(path: Path) -> EventRecord:
    path = Path(path)
    return parse_eve_bytes(path.read_bytes(), path)


def parse_eve_bytes(source: bytes, path: Path = Path("event.eve")) -> EventRecord:
    """Parse EVE report bytes already in memory (e.g. an archived ``EVE n`` response)."""

    text = _decode(source).replace("\x02", "").replace("\x03", "")
    lines = text.splitlines()
    metadata = _parse_metadata(lines)
    channels, samples, samples_per_cycle = _parse_analog(lines)
    trigger_count = sum(sample.trigger for sample in samples)
    inferred = False
    if trigger_count == 0:
        # ER-triggered reports (seen live on a 651R-2 R409) mark the trigger only in the
        # digital tables; take the trigger sample from there.
        index = _digital_trigger_index(lines)
        if index is not None and index < len(samples):
            samples[index] = replace(samples[index], trigger=True)
            trigger_count, inferred = 1, True
    if trigger_count != 1:
        raise EveParseError(f"expected exactly one trigger marker, found {trigger_count}")
    frequency = _nominal_frequency(samples)
    digital_signals, warnings = _parse_digital_tables(lines, len(samples))
    if inferred:
        warnings = list(warnings) + ["trigger taken from the digital table (no analog trigger marker)"]
    return EventRecord(
        source_path=path,
        source_bytes=source,
        metadata=metadata,
        nominal_frequency_hz=frequency,
        samples_per_cycle=samples_per_cycle,
        analog_channels=tuple(channels),
        samples=tuple(samples),
        digital_signals=tuple(digital_signals),
        reported_currents=_parse_reported_currents(lines),
        warnings=tuple(warnings),
    )


def _decode(source: bytes) -> str:
    try:
        return source.decode("utf-8")
    except UnicodeDecodeError:
        return source.decode("latin-1")


def _match(lines: list[str], pattern: str, label: str) -> re.Match[str]:
    rx = re.compile(pattern)
    for line in lines:
        match = rx.search(line)
        if match:
            return match
    raise EveParseError(f"missing {label}")


def _parse_metadata(lines: list[str]) -> EventMetadata:
    dated = _match(lines, r"^(.*?)\s+Date:\s*(\S+)\s+Time:\s*(\S+)", "event timestamp")
    timed = _match(lines, r"^(.*?)\s+Time Source:\s*(.+?)\s*$", "time source")
    firmware = _match(lines, r"\bFID=([^\s,\"]+)", "firmware ID").group(1)
    number = int(_match(lines, r"Event Number\s*=\s*(\d+)", "event number").group(1))
    event_line = next((line for line in lines if line.startswith("Event:")), "")
    event_match = re.search(r"Event:\s*(.*?)\s+Location:\s*(.*?)\s+Shot:\s*(\d+)", event_line)
    targets_line = next((line for line in lines if line.startswith("Targets:")), "")
    return EventMetadata(
        station=dated.group(1).strip(),
        device=timed.group(1).strip(),
        firmware_id=firmware,
        event_number=number,
        timestamp=f"{dated.group(2)} {dated.group(3)}",
        time_source=timed.group(2).strip(),
        event_type=event_match.group(1).strip() if event_match else "",
        location=event_match.group(2).strip() if event_match else "",
        shot=int(event_match.group(3)) if event_match else None,
        targets=tuple(targets_line.removeprefix("Targets:").split()),
    )


def _parse_analog(lines: list[str]) -> tuple[list[Channel], list[Sample], int]:
    header_index = next(
        (i for i, line in enumerate(lines) if re.match(r"^\s*IA\s+IB\s+IC\s+IG\b", line)),
        None,
    )
    if header_index is None:
        raise EveParseError("missing analog header")
    tokens = lines[header_index].split()
    try:
        freq_index = tokens.index("Freq")
    except ValueError as error:
        raise EveParseError("analog header has no Freq channel") from error
    names = tokens[: freq_index + 1]
    channels = [Channel(name, _quantity(name), _unit(name)) for name in names]
    samples: list[Sample] = []
    group_lengths: list[int] = []
    current_group: int | None = None
    current_length = 0
    for line in lines[header_index + 1 :]:
        if line.startswith("Protection and Control Elements"):
            break
        group_match = re.fullmatch(r"\[(\d+)\]", line.strip())
        if group_match:
            if current_group is not None:
                group_lengths.append(current_length)
            current_group = int(group_match.group(1))
            current_length = 0
            continue
        if current_group is None or not line.strip():
            continue
        matches = list(NUMBER.finditer(line))
        if len(matches) < len(names):
            raise EveParseError(f"malformed analog row in group {current_group}: {line!r}")
        values = [float(match.group()) for match in matches[: len(names)]]
        suffix = line[matches[len(names) - 1].end() :]
        samples.append(
            Sample(
                index=len(samples),
                group=current_group,
                analog=dict(zip(names, values)),
                raw_suffix=suffix,
                trigger=">" in suffix,
            )
        )
        current_length += 1
    if current_group is not None:
        group_lengths.append(current_length)
    if not samples:
        raise EveParseError("missing waveform data")
    if not group_lengths or any(length != group_lengths[0] for length in group_lengths):
        raise EveParseError("inconsistent samples per cycle")
    return channels, samples, group_lengths[0]


def _quantity(name: str) -> str:
    if name.startswith("I"):
        return "current"
    if name.startswith("V"):
        return "voltage"
    return "frequency" if name == "Freq" else "other"


def _unit(name: str) -> str:
    return "A" if name.startswith("I") else "kV" if name.startswith("V") else "Hz" if name == "Freq" else ""


def _nominal_frequency(samples: list[Sample]) -> float:
    values = [sample.analog["Freq"] for sample in samples]
    result = round(statistics.median(values), 2)
    if not 40 <= result <= 70:
        raise EveParseError(f"invalid nominal frequency: {result}")
    return result


def _parse_reported_currents(lines: list[str]) -> dict[str, float]:
    line = next((line for line in lines if line.startswith("Currents (A Pri), ABCGQ:")), "")
    values = [float(value) for value in NUMBER.findall(line.split(":", 1)[-1])]
    return dict(zip(("A", "B", "C", "G", "Q"), values)) if len(values) == 5 else {}


def _digital_trigger_index(lines: list[str]) -> int | None:
    """Sample index of the first ``>`` row in the first digital table, if any."""

    try:
        start = next(i for i, line in enumerate(lines) if line == "Protection and Control Elements")
    except StopIteration:
        return None
    row = 0
    started = False
    for line in lines[start + 1:]:
        if line.startswith(("Mirrored Bits", "Event:")):
            break
        if re.fullmatch(r"\[\d+\]", line.strip()):
            started = True
            continue
        if not started or not line.strip():
            continue
        if line.rstrip().endswith(">"):
            return row
        row += 1
    return None


def _parse_digital_tables(lines: list[str], sample_count: int) -> tuple[list[DigitalSignal], list[str]]:
    boundaries = [i for i, line in enumerate(lines) if line in {
        "Protection and Control Elements",
        "Mirrored Bits, Communication and Automation Elements",
    }]
    signals: list[DigitalSignal] = []
    warnings: list[str] = []
    for boundary_index, start in enumerate(boundaries):
        end = boundaries[boundary_index + 1] if boundary_index + 1 < len(boundaries) else next(
            (i for i in range(start + 1, len(lines)) if lines[i].startswith("Event:")), len(lines)
        )
        section = re.sub(r"[^a-z0-9]+", "_", lines[start].lower()).strip("_")
        first_group = next((i for i in range(start + 1, end) if re.fullmatch(r"\[1\]", lines[i].strip())), None)
        if first_group is None:
            continue
        header = [line for line in lines[start + 1 : first_group] if line.strip()]
        state_rows: list[str] = []
        for line in lines[first_group:end]:
            if re.fullmatch(r"\[\d+\]", line.strip()) or not line.strip():
                continue
            state_rows.append(line.rstrip(">"))
        if not state_rows:
            continue
        state_rows = state_rows[:sample_count]
        width = max([len(line) for line in header + state_rows], default=0)
        for position in range(width):
            states = tuple(line[position] if position < len(line) else " " for line in state_rows)
            if not any(char.strip() for char in states):
                continue
            label = "".join(line[position] if position < len(line) else " " for line in header).strip().replace(" ", "")
            if not label:
                label = f"raw_{position:03d}"
                warnings.append(f"Ambiguous digital label at {section} position {position}")
            if len(states) < sample_count:
                states += (" ",) * (sample_count - len(states))
                warnings.append(f"Digital signal {section}.{label} has missing samples")
            signals.append(DigitalSignal(f"{section}.{label}", section, position, states))
    return signals, warnings
