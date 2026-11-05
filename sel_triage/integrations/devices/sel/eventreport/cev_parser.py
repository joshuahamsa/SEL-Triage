from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

from .eve_parser import EveParseError
from .model import Channel, DigitalSignal, EventMetadata, EventRecord, Sample


class CevParseError(EveParseError):
    """Raised when a raw SEL-651R-2 CEV cannot be interpreted safely."""


def parse_cev(path: Path) -> EventRecord:
    path = Path(path)
    source = path.read_bytes()
    return parse_cev_text(_decode(source), path=path, source_bytes=source)


def parse_cev_text(
    text: str,
    *,
    path: Path = Path("<memory>"),
    source_bytes: bytes | None = None,
) -> EventRecord:
    clean = text.replace("\x02", "").replace("\x03", "").replace("\r", "")
    lines = clean.splitlines()
    original = source_bytes if source_bytes is not None else text.encode("utf-8")

    firmware = _firmware(lines)
    # same CEV layout on the 651R-2 and the 651RA (live 651RA R104 reports, 2026-10-12)
    if not firmware.startswith(("SEL-651R-2-", "SEL-651RA-")):
        raise CevParseError(f"unsupported CEV relay family: {firmware}")

    date_header, date_values = _paired_record(lines, "MONTH", {"MSEC"})
    date = _record_dict(date_header, date_values, "date/time")
    event_header, event_values = _paired_record(
        lines, "REF_NUM", {"SAM/CYC_A", "SAM/CYC_D", "NUM_OF_CYC"}
    )
    event = _record_dict(event_header, event_values, "event metadata")

    analog_rate = _integer(event, "SAM/CYC_A")
    digital_rate = _integer(event, "SAM/CYC_D")
    if analog_rate != digital_rate:
        raise CevParseError(f"analog and digital sample rates differ: {analog_rate} != {digital_rate}")
    cycles = _integer(event, "NUM_OF_CYC")
    if analog_rate <= 0 or cycles <= 0:
        raise CevParseError("sample rate and cycle count must be positive")

    waveform_index, waveform_header = _waveform_header(lines)
    trigger_index = waveform_header.index("TRIG")
    if trigger_index < 1 or len(waveform_header) < trigger_index + 3:
        raise CevParseError("malformed waveform header")
    source_names = waveform_header[:trigger_index]
    channel_names = [_normalize_channel(name) for name in source_names]
    channels = tuple(Channel(name, _quantity(name), _unit(name)) for name in channel_names)
    relay_labels = waveform_header[trigger_index + 1].split()

    waveform_rows = _waveform_rows(lines, waveform_index + 1)
    expected_rows = cycles * analog_rate
    if len(waveform_rows) != expected_rows:
        raise CevParseError(f"expected {expected_rows} waveform rows, found {len(waveform_rows)}")

    samples: list[Sample] = []
    relay_words: list[str] = []
    triggers = 0
    expected_columns = trigger_index + 3
    for row_index, row in enumerate(waveform_rows):
        if len(row) != expected_columns:
            raise CevParseError(
                f"waveform row {row_index + 1} has {len(row)} columns; expected {expected_columns}"
            )
        try:
            values = [float(value) for value in row[:trigger_index]]
        except ValueError as error:
            raise CevParseError(f"invalid analog value at waveform row {row_index + 1}") from error
        marker = row[trigger_index].strip()
        relay_words.append(row[trigger_index + 1].strip())
        trigger = marker == ">"
        triggers += int(trigger)
        samples.append(
            Sample(
                index=row_index,
                group=row_index // analog_rate + 1,
                analog=dict(zip(channel_names, values)),
                raw_suffix=marker,
                trigger=trigger,
            )
        )
    if triggers != 1:
        raise CevParseError(f"expected exactly one trigger marker, found {triggers}")

    station = _setting(clean, "RID")
    device = _setting(clean, "TID")
    frequency = _number(event, "FREQ")
    if not 40 <= frequency <= 70:
        raise CevParseError(f"invalid nominal frequency: {frequency}")

    metadata = EventMetadata(
        station=station,
        device=device,
        firmware_id=firmware,
        event_number=_integer(event, "REF_NUM"),
        timestamp=(
            f"{_integer(date, 'MONTH'):02d}/{_integer(date, 'DAY'):02d}/{_integer(date, 'YEAR'):04d} "
            f"{_integer(date, 'HOUR'):02d}:{_integer(date, 'MIN'):02d}:{_integer(date, 'SEC'):02d}."
            f"{_integer(date, 'MSEC'):03d}"
        ),
        time_source="CEV event record",
        event_type=event.get("EVENT", "").strip(),
        location=event.get("LOCATION", "").strip(),
        shot=_integer(event, "SHOT") if event.get("SHOT", "").strip() else None,
        targets=tuple(event.get("TARGETS", "").split()),
    )
    return EventRecord(
        source_path=Path(path),
        source_bytes=original,
        metadata=metadata,
        nominal_frequency_hz=frequency,
        samples_per_cycle=analog_rate,
        analog_channels=channels,
        samples=tuple(samples),
        digital_signals=_decode_relay_words(relay_labels, relay_words),
        reported_currents=_reported_currents(event),
        warnings=("line checksums were not independently validated",),
    )


def _decode(source: bytes) -> str:
    try:
        return source.decode("utf-8")
    except UnicodeDecodeError:
        return source.decode("latin-1")


def _csv_record(line: str) -> list[str]:
    try:
        return next(csv.reader([line], strict=True))
    except csv.Error as error:
        raise CevParseError(f"malformed CEV CSV record: {line[:80]!r}") from error


def _firmware(lines: list[str]) -> str:
    for line in lines:
        if line.startswith('"FID='):
            row = _csv_record(line)
            return row[0].removeprefix("FID=").strip()
    raise CevParseError("missing FID")


def _paired_record(lines: list[str], first: str, required: set[str]) -> tuple[list[str], list[str]]:
    for index, line in enumerate(lines[:-1]):
        if not line.startswith(f'"{first}"'):
            continue
        header = _csv_record(line)
        if not required.issubset(header):
            continue
        values = _csv_record(lines[index + 1])
        return header, values
    raise CevParseError(f"missing {first} record")


def _record_dict(header: list[str], values: list[str], label: str) -> dict[str, str]:
    if len(header) != len(values):
        raise CevParseError(f"{label} header/value length mismatch")
    return dict(zip(header, values))


def _waveform_header(lines: list[str]) -> tuple[int, list[str]]:
    for index, line in enumerate(lines):
        if not line.startswith('"IA"'):
            continue
        row = _csv_record(line)
        if "TRIG" in row and "FREQ" in row:
            return index, row
    raise CevParseError("missing waveform header")


def _waveform_rows(lines: list[str], start: int) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in lines[start:]:
        if line.startswith('"SETTINGS"'):
            break
        if not line.strip():
            continue
        rows.append(_csv_record(line))
    return rows


def _setting(text: str, name: str) -> str:
    match = re.search(rf"^\s*{re.escape(name)}\s*:=\s*(.*?)\s*$", text, re.MULTILINE)
    if not match or not match.group(1).strip():
        raise CevParseError(f"missing {name}")
    return match.group(1).strip()


def _integer(values: dict[str, str], name: str) -> int:
    try:
        return int(values[name])
    except (KeyError, ValueError) as error:
        raise CevParseError(f"invalid {name}") from error


def _number(values: dict[str, str], name: str) -> float:
    try:
        return float(values[name])
    except (KeyError, ValueError) as error:
        raise CevParseError(f"invalid {name}") from error


def _normalize_channel(name: str) -> str:
    normalized = re.sub(r"\([^)]*\)$", "", name).strip()
    return "Freq" if normalized.upper() == "FREQ" else normalized


def _quantity(name: str) -> str:
    if name.startswith("I"):
        return "current"
    if name.startswith("V"):
        return "voltage"
    return "frequency" if name == "Freq" else "other"


def _unit(name: str) -> str:
    if name.startswith("I"):
        return "A"
    if name.startswith("V"):
        return "kV"
    return "Hz" if name == "Freq" else ""


def _reported_currents(event: dict[str, str]) -> dict[str, float]:
    headings = {"A": "IA", "B": "IB", "C": "IC", "G": "IG", "Q": "3I2"}
    try:
        return {target: float(event[source]) for target, source in headings.items()}
    except (KeyError, ValueError) as error:
        raise CevParseError("invalid reported currents") from error


def _decode_relay_words(labels: list[str], words: list[str]) -> tuple[DigitalSignal, ...]:
    expected_bits = len(labels)
    decoded: list[str] = []
    for row_index, word in enumerate(words):
        if not re.fullmatch(r"[0-9A-Fa-f]+", word):
            raise CevParseError(f"invalid relay word at waveform row {row_index + 1}")
        bits = "".join(f"{int(nibble, 16):04b}" for nibble in word)
        if len(bits) != expected_bits:
            raise CevParseError(
                f"relay-word width at waveform row {row_index + 1}: "
                f"expected {expected_bits} bits, found {len(bits)}"
            )
        decoded.append(bits)

    counts = Counter(label for label in labels if label != "*")
    signals: list[DigitalSignal] = []
    for position, label in enumerate(labels):
        if label == "*":
            continue
        unique = f"{label}__bit_{position:04d}" if counts[label] > 1 else label
        states = tuple("1" if bits[position] == "1" else "." for bits in decoded)
        signals.append(DigitalSignal(f"relay_word.{unique}", "relay_word", position, states))
    return tuple(signals)
