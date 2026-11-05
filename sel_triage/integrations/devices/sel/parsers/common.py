"""Small helpers that retain any source lines they cannot parse safely."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Match, Pattern
from typing import Sequence, Set, Tuple


SourceLine = Tuple[int, str]
ScalarConverter = Callable[[Match[str]], Any]
RowBuilder = Callable[[Match[str]], Dict[str, Any]]


def nonempty_lines(text: str) -> List[SourceLine]:
    """Return indexed nonempty lines, retaining their visible formatting."""

    return [
        (index, line.rstrip("\r"))
        for index, line in enumerate(text.splitlines())
        if line.strip()
    ]


def parse_labeled_scalars(
    lines: Sequence[SourceLine],
    fields: Mapping[str, Tuple[Pattern[str], ScalarConverter]],
) -> Tuple[Dict[str, Any], Set[int]]:
    """Parse scalar lines only when their complete label pattern matches."""

    values: Dict[str, Any] = {}
    consumed: Set[int] = set()
    for index, line in lines:
        candidate = line.strip()
        for key, (pattern, convert) in fields.items():
            if key in values:
                continue
            match = pattern.fullmatch(candidate)
            if match is None:
                continue
            try:
                values[key] = convert(match)
            except (TypeError, ValueError):
                # A labeled but malformed value remains available to callers as
                # an unparsed line; parsers do not guess a replacement value.
                continue
            consumed.add(index)
            break
    return values, consumed


def parse_labeled_table(
    lines: Sequence[SourceLine],
    header_pattern: Pattern[str],
    row_pattern: Pattern[str],
    build_row: RowBuilder,
) -> Tuple[List[Dict[str, Any]], Set[int]]:
    """Parse consecutive rows only after an explicit labeled header."""

    for position, (header_index, line) in enumerate(lines):
        if header_pattern.fullmatch(line.strip()) is None:
            continue

        rows: List[Dict[str, Any]] = []
        consumed = {header_index}
        for row_index, row_line in lines[position + 1 :]:
            match = row_pattern.fullmatch(row_line.strip())
            if match is None:
                break
            try:
                row = build_row(match)
            except (TypeError, ValueError):
                break
            rows.append(row)
            consumed.add(row_index)
        return rows, consumed
    return [], set()


def remaining_lines(
    lines: Iterable[SourceLine], consumed: Set[int]
) -> List[str]:
    """Return every nonempty source line not claimed by a parser."""

    return [line for index, line in lines if index not in consumed]


def labeled_value(label: str) -> Pattern[str]:
    """Build an exact case-insensitive ``Label: value`` pattern."""

    return re.compile(
        r"{0}\s*:\s*(?P<value>.+)".format(re.escape(label)),
        re.IGNORECASE,
    )


__all__ = [
    "labeled_value",
    "nonempty_lines",
    "parse_labeled_scalars",
    "parse_labeled_table",
    "remaining_lines",
]


# --- SEL column tables -------------------------------------------------------
#
# SEL MET/STA/BRE/TAR print a row of column names followed by value rows with
# an optional leading label ("Mag (A pri.)  48.0  50.3 ..."). Verified on live
# SEL-700GT and SEL-735 output (2026-09-25).

NUMBER = re.compile(r"^[-+]?\d+(?:\.\d+)?$")
UPPER_HEADER_TOKEN = re.compile(r"^[+-]?[0-9A-Z_.]*[A-Z][0-9A-Z_.]*$")
PF_DIRECTIONS = frozenset(("LAG", "LEAD"))


def table_value(token: str) -> Any:
    """Convert a numeric token to int or float; keep anything else as text."""

    if NUMBER.match(token):
        number = float(token)
        return int(number) if "." not in token else number
    return token


def column_tables(
    lines: Sequence[SourceLine], header_token: Pattern[str] = UPPER_HEADER_TOKEN
) -> List[Dict[str, Any]]:
    """Group lines into column tables without consuming any of them.

    Each table is {"title", "columns", "header_index", "rows"}, where rows are
    (label, values, line_index) and label is "" for unlabeled value rows. The
    nearest preceding non-table line becomes the title. Parsers mark lines
    consumed with ``use_row`` only for tables they understand, so text that
    merely looks like a header stays in unparsed_lines.
    """

    def is_header(tokens: List[str]) -> bool:
        return (
            bool(tokens)
            and all(header_token.match(token) for token in tokens)
            and not all(NUMBER.match(token) for token in tokens)
        )

    tables: List[Dict[str, Any]] = []
    current: Any = None
    title = ""
    for index, line in lines:
        tokens = line.split()
        if current is not None:
            width = len(current["columns"])
            if len(tokens) == width and (
                all(NUMBER.match(tok) for tok in tokens)
                or not is_header(tokens)
                or all(tok in PF_DIRECTIONS for tok in tokens)
                or not current["rows"]
            ):
                current["rows"].append(("", [table_value(tok) for tok in tokens], index))
                continue
            if (
                len(tokens) > width
                and all(NUMBER.match(tok) for tok in tokens[-width:])
                and not NUMBER.match(tokens[-width - 1])
            ):
                label = " ".join(tokens[:-width])
                current["rows"].append((label, [table_value(tok) for tok in tokens[-width:]], index))
                continue
        if is_header(tokens):
            current = {"title": title, "columns": tokens, "header_index": index, "rows": []}
            tables.append(current)
            continue
        current = None
        title = line.strip()
    return tables


def use_row(consumed: Set[int], table: Mapping[str, Any], row_index: int) -> None:
    """Mark a table row and its header line as parsed."""

    consumed.add(row_index)
    consumed.add(table["header_index"])


def parse_capture_only(text: str) -> Dict[str, Any]:
    """Keep output from a model not yet seen live, without guessing its format.

    Diagnostics report sections marked ``capture_only`` as saved evidence
    rather than as missing measurements.
    """

    lines = nonempty_lines(text)
    return {"capture_only": True, "unparsed_lines": remaining_lines(lines, set())}


# SHO output ("KEY := value", several per line in fixed columns). A key sits
# at the start of a line or after a space; the value runs to the next key.
_SETTING_KEY = re.compile(r"(?:^|(?<= ))([A-Z0-9][A-Z0-9_]*) *:=")
# Older relays (SEL-351, SEL-651) print ``KEY =value``. A key there needs two characters
# so SHO R help text such as ``I=Integer, F=Float`` is not read as settings (SEL-Audit rule).
_EQUALS_SETTING_KEY = re.compile(r"(?:^|(?<= ))([A-Z0-9][A-Z0-9_]+) *=")
_SETTINGS_ECHO = re.compile(r"^(?:=>)?SHO\b")
_SETTINGS_GROUP = re.compile(r"^Group (?P<value>\d+)$")


def parse_settings(text: str) -> Dict[str, Any]:
    """Parse ``SHO`` settings output in the ``KEY := value`` or ``KEY =value`` dialect.

    The dialect is picked per text: any ``:=`` selects the colon form (newer relays);
    otherwise ``KEY =value`` (SEL-351 / SEL-651), as SEL-Audit's ``sho_convert`` does.

    Indented lines without a key continue the value above them (long SELogic
    equations wrap). Column-0 lines without ``=`` that are not sentences are
    section headings; ``Group N`` also reports the displayed group. Prose
    (help text with ``=`` or ending in a period) and command echoes are left
    in ``unparsed_lines``.
    """

    key_pattern = _SETTING_KEY if ":=" in text else _EQUALS_SETTING_KEY
    lines = nonempty_lines(text)
    settings: Dict[str, str] = {}
    sections: List[str] = []
    consumed: Set[int] = set()
    values: Dict[str, Any] = {}
    current: Any = None
    for index, line in lines:
        keys = list(key_pattern.finditer(line))
        if keys:
            for position, match in enumerate(keys):
                end = keys[position + 1].start() if position + 1 < len(keys) else len(line)
                current = match.group(1)
                settings[current] = line[match.end():end].strip()
            consumed.add(index)
            continue
        stripped = line.strip()
        if line[0] == " ":
            if current is not None:
                settings[current] = "{0} {1}".format(settings[current], stripped).strip()
                consumed.add(index)
            continue
        current = None
        if "=" in stripped or stripped.endswith(".") or _SETTINGS_ECHO.match(stripped):
            continue
        group = _SETTINGS_GROUP.match(stripped)
        if group is not None:
            values["group"] = int(group.group("value"))
        sections.append(stripped)
        consumed.add(index)
    values["settings"] = settings
    values["sections"] = sections
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


# --- SER (sequential events recorder) ----------------------------------------
#
# One table layout across the fleet (live 351/351A/351S, 651R-2, 651RA, 700G, 735,
# 751/751A and 851 captures, 2026-10-12): "#  DATE  TIME  ELEMENT  STATE", rows
# numbered newest = 1, two- or four-digit years, states Asserted/Deasserted or
# PICKUP/DROPOUT, and message rows without a state ("Power loss", "Relay Settings
# Changed", "Going to sleep"). Message rows keep the text as the element and state
# "Event" (a downstream SER table needs both) plus a category in ``event``.

_SER_TABLE_HEADER = re.compile(r"^#\s+date\s+time\s+element\s+state$", re.IGNORECASE)
_SER_TABLE_ROW = re.compile(
    r"^(?P<number>\d+)\s+(?P<month>\d{1,2})/(?P<day>\d{1,2})/(?P<year>\d{2}|\d{4})\s+"
    r"(?P<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<rest>\S.*?)\s*$"
)
_SER_STATES = {"ASSERTED": "Asserted", "DEASSERTED": "Deasserted", "PICKUP": "PICKUP", "DROPOUT": "DROPOUT"}
_SER_EVENTS = (
    (re.compile(r"time changed|clock (?:set|changed)", re.IGNORECASE), "time_changed"),
    (re.compile(r"breaker\s+closed?", re.IGNORECASE), "breaker_closed"),
    (re.compile(r"breaker\s+open", re.IGNORECASE), "breaker_open"),
    (re.compile(r"control\s+local", re.IGNORECASE), "control_local"),
    (re.compile(r"control\s+remote", re.IGNORECASE), "control_remote"),
    (re.compile(r"power loss|power lost", re.IGNORECASE), "power_loss"),
    (re.compile(r"power restored", re.IGNORECASE), "power_restored"),
    (re.compile(r"settings? changed", re.IGNORECASE), "settings_changed"),
    (re.compile(r"powered up|power[- ]?up", re.IGNORECASE), "powered_up"),
    (re.compile(r"restart", re.IGNORECASE), "restarted"),
    (re.compile(r"going to sleep|sleep", re.IGNORECASE), "sleep"),
    (re.compile(r"\benabled\b", re.IGNORECASE), "enabled"),
    (re.compile(r"\bdisabled\b", re.IGNORECASE), "disabled"),
    (re.compile(r"archive cleared|ser cleared|cleared", re.IGNORECASE), "archive_cleared"),
    (re.compile(r"group", re.IGNORECASE), "group_change"),
)
_SER_BANNER = re.compile(
    r"Date:\s*(?P<a>\d{1,2})/(?P<b>\d{1,2})/(?P<c>\d{2,4})\s+Time:\s*(?P<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)"
)
_SER_TIME_SOURCE = re.compile(r"Time Source:\s*(?P<value>\S+)", re.IGNORECASE)
_SER_HEADER_LINE = re.compile(r"^(?:=>)?\s*SER\b|^=>+$|FID\s*=|CID\s*=|Serial (?:No|Number)", re.IGNORECASE)


def _ser_year(text: str) -> str:
    return text if len(text) == 4 else "20" + text


def ser_event_category(message: str):
    for pattern, category in _SER_EVENTS:
        if pattern.search(message):
            return category
    return "other"


def parse_ser_table(text: str) -> Dict[str, Any]:
    """Parse SEL ``SER`` output (any family): records oldest first, element summary, clock."""

    lines = nonempty_lines(text)
    consumed: Set[int] = set()
    records: List[Dict[str, Any]] = []
    values: Dict[str, Any] = {}
    in_table = False
    after_banner = False
    for index, line in lines:
        stripped = line.strip()
        banner = _SER_BANNER.search(line)
        if banner is not None and not in_table:
            values["clock"] = "{0}-{1:0>2}-{2:0>2}T{3}".format(
                _ser_year(banner.group("c")), banner.group("a"), banner.group("b"), banner.group("time"))
            source = _SER_TIME_SOURCE.search(line)
            if source is not None:
                values["time_source"] = source.group("value")
            consumed.add(index)
            after_banner = True
            continue
        if after_banner and not in_table:
            # the line under the banner names the relay (and may carry Time Source)
            source = _SER_TIME_SOURCE.search(line)
            if source is not None:
                values["time_source"] = source.group("value")
            consumed.add(index)
            after_banner = False
            continue
        if _SER_TABLE_HEADER.match(stripped):
            in_table = True
            consumed.add(index)
            continue
        if _SER_HEADER_LINE.search(stripped):
            consumed.add(index)
            continue
        if not in_table:
            continue
        match = _SER_TABLE_ROW.match(stripped)
        if match is None:
            continue
        rest = match.group("rest")
        tokens = rest.split()
        state = _SER_STATES.get(tokens[-1].upper()) if len(tokens) > 1 else None
        if state is not None:
            element, event = " ".join(tokens[:-1]), None
        else:
            element, state, event = " ".join(tokens), "Event", ser_event_category(rest)
        records.append({
            "number": int(match.group("number")),
            "timestamp": "{0}-{1:0>2}-{2:0>2}T{3}".format(
                _ser_year(match.group("year")), match.group("month"), match.group("day"), match.group("time")),
            "element": element,
            "state": state,
            "event": event,
        })
        consumed.add(index)
    records.sort(key=lambda record: -record["number"])
    summary: Dict[str, Dict[str, Any]] = {}
    for record in records:
        entry = summary.setdefault(record["element"], {"asserted": 0, "deasserted": 0,
                                                       "first": record["timestamp"], "last": None})
        key = record["state"].lower()
        entry[key] = entry.get(key, 0) + 1
        entry["last"] = record["timestamp"]
    values["records"] = records
    values["element_summary"] = summary
    values["unparsed_lines"] = remaining_lines(lines, consumed)
    return values


__all__ += ["parse_ser_table", "ser_event_category"]
