"""Shared record constants, keys and the S3 layout for the SEL event archive."""

from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
from typing import Dict, Iterable, List, Mapping

SCHEMA_VERSION = 1
REPORT_FORMAT = "eve"
# Bump a family's number whenever its HIS or SER parser output changes, so
# (2: SER parsed for 351/651/735/751/851 by parsers.common.parse_ser_table;
#  sel751 3: the 751A HIS layout without REF/LOCAT)
# sel-event-reparse and downstream loaders know newer rows win.
PARSER_VERSIONS: Dict[str, int] = {
    "sel351": 2,
    "sel651": 2,
    "sel700g": 1,
    "sel735": 2,
    "sel751": 3,
    "sel851": 2,
}


# Bump when the event-report summary (event_reports.jsonl) changes; sel-event-reparse
# re-summarizes archived reports whose rows carry an older version.
REPORT_PARSER_VERSION = 2  # 2: ER-triggered EVE (trigger only in the digital table); CEV reports
# Bump when the BRE parsers or breaker.jsonl rows change; sel-event-reparse re-reads bre.txt.
BREAKER_PARSER_VERSION = 1


def device_key(name: str) -> str:
    """Return a stable archive key for an inventory device name."""

    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
    return "{0}-{1}".format(slug, digest)


def new_run_id(now: datetime) -> str:
    stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "{0}-{1}".format(stamp, secrets.token_hex(3))


def iso_utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_key(prefix: str, device_key: str, run_id: str, name: str) -> str:
    return "{0}/raw/{1}/{2}/{3}".format(prefix, device_key, run_id, name)


def normalized_key(prefix: str, run_id: str, name: str) -> str:
    return "{0}/normalized/{1}/{2}".format(prefix, run_id, name)


# The SEL-651RA has no EVE command (its manual lists CEV only): its reports are fetched
# with CEV n and archived as .cev.
_REPORT_FORMAT_BY_MODEL = {"SEL-651RA": "cev"}


def report_format(observed_model) -> str:
    return _REPORT_FORMAT_BY_MODEL.get((observed_model or "").upper(), REPORT_FORMAT)


def report_file_name(device_ts: str, fmt: str = REPORT_FORMAT) -> str:
    return "event-{0}.{1}".format(re.sub(r"[^0-9T]", "", device_ts), fmt)


def to_jsonl(rows: Iterable[Mapping]) -> bytes:
    return b"".join(
        (json.dumps(row, sort_keys=True) + "\n").encode("utf-8") for row in rows
    )


def from_jsonl(data: bytes) -> List[Dict]:
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]
