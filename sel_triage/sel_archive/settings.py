"""Read the ``selEventArchive`` config section.

``store`` picks where sweeps go: ``s3`` (``bucket`` required) or ``local`` (``localDir``,
default ``~/Library/Application Support/sel-triage/sel-events``; same layout on disk, no AWS). Without a ``store`` key it is ``s3`` when a
bucket is set, else ``local``.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from ..core.evidence import default_evidence_root

DEFAULTS: Dict[str, Any] = {
    "prefix": "sel_events",
    "eventsPerRun": 10,
    "eventReportFamilies": ["sel651", "sel700g"],
    "staleNotifyDays": 5,
    "unreachableStopAfter": 5,
    "maxSitesParallel": 8,
    "readTimeoutSeconds": 60,
}
_POSITIVE_INTS = ("eventsPerRun", "staleNotifyDays", "unreachableStopAfter", "maxSitesParallel")


def default_local_dir() -> Path:
    return default_evidence_root().parent / "sel-events"


@dataclass(frozen=True)
class ArchiveSettings:
    bucket: Optional[str]
    prefix: str
    profile: Optional[str]
    events_per_run: int
    event_report_families: Tuple[str, ...]
    stale_notify_days: int
    unreachable_stop_after: int
    max_sites_parallel: int
    read_timeout_seconds: float
    store: str = "s3"
    local_dir: Optional[Path] = None


def archive_settings(config: dict) -> ArchiveSettings:
    section = config.get("selEventArchive", {})
    if not isinstance(section, dict):
        raise ValueError("selEventArchive must be an object")
    values = dict(DEFAULTS)
    values.update(section)
    bucket = values.get("bucket")
    has_bucket = isinstance(bucket, str) and bool(bucket.strip())
    store = values.get("store") or ("s3" if has_bucket else "local")
    if store not in ("s3", "local"):
        raise ValueError("selEventArchive.store must be 's3' or 'local'")
    if store == "s3" and not has_bucket:
        raise ValueError("selEventArchive.bucket is required when store is 's3'")
    local_dir = Path(values.get("localDir") or default_local_dir()).expanduser() if store == "local" else None
    prefix = values["prefix"]
    if not isinstance(prefix, str) or not prefix or prefix.startswith("/") or prefix.endswith("/"):
        raise ValueError("selEventArchive.prefix must be a non-empty path without leading or trailing '/'")
    for name in _POSITIVE_INTS:
        value = values[name]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("selEventArchive.{0} must be a positive integer".format(name))
    families = values["eventReportFamilies"]
    if not isinstance(families, list) or not all(isinstance(f, str) for f in families):
        raise ValueError("selEventArchive.eventReportFamilies must be a list of family names")
    timeout = values["readTimeoutSeconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
        raise ValueError("selEventArchive.readTimeoutSeconds must be in (0, 300]")
    profile = values.get("profile")
    return ArchiveSettings(
        bucket=bucket if has_bucket else None,
        prefix=prefix,
        profile=profile,
        events_per_run=values["eventsPerRun"],
        event_report_families=tuple(families),
        stale_notify_days=values["staleNotifyDays"],
        unreachable_stop_after=values["unreachableStopAfter"],
        max_sites_parallel=values["maxSitesParallel"],
        read_timeout_seconds=float(timeout),
        store=store,
        local_dir=local_dir,
    )
