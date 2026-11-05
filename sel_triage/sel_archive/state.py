"""Local sweep state: per-device progress and archived event reports."""

from contextlib import contextmanager
import fcntl
import os
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import FrozenSet, Iterable, Iterator, Optional, Tuple, Union

from ..core.evidence import default_evidence_root

SCHEMA_VERSION = 1
_V1 = """
CREATE TABLE device_state (
    device_key TEXT PRIMARY KEY,
    last_success_at TEXT,
    newest_ser_ts TEXT,
    newest_his_ts TEXT
);
CREATE TABLE archived_reports (
    device_key TEXT NOT NULL,
    device_ts TEXT NOT NULL,
    format TEXT NOT NULL,
    s3_key TEXT NOT NULL,
    PRIMARY KEY (device_key, device_ts, format)
);
"""
MIGRATIONS = (_V1,)


def default_state_path() -> Path:
    return default_evidence_root().parent / "sel-events.sqlite"


def _prepare_file(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.close(os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600))
    os.chmod(str(path), 0o600)


def _migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > len(MIGRATIONS):
        raise ValueError("sel-events state schema {0} is newer than this tool".format(version))
    for number, sql in enumerate(MIGRATIONS[version:], start=version + 1):
        conn.executescript(
            "BEGIN;\n{0}\nPRAGMA user_version = {1};\nCOMMIT;".format(sql, number)
        )


def open_state(path: Union[str, Path]) -> sqlite3.Connection:
    if str(path) != ":memory:":
        _prepare_file(Path(path))
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    _migrate(conn)
    return conn


@dataclass(frozen=True)
class DevicePrior:
    newest_ser_ts: Optional[str] = None
    newest_his_ts: Optional[str] = None
    archived: FrozenSet[Tuple[str, str]] = frozenset()


def _newer(stored: Optional[str], incoming: Optional[str]) -> Optional[str]:
    if stored is None:
        return incoming
    if incoming is None:
        return stored
    return max(stored, incoming)


class SweepState:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def prior(self, device_key: str) -> DevicePrior:
        row = self.conn.execute(
            "SELECT newest_ser_ts, newest_his_ts FROM device_state WHERE device_key = ?",
            (device_key,),
        ).fetchone()
        archived = frozenset(
            (r["device_ts"], r["format"])
            for r in self.conn.execute(
                "SELECT device_ts, format FROM archived_reports WHERE device_key = ?",
                (device_key,),
            )
        )
        if row is None:
            return DevicePrior(archived=archived)
        return DevicePrior(row["newest_ser_ts"], row["newest_his_ts"], archived)

    def last_success(self, device_key: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT last_success_at FROM device_state WHERE device_key = ?", (device_key,)
        ).fetchone()
        return None if row is None else row["last_success_at"]

    def latest_success_any(self) -> Optional[str]:
        return self.conn.execute("SELECT MAX(last_success_at) FROM device_state").fetchone()[0]

    def record(
        self,
        device_key: str,
        success_at: str,
        newest_ser_ts: Optional[str],
        newest_his_ts: Optional[str],
        reports: Iterable[Tuple[str, str, str]],
    ) -> None:
        prior = self.prior(device_key)
        with self.conn:
            self.conn.execute(
                "INSERT INTO device_state (device_key, last_success_at, newest_ser_ts, newest_his_ts)"
                " VALUES (?, ?, ?, ?) ON CONFLICT(device_key) DO UPDATE SET"
                " last_success_at = excluded.last_success_at,"
                " newest_ser_ts = excluded.newest_ser_ts,"
                " newest_his_ts = excluded.newest_his_ts",
                (
                    device_key,
                    success_at,
                    _newer(prior.newest_ser_ts, newest_ser_ts),
                    _newer(prior.newest_his_ts, newest_his_ts),
                ),
            )
            self.conn.executemany(
                "INSERT OR IGNORE INTO archived_reports (device_key, device_ts, format, s3_key)"
                " VALUES (?, ?, ?, ?)",
                [(device_key, ts, fmt, key) for ts, fmt, key in reports],
            )


@contextmanager
def sweep_lock(state_path: Union[str, Path]) -> Iterator[bool]:
    lock_path = Path(str(state_path) + ".lock")
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
