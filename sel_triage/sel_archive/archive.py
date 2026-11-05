"""Where sweeps are stored: S3 (real) or memory (tests), and the commit order."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import records

_TEXT = "text/plain; charset=utf-8"
_NDJSON = "application/x-ndjson"


class MemoryArchive:
    def __init__(self) -> None:
        self.objects: Dict[str, bytes] = {}
        self.puts: List[str] = []
        self.fail_on: Optional[str] = None

    def put(self, key: str, data: bytes, content_type: str) -> None:
        if self.fail_on is not None and key.endswith(self.fail_on):
            raise RuntimeError("simulated upload failure for " + key)
        self.objects[key] = data
        self.puts.append(key)

    def get(self, key: str) -> bytes:
        return self.objects[key]

    def list_children(self, prefix: str) -> List[str]:
        start = prefix.rstrip("/") + "/"
        return sorted(
            {k[len(start):].split("/", 1)[0] for k in self.objects if k.startswith(start) and "/" in k[len(start):]}
        )


class LocalArchive:
    """The S3 layout on local disk: ``<root>/<key>``. Owner-only; writes are atomic renames."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser()

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("archive key escapes the archive folder: " + key)
        return path

    def put(self, key: str, data: bytes, content_type: str) -> None:
        path = self._path(key)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = path.with_name(path.name + ".partial")
        with open(os.open(str(temp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "wb") as handle:
            handle.write(data)
        os.replace(str(temp), str(path))

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not path.is_file():
            raise KeyError(key)
        return path.read_bytes()

    def list_children(self, prefix: str) -> List[str]:
        folder = self._path(prefix.rstrip("/"))
        if not folder.is_dir():
            return []
        return sorted(child.name for child in folder.iterdir() if child.is_dir())


class S3Archive:
    def __init__(self, bucket: str, profile: Optional[str] = None, client: Any = None) -> None:
        self.bucket = bucket
        if client is None:
            import boto3

            client = boto3.Session(profile_name=profile).client("s3")
        self.client = client

    def put(self, key: str, data: bytes, content_type: str) -> None:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType=content_type)

    def get(self, key: str) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
        except self.client.exceptions.NoSuchKey:
            raise KeyError(key)
        return response["Body"].read()

    def list_children(self, prefix: str) -> List[str]:
        start = prefix.rstrip("/") + "/"
        names: List[str] = []
        pages = self.client.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=start, Delimiter="/"
        )
        for page in pages:
            names.extend(cp["Prefix"][len(start):].rstrip("/") for cp in page.get("CommonPrefixes", []))
        return sorted(names)


def commit_run(archive, prefix: str, run_id: str, results: Sequence) -> Dict[str, int]:
    """Upload a sweep: raw files, then row files, then ``runs.jsonl`` as the commit marker."""

    ser: List[Dict] = []
    history: List[Dict] = []
    reports: List[Dict] = []
    event_reports: List[Dict] = []
    breakers: List[Dict] = []
    runs: List[Dict] = []
    raw_count = 0
    for result in results:
        key = result.item.device_key
        for name, data in sorted(result.raw.items()):
            archive.put(records.raw_key(prefix, key, run_id, name), data, _TEXT)
            raw_count += 1
        common = {"schema_version": records.SCHEMA_VERSION, "run_id": run_id, "device_key": key}
        version = result.run_row.get("parser_version")
        ser.extend(dict(common, parser_version=version, **row) for row in result.ser_rows)
        history.extend(dict(common, parser_version=version, **row) for row in result.history_rows)
        for row in result.report_rows:
            summary = getattr(result, "event_summaries", {}).get(row["raw_name"])
            if summary is not None:
                event_reports.append(dict(
                    common,
                    device_ts=row["device_ts"],
                    s3_key=records.raw_key(prefix, key, run_id, row["raw_name"]),
                    sha256=row["sha256"],
                    report_parser_version=records.REPORT_PARSER_VERSION,
                    **summary,
                ))
            reports.append(
                dict(
                    common,
                    device_ts=row["device_ts"],
                    format=row["format"],
                    s3_key=records.raw_key(prefix, key, run_id, row["raw_name"]),
                    bytes=row["bytes"],
                    sha256=row["sha256"],
                )
            )
        breaker = getattr(result, "breaker", None)
        if breaker is not None:
            breakers.append(dict(common, seen_run=run_id, **breaker))
        runs.append(dict(result.run_row, run_id=run_id))
    # event_reports.jsonl is additive: consumers that read only the four files above ignore it
    for name, rows in (("ser.jsonl", ser), ("history.jsonl", history), ("reports.jsonl", reports),
                       ("event_reports.jsonl", event_reports), ("breaker.jsonl", breakers)):
        archive.put(records.normalized_key(prefix, run_id, name), records.to_jsonl(rows), _NDJSON)
    archive.put(records.normalized_key(prefix, run_id, "runs.jsonl"), records.to_jsonl(runs), _NDJSON)
    return {"raw": raw_count, "ser": len(ser), "history": len(history), "reports": len(reports),
            "event_reports": len(event_reports), "breakers": len(breakers), "runs": len(runs)}
