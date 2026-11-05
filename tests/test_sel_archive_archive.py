import unittest

from sel_triage.core.inventory import DeviceTarget
from sel_triage.sel_archive import records
from sel_triage.sel_archive.archive import MemoryArchive, S3Archive, commit_run
from sel_triage.sel_archive.device import DeviceResult, SweepItem


def result():
    item = SweepItem("Lab Site", DeviceTarget("Lab Site/Relay", "sel", "192.0.2.1", 23, "SEL-700GT", "sel/access1", 5))
    res = DeviceResult(item, {"device_key": item.device_key, "parser_version": 1, "kind": "sweep"})
    res.raw = {"his.txt": b"HIS", "ser.txt": b"SER", "event-20260101T000000.eve": b"EVE"}
    res.ser_rows = [{"device_ts": "2026-01-01T00:00:00", "element": "IN101", "state": "Asserted"}]
    res.history_rows = [{"device_ts": "2026-01-01T00:00:00", "event_type": "TRIP", "details": {}}]
    res.report_rows = [{"device_ts": "2026-01-01T00:00:00", "format": "eve",
                        "raw_name": "event-20260101T000000.eve", "bytes": 3, "sha256": "ab"}]
    return res


class TestCommitRun(unittest.TestCase):
    def test_runs_jsonl_is_written_last_and_rows_are_stamped(self):
        archive = MemoryArchive()
        res = result()
        counts = commit_run(archive, "sel_events", "RUN1", [res])
        self.assertEqual(archive.puts[-1], "sel_events/normalized/RUN1/runs.jsonl")
        raw_puts = [k for k in archive.puts if "/raw/" in k]
        self.assertEqual(archive.puts[:len(raw_puts)], raw_puts)  # raw first
        ser = records.from_jsonl(archive.objects["sel_events/normalized/RUN1/ser.jsonl"])
        self.assertEqual(ser[0]["run_id"], "RUN1")
        self.assertEqual(ser[0]["device_key"], res.item.device_key)
        self.assertEqual(ser[0]["schema_version"], 1)
        self.assertEqual(ser[0]["parser_version"], 1)
        reports = records.from_jsonl(archive.objects["sel_events/normalized/RUN1/reports.jsonl"])
        self.assertEqual(
            reports[0]["s3_key"],
            "sel_events/raw/{0}/RUN1/event-20260101T000000.eve".format(res.item.device_key),
        )
        self.assertNotIn("raw_name", reports[0])
        runs = records.from_jsonl(archive.objects["sel_events/normalized/RUN1/runs.jsonl"])
        self.assertEqual(runs[0]["run_id"], "RUN1")
        self.assertEqual(counts, {"raw": 3, "ser": 1, "history": 1, "reports": 1, "event_reports": 0, "breakers": 0, "runs": 1})

    def test_event_summaries_go_to_event_reports_jsonl(self):
        from pathlib import Path
        from sel_triage.sel_archive.event_reports import summarize

        eve = (Path(__file__).parent / "fixtures" / "sel" / "events" / "sel651r2_event_10259.eve").read_bytes()
        archive = MemoryArchive()
        res = result()
        name = res.report_rows[0]["raw_name"]
        res.event_summaries[name] = summarize(eve)
        counts = commit_run(archive, "sel_events", "RUN1", [res])
        rows = records.from_jsonl(archive.objects["sel_events/normalized/RUN1/event_reports.jsonl"])
        self.assertEqual(counts["event_reports"], 1)
        self.assertEqual(rows[0]["event_number"], 10259)
        self.assertEqual(rows[0]["event_type"], "CAG T")
        self.assertIsNone(rows[0]["location"])
        self.assertEqual(rows[0]["reported_currents"]["A"], 2697.0)
        self.assertEqual(rows[0]["s3_key"], "sel_events/raw/{0}/RUN1/{1}".format(res.item.device_key, name))
        self.assertEqual((rows[0]["report_parser_version"], rows[0]["run_id"]), (records.REPORT_PARSER_VERSION, "RUN1"))
        self.assertEqual(archive.puts[-1], "sel_events/normalized/RUN1/runs.jsonl")

    def test_empty_files_still_written(self):
        archive = MemoryArchive()
        commit_run(archive, "p", "RUN", [])
        for name in ("ser.jsonl", "history.jsonl", "reports.jsonl", "runs.jsonl"):
            self.assertEqual(archive.objects["p/normalized/RUN/" + name], b"")

    def test_failure_before_marker_leaves_no_marker(self):
        archive = MemoryArchive()
        archive.fail_on = "reports.jsonl"
        with self.assertRaises(RuntimeError):
            commit_run(archive, "p", "RUN", [result()])
        self.assertNotIn("p/normalized/RUN/runs.jsonl", archive.objects)


class TestMemoryArchive(unittest.TestCase):
    def test_get_and_list_children(self):
        archive = MemoryArchive()
        archive.put("p/normalized/R1/runs.jsonl", b"x", "text/plain")
        archive.put("p/normalized/R2/ser.jsonl", b"y", "text/plain")
        self.assertEqual(archive.list_children("p/normalized"), ["R1", "R2"])
        self.assertEqual(archive.get("p/normalized/R1/runs.jsonl"), b"x")
        with self.assertRaises(KeyError):
            archive.get("missing")


class FakeS3:
    class exceptions:
        class NoSuchKey(Exception):
            pass

    def __init__(self):
        self.store = {}

    def put_object(self, Bucket, Key, Body, ContentType):
        self.store[Key] = Body

    def get_object(self, Bucket, Key):
        if Key not in self.store:
            raise self.exceptions.NoSuchKey()
        body = self.store[Key]

        class Stream:
            def read(self_inner):
                return body

        return {"Body": Stream()}

    def get_paginator(self, name):
        store = self.store

        class Paginator:
            def paginate(self_inner, Bucket, Prefix, Delimiter):
                children = sorted({k[len(Prefix):].split("/", 1)[0] for k in store
                                   if k.startswith(Prefix) and "/" in k[len(Prefix):]})
                yield {"CommonPrefixes": [{"Prefix": Prefix + c + "/"} for c in children]}

        return Paginator()


class TestS3Archive(unittest.TestCase):
    def test_round_trip_with_fake_client(self):
        archive = S3Archive("bucket", client=FakeS3())
        archive.put("p/normalized/R1/runs.jsonl", b"x", "application/x-ndjson")
        self.assertEqual(archive.get("p/normalized/R1/runs.jsonl"), b"x")
        self.assertEqual(archive.list_children("p/normalized"), ["R1"])
        with self.assertRaises(KeyError):
            archive.get("p/missing")


class TestLocalArchive(unittest.TestCase):
    def test_round_trip_listing_and_commit_marker(self):
        import tempfile
        from pathlib import Path
        from sel_triage.sel_archive.archive import LocalArchive

        with tempfile.TemporaryDirectory() as tmp:
            archive = LocalArchive(Path(tmp))
            counts = commit_run(archive, "sel_events", "RUN1", [result()])
            self.assertEqual(counts["runs"], 1)
            self.assertEqual(archive.list_children("sel_events/normalized"), ["RUN1"])
            runs = records.from_jsonl(archive.get("sel_events/normalized/RUN1/runs.jsonl"))
            self.assertEqual(runs[0]["run_id"], "RUN1")
            self.assertEqual(archive.list_children("sel_events/nothing"), [])
            with self.assertRaises(KeyError):
                archive.get("sel_events/normalized/RUN2/runs.jsonl")
            with self.assertRaises(ValueError):
                archive.put("../escape.txt", b"x", "t")
            raw = Path(tmp) / "sel_events" / "raw"
            self.assertTrue(any(raw.rglob("his.txt")))
            self.assertFalse(any(Path(tmp).rglob("*.partial")))
            mode = (Path(tmp) / "sel_events" / "normalized" / "RUN1" / "runs.jsonl").stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
