from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest import mock

from sel_triage.sel_archive import records
from sel_triage.sel_archive.archive import MemoryArchive
from sel_triage.sel_archive.reparse import reparse

FIXTURES = Path(__file__).parent / "fixtures" / "sel"
NOW = datetime(2026, 11, 1, 7, 0, tzinfo=timezone.utc)
RUN = "20261006T070000Z-aaaaaa"  # real run ids sort by time
RUN2 = "20261007T070000Z-bbbbbb"


def seed(archive, run=RUN, ser_parse="no_parser", parser_version=1, model="SEL-700GT"):
    run_row = {"schema_version": 1, "kind": "sweep", "run_id": run, "device_key": "dev-1",
               "name": "Lab/Relay", "site": "Lab", "observed_model": model, "devid": "X",
               "family": "sel700g", "parser_version": parser_version, "ser_parse": ser_parse,
               "his_parse": "parsed"}
    archive.put(records.raw_key("p", "dev-1", run, "ser.txt"), (FIXTURES / "700gt-ser.txt").read_bytes(), "t")
    archive.put(records.raw_key("p", "dev-1", run, "his.txt"), (FIXTURES / "700gt-history.txt").read_bytes(), "t")
    archive.put(records.normalized_key("p", run, "runs.jsonl"), records.to_jsonl([run_row]), "t")


def rows(archive, run_id, name):
    return records.from_jsonl(archive.get(records.normalized_key("p", run_id, name)))


class TestReparse(unittest.TestCase):
    def test_reparses_rows_that_had_no_parser(self):
        archive = MemoryArchive()
        seed(archive)
        result = reparse(archive, "p", clock=lambda: NOW)
        self.assertEqual(result["devices_reparsed"], 1)
        self.assertGreater(result["ser_rows"], 0)
        self.assertEqual(result["history_rows"], 0)  # HIS already parsed at this version
        (run_id,) = result["run_ids"]
        runs = rows(archive, run_id, "runs.jsonl")
        self.assertEqual(runs[0]["kind"], "reparse")
        self.assertEqual(runs[0]["source_run_id"], RUN)
        self.assertEqual(archive.puts[-1], records.normalized_key("p", run_id, "runs.jsonl"))

    def test_reparsed_rows_carry_the_source_run(self):
        archive = MemoryArchive()
        seed(archive)
        (run_id,) = reparse(archive, "p", clock=lambda: NOW)["run_ids"]
        ser = rows(archive, run_id, "ser.jsonl")
        self.assertTrue(all(r["seen_run"] == RUN for r in ser))
        self.assertTrue(all(r["run_id"] == run_id for r in ser))

    def test_up_to_date_rows_are_a_no_op(self):
        archive = MemoryArchive()
        seed(archive, ser_parse="parsed")
        before = list(archive.puts)
        result = reparse(archive, "p", clock=lambda: NOW)
        self.assertEqual(result["run_ids"], [])
        self.assertEqual(archive.puts, before)

    def test_second_reparse_is_a_no_op(self):
        archive = MemoryArchive()
        seed(archive)
        reparse(archive, "p", clock=lambda: NOW)
        before = list(archive.puts)
        second = reparse(archive, "p", clock=lambda: NOW)
        self.assertEqual(second["devices_reparsed"], 0)
        self.assertEqual(archive.puts, before)

    def test_version_bump_reparses_again(self):
        archive = MemoryArchive()
        seed(archive, ser_parse="parsed")
        with mock.patch.dict(records.PARSER_VERSIONS, {"sel700g": 2}):
            first = reparse(archive, "p", clock=lambda: NOW)
            second = reparse(archive, "p", clock=lambda: NOW)
        self.assertGreater(first["ser_rows"], 0)
        self.assertGreater(first["history_rows"], 0)
        self.assertEqual(second["devices_reparsed"], 0)

    def test_each_source_run_gets_its_own_output_run(self):
        archive = MemoryArchive()
        seed(archive, run=RUN)
        seed(archive, run=RUN2)
        result = reparse(archive, "p", clock=lambda: NOW)
        self.assertEqual(len(result["run_ids"]), 2)
        sources = sorted(rows(archive, r, "runs.jsonl")[0]["source_run_id"] for r in result["run_ids"])
        self.assertEqual(sources, [RUN, RUN2])
        for run_id in result["run_ids"]:
            self.assertEqual(len(rows(archive, run_id, "runs.jsonl")), 1)

    def test_family_filter(self):
        archive = MemoryArchive()
        seed(archive)
        self.assertEqual(reparse(archive, "p", clock=lambda: NOW, family="sel735")["devices_reparsed"], 0)


def seed_report(archive, run=RUN, summarized=False):
    """An archived sweep run with one EVE report and (optionally) its summary."""

    seed(archive, run=run, ser_parse="parsed", model="SEL-651R2", parser_version=records.PARSER_VERSIONS["sel651"])
    eve = (FIXTURES / "events" / "sel651r2_event_10259.eve").read_bytes()
    key = records.raw_key("p", "dev-1", run, "event-20260715T093357.eve")
    archive.put(key, eve, "t")
    report = {"schema_version": 1, "run_id": run, "device_key": "dev-1", "device_ts": "2026-07-15T09:33:57",
              "format": "eve", "s3_key": key, "bytes": len(eve), "sha256": "sha-10259"}
    archive.put(records.normalized_key("p", run, "reports.jsonl"), records.to_jsonl([report]), "t")
    if summarized:
        done = dict(report, report_parser_version=records.REPORT_PARSER_VERSION, report_parse="parsed")
        archive.put(records.normalized_key("p", run, "event_reports.jsonl"), records.to_jsonl([done]), "t")


class TestReparseEventReports(unittest.TestCase):
    def test_archived_reports_are_summarized(self):
        archive = MemoryArchive()
        seed_report(archive)
        result = reparse(archive, "p", clock=lambda: NOW)
        self.assertEqual(result["event_reports"], 1)
        (run_id,) = result["run_ids"]
        (summary,) = rows(archive, run_id, "event_reports.jsonl")
        self.assertEqual((summary["event_number"], summary["event_type"]), (10259, "CAG T"))
        self.assertEqual((summary["seen_run"], summary["run_id"], summary["sha256"]), (RUN, run_id, "sha-10259"))
        (run_row,) = rows(archive, run_id, "runs.jsonl")
        self.assertEqual((run_row["kind"], run_row["source_run_id"]), ("reparse", RUN))
        self.assertEqual(archive.puts[-1], records.normalized_key("p", run_id, "runs.jsonl"))

    def test_second_reparse_does_not_resummarize(self):
        archive = MemoryArchive()
        seed_report(archive)
        reparse(archive, "p", clock=lambda: NOW)
        before = list(archive.puts)
        self.assertEqual(reparse(archive, "p", clock=lambda: NOW)["run_ids"], [])
        self.assertEqual(archive.puts, before)

    def test_reports_summarized_in_the_sweep_are_skipped(self):
        archive = MemoryArchive()
        seed_report(archive, summarized=True)
        self.assertEqual(reparse(archive, "p", clock=lambda: NOW)["run_ids"], [])

    def test_family_filter_applies_to_reports(self):
        archive = MemoryArchive()
        seed_report(archive)
        self.assertEqual(reparse(archive, "p", clock=lambda: NOW, family="sel751")["run_ids"], [])
        self.assertEqual(reparse(archive, "p", clock=lambda: NOW, family="sel651")["event_reports"], 1)
