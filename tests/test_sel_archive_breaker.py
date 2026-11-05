"""BRE readings in the event sweep (breaker.jsonl)."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.sel_archive import records
from sel_triage.sel_archive.archive import MemoryArchive, commit_run
from sel_triage.sel_archive.breaker import BREAKER_FAMILIES, breaker_row, reads_breaker
from tests.test_sel_archive_archive import result as committed_result
from tests.test_sel_archive_device import FakeClient, fixture, run

FIXTURES = Path(__file__).parent / "fixtures" / "sel"


def adapter(model):
    return adapter_for(model).adapter


class TestBreakerRow(unittest.TestCase):
    def test_families_with_a_breaker_monitor(self):
        self.assertEqual(BREAKER_FAMILIES, {"sel351", "sel700g", "sel751"})
        self.assertFalse(reads_breaker("sel735"))

    def test_351s_wear_and_counts(self):
        row = breaker_row(adapter("SEL-351S"), (FIXTURES / "351s-breaker.txt").read_text(), "2026-10-12T00:00:00Z")
        self.assertEqual(row["bre_parse"], "parsed")
        self.assertEqual((row["breaker_wear_percent"], row["operation_count"]), (35.0, 3539))
        self.assertEqual(row["wear_percent"], {"A": 35, "B": 35, "C": 35})
        self.assertTrue(row["monitor_enabled"])
        self.assertIn("relay_accum_current_ka", row["details"])
        self.assertEqual(row["breaker_parser_version"], records.BREAKER_PARSER_VERSION)

    def test_751_with_the_monitor_disabled(self):
        row = breaker_row(adapter("SEL-751"), (FIXTURES / "751-breaker.txt").read_text(), "t")
        self.assertEqual(row["monitor_enabled"], False)
        self.assertIsNone(row["breaker_wear_percent"])

    def test_parse_failure_is_a_row_not_an_exception(self):
        class Broken:
            def parse(self, capability, text):
                raise ValueError("unexpected layout")

        row = breaker_row(Broken(), "BRE", "t")
        self.assertEqual((row["bre_parse"], row["bre_error"]), ("parse_failed", "unexpected layout"))


class TestSweepAndCommit(unittest.TestCase):
    def test_735_sweep_does_not_read_bre(self):
        client = FakeClient("SEL-735", {"history": fixture("735-history.txt"), "ser": b"SER\r\n=>"})
        result = run(client)
        self.assertNotIn("breaker", [call[0] for call in client.calls])
        self.assertIsNone(result.breaker)

    def test_commit_writes_breaker_jsonl(self):
        archive = MemoryArchive()
        res = committed_result()
        res.breaker = breaker_row(adapter("SEL-351S"), (FIXTURES / "351s-breaker.txt").read_text(), "2026-10-12T00:00:00Z")
        counts = commit_run(archive, "p", "RUN1", [res])
        rows = records.from_jsonl(archive.get(records.normalized_key("p", "RUN1", "breaker.jsonl")))
        self.assertEqual(counts["breakers"], 1)
        self.assertEqual((rows[0]["device_key"], rows[0]["run_id"], rows[0]["seen_run"]), (res.item.device_key, "RUN1", "RUN1"))
        self.assertEqual(rows[0]["breaker_wear_percent"], 35.0)
        self.assertEqual(archive.puts[-1], records.normalized_key("p", "RUN1", "runs.jsonl"))


class TestReparseBreaker(unittest.TestCase):
    def seed(self, archive, bre=True, parsed=False):
        from tests.test_sel_archive_reparse import RUN, seed

        seed(archive, ser_parse="parsed", model="SEL-351S", parser_version=records.PARSER_VERSIONS["sel351"])
        if bre:
            archive.put(records.raw_key("p", "dev-1", RUN, "bre.txt"), (FIXTURES / "351s-breaker.txt").read_bytes(), "t")
        if parsed:
            row = {"device_key": "dev-1", "seen_run": RUN, "breaker_parser_version": records.BREAKER_PARSER_VERSION}
            archive.put(records.normalized_key("p", RUN, "breaker.jsonl"), records.to_jsonl([row]), "t")
        return RUN

    def test_archived_bre_is_parsed_once(self):
        from datetime import datetime, timezone
        from sel_triage.sel_archive.reparse import reparse

        archive = MemoryArchive()
        source = self.seed(archive)
        now = datetime(2026, 11, 1, tzinfo=timezone.utc)
        result = reparse(archive, "p", clock=lambda: now)
        self.assertEqual(result["breakers"], 1)
        (run_id,) = result["run_ids"]
        (row,) = records.from_jsonl(archive.get(records.normalized_key("p", run_id, "breaker.jsonl")))
        self.assertEqual((row["seen_run"], row["breaker_wear_percent"]), (source, 35.0))
        self.assertEqual(reparse(archive, "p", clock=lambda: now)["run_ids"], [])

    def test_already_parsed_and_missing_bre_are_skipped(self):
        from sel_triage.sel_archive.reparse import reparse

        for kwargs in ({"parsed": True}, {"bre": False}):
            with self.subTest(**kwargs):
                archive = MemoryArchive()
                self.seed(archive, **kwargs)
                self.assertEqual(reparse(archive, "p")["breakers"], 0)


if __name__ == "__main__":
    unittest.main()
