from pathlib import Path
import sqlite3
import tempfile
import unittest

from sel_triage.sel_archive.state import DevicePrior, SweepState, open_state, sweep_lock


class TestSweepState(unittest.TestCase):
    def setUp(self):
        self.conn = open_state(":memory:")
        self.state = SweepState(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_unknown_device_has_empty_prior(self):
        self.assertEqual(self.state.prior("dev-1"), DevicePrior())
        self.assertIsNone(self.state.last_success("dev-1"))
        self.assertIsNone(self.state.latest_success_any())

    def test_record_and_read_back(self):
        self.state.record(
            "dev-1", "2026-10-06T07:00:00Z", "2026-10-05T10:00:00.100",
            "2026-10-04T09:00:00.000",
            [("2026-10-04T09:00:00.000", "eve", "p/raw/dev-1/R/event-1.eve")],
        )
        prior = self.state.prior("dev-1")
        self.assertEqual(prior.newest_ser_ts, "2026-10-05T10:00:00.100")
        self.assertEqual(prior.newest_his_ts, "2026-10-04T09:00:00.000")
        self.assertEqual(prior.archived, frozenset({("2026-10-04T09:00:00.000", "eve")}))
        self.assertEqual(self.state.last_success("dev-1"), "2026-10-06T07:00:00Z")
        self.assertEqual(self.state.latest_success_any(), "2026-10-06T07:00:00Z")

    def test_record_keeps_newest_timestamps(self):
        self.state.record("dev-1", "2026-10-06T07:00:00Z", "2026-10-05T10:00:00", "2026-10-05T10:00:00", [])
        # relay clock reset to 2000: stored newest must not move backwards
        self.state.record("dev-1", "2026-10-07T07:00:00Z", "2000-01-01T00:00:05", None, [])
        prior = self.state.prior("dev-1")
        self.assertEqual(prior.newest_ser_ts, "2026-10-05T10:00:00")
        self.assertEqual(prior.newest_his_ts, "2026-10-05T10:00:00")
        self.assertEqual(self.state.last_success("dev-1"), "2026-10-07T07:00:00Z")

    def test_newer_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sel-events.sqlite"
            open_state(path).close()
            conn = sqlite3.connect(str(path))
            conn.execute("PRAGMA user_version = 99")
            conn.commit()
            conn.close()
            with self.assertRaises(ValueError):
                open_state(path)


class TestSweepLock(unittest.TestCase):
    def test_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sel-events.sqlite"
            with sweep_lock(path) as first:
                self.assertTrue(first)
                with sweep_lock(path) as second:
                    self.assertFalse(second)
            with sweep_lock(path) as again:
                self.assertTrue(again)
