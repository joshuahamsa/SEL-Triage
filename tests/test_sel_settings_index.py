"""SQLite index over saved SEL settings captures (synthetic Reads fixtures)."""

import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from sel_triage.integrations.devices.sel.settings.index import build_index, inventory_endpoints

READS = Path(__file__).parent / "fixtures" / "sel" / "reads"


class TestSettingsIndex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "Reads"
        shutil.copytree(READS, self.root)
        self.db = Path(self.tmp.name) / "index.sqlite"

    def tearDown(self):
        self.tmp.cleanup()

    def query(self, sql, *args):
        conn = sqlite3.connect(str(self.db))
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def test_builds_captures_settings_and_latest_views(self):
        summary = build_index(self.root, self.db)

        self.assertGreater(summary["indexed"], 0)
        self.assertEqual(summary["captures"], summary["indexed"])
        alpha = self.query(
            "SELECT captured_at, status, model, method, firmware_revision FROM captures "
            "WHERE device_key = 'Alpha Solar/192.0.2.11_2381' ORDER BY captured_at")
        self.assertEqual([row[1] for row in alpha], ["ok", "ok"])
        self.assertEqual(alpha[-1][0], "2026-06-01T12:00:00Z")
        self.assertEqual(alpha[-1][2], "SEL-751")
        self.assertEqual(alpha[-1][4], "R400")
        latest = self.query(
            "SELECT value FROM latest_settings WHERE device_key = 'Alpha Solar/192.0.2.11_2381' "
            "AND class = '1' AND key = 'CTR'")
        self.assertEqual(latest, [("500",)])
        failed = self.query("SELECT error FROM captures WHERE device_key LIKE 'Delta Solar/%' AND status = 'failed'")
        self.assertEqual(failed, [("TimeoutError",)])
        # the device whose only run failed has no latest capture; its site peer does
        self.assertEqual(
            self.query("SELECT status FROM latest_captures WHERE device_key LIKE 'Delta Solar/%'"), [("ok",)])

    def test_rerun_is_incremental(self):
        first = build_index(self.root, self.db)
        second = build_index(self.root, self.db)
        self.assertEqual(second["indexed"], 0)
        self.assertEqual(second["unchanged"], first["indexed"])
        self.assertEqual(second["settings_rows"], first["settings_rows"])

    def test_changed_run_is_reindexed_and_missing_run_dropped(self):
        build_index(self.root, self.db)
        delta_runs = self.query("SELECT COUNT(*) FROM captures WHERE device_key LIKE 'Delta Solar/%'")[0][0]
        run = self.root / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z"
        settings = run / "set_1.txt"
        settings.write_text(settings.read_text().replace('CTR,"500"', 'CTR,"600"'))
        os.utime(settings, ns=(1, 1))
        shutil.rmtree(self.root / "Delta Solar")

        summary = build_index(self.root, self.db)

        self.assertEqual(summary["indexed"], 1)
        self.assertEqual(summary["removed"], delta_runs)
        self.assertEqual(
            self.query("SELECT value FROM latest_settings WHERE device_key = 'Alpha Solar/192.0.2.11_2381' "
                       "AND class = '1' AND key = 'CTR'"),
            [("600",)])
        self.assertEqual(self.query("SELECT COUNT(*) FROM captures WHERE device_key LIKE 'Delta Solar/%'"), [(0,)])

    def test_secret_values_stay_redacted(self):
        build_index(self.root, self.db)
        rows = self.query("SELECT key, value FROM settings WHERE key LIKE '%PASS%' OR key LIKE '%PW%'")
        for key, value in rows:
            self.assertIn("REDACTED", str(value).upper(), key)

    def test_two_roots_share_a_database(self):
        other = Path(self.tmp.name) / "captures"
        run = other / "Alpha Solar" / "192.0.2.11_2381" / "20261012T120000Z"
        shutil.copytree(self.root / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z", run)
        build_index(self.root, self.db)
        build_index(other, self.db)
        self.assertEqual(
            self.query("SELECT captured_at FROM latest_captures WHERE device_key = 'Alpha Solar/192.0.2.11_2381'"),
            [("2026-10-12T12:00:00Z",)])
        build_index(other, self.db, rebuild=True)
        self.assertEqual(self.query("SELECT COUNT(DISTINCT root) FROM captures"), [(2,)])

    def test_a_newer_failed_run_does_not_hide_the_last_good_capture(self):
        failed = self.root / "Alpha Solar" / "192.0.2.11_2381" / "20261012T120000Z"
        failed.mkdir()
        (failed / "ERROR.txt").write_text("Error: TriageError: unable to establish Telnet connection\n")
        build_index(self.root, self.db)
        self.assertEqual(
            self.query("SELECT captured_at FROM latest_captures WHERE device_key = 'Alpha Solar/192.0.2.11_2381'"),
            [("2026-06-01T12:00:00Z",)])

    def test_inventory_merges_one_device_filed_under_two_site_names(self):
        other = Path(self.tmp.name) / "captures"
        newer = other / "Alpha Solar Farm (renamed)" / "192.0.2.11_2381" / "20261012T120000Z"
        shutil.copytree(self.root / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z", newer)
        endpoints = inventory_endpoints({"devices": [
            {"name": "Alpha Solar Farm/Relay", "kind": "sel", "host": "192.0.2.11", "port": 2381},
            {"name": "Alpha Solar Farm/Inverter", "kind": "sma", "host": "192.0.2.99", "port": 443},
        ]})
        self.assertEqual(endpoints, {"192.0.2.11_2381": ("Alpha Solar Farm/Relay", "Alpha Solar Farm")})

        build_index(self.root, self.db, endpoints=endpoints)
        summary = build_index(other, self.db, endpoints=endpoints)

        self.assertGreaterEqual(summary["matched_to_inventory"], 1)
        history = self.query(
            "SELECT device_key, captured_at FROM captures WHERE device = 'Alpha Solar Farm/Relay' ORDER BY captured_at")
        self.assertEqual([row[0] for row in history], ["Alpha Solar/192.0.2.11_2381"] * 2
                         + ["Alpha Solar Farm (renamed)/192.0.2.11_2381"])
        self.assertEqual(
            self.query("SELECT device_site, captured_at FROM latest_captures WHERE device = 'Alpha Solar Farm/Relay'"),
            [("Alpha Solar Farm", "2026-10-12T12:00:00Z")])
        unmatched = self.query("SELECT device FROM captures WHERE device_key = 'Bravo Solar/192.0.2.21_2381'")
        self.assertEqual(unmatched, [("Bravo Solar/192.0.2.21_2381",)])

    def test_inventory_change_reindexes_unchanged_runs(self):
        build_index(self.root, self.db)
        endpoints = {"192.0.2.11_2381": ("Alpha/Relay", "Alpha")}
        summary = build_index(self.root, self.db, endpoints=endpoints)
        self.assertEqual(summary["indexed"], 2)
        self.assertEqual(self.query("SELECT COUNT(*) FROM captures WHERE device = 'Alpha/Relay'"), [(2,)])

    def test_old_schema_is_reset(self):
        conn = sqlite3.connect(str(self.db))
        conn.executescript("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                           "INSERT INTO meta VALUES ('schema_version', '1');"
                           "CREATE TABLE captures (capture_id INTEGER PRIMARY KEY, path TEXT);")
        conn.close()
        summary = build_index(self.root, self.db)
        self.assertTrue(summary["schema_reset"])
        self.assertEqual(self.query("SELECT value FROM meta WHERE key = 'schema_version'"), [("4",)])
        self.assertFalse(build_index(self.root, self.db)["schema_reset"])

    def test_help_lists_are_indexed_per_device(self):
        from tests.test_sel_settings_help import HELP

        run = self.root / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z"
        (run / "HELP.txt").write_text(HELP, encoding="utf-8")
        rejected = self.root / "Alpha Solar" / "192.0.2.12_2341" / "20260520T162204Z"
        (rejected / "HELP.txt").write_text("HELP\r\nInvalid Command\r\n=>", encoding="utf-8")
        build_index(self.root, self.db)
        self.assertEqual(
            self.query("SELECT command FROM latest_commands WHERE device = 'Alpha Solar/192.0.2.11_2381' ORDER BY command"),
            [("89CLOSE",), ("BREAKER",), ("HSG",), ("METER",), ("SET/SHOW",)])
        self.assertEqual(
            self.query("SELECT help_status, help_command_count FROM captures WHERE path LIKE '%192.0.2.12_2341%'"),
            [("rejected", 0)])
        self.assertEqual(self.query("SELECT COUNT(*) FROM latest_commands WHERE device LIKE '%192.0.2.12_2341'"), [(0,)])

    def test_manual_reference_joins_devices_by_model_and_firmware(self):
        build_index(self.root, self.db)
        self.assertGreater(self.query("SELECT COUNT(DISTINCT model) FROM manual_commands")[0][0], 9)
        alpha = "Alpha Solar/192.0.2.11_2381"
        self.assertEqual(self.query("SELECT manual_model FROM latest_captures WHERE device = ?", alpha), [("SEL-751",)])
        met = self.query("SELECT DISTINCT kind, min_access_level FROM device_command_reference "
                         "WHERE device = ? AND verb = 'MET'", alpha)
        # plain MET reads; some MET variants reset stored values and are classed write
        self.assertIn(("read", "1"), met)
        self.assertEqual(self.query("SELECT DISTINCT kind FROM device_command_reference WHERE device = ? AND verb = 'SET'",
                                    alpha), [("write",)])
        firmware = self.query(
            "SELECT firmware_revision, manual_latest_revision, fid_in_manual FROM device_firmware_reference WHERE device = ?",
            alpha)
        self.assertEqual(firmware[0][0], "R400")
        self.assertIsNotNone(firmware[0][1])
        self.assertIn(firmware[0][2], (0, 1))

    def test_missing_root_is_an_error(self):
        with self.assertRaises(ValueError):
            build_index(Path(self.tmp.name) / "nope", self.db)


if __name__ == "__main__":
    unittest.main()
