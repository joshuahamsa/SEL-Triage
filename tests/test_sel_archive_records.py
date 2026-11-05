from datetime import datetime, timezone
import unittest

from sel_triage.sel_archive import records
from sel_triage.sel_archive.settings import archive_settings


class TestRecords(unittest.TestCase):
    def test_device_key_is_slug_plus_stable_hash(self):
        key = records.device_key("Lab Site/Relay @2381")
        self.assertRegex(key, r"^lab-site-relay-2381-[0-9a-f]{8}$")
        self.assertEqual(key, records.device_key("Lab Site/Relay @2381"))
        self.assertNotEqual(key, records.device_key("Lab Site-Relay @2381"))

    def test_run_id_sorts_by_time(self):
        early = records.new_run_id(datetime(2026, 10, 6, 7, 0, tzinfo=timezone.utc))
        late = records.new_run_id(datetime(2026, 10, 7, 7, 0, tzinfo=timezone.utc))
        self.assertRegex(early, r"^20261006T070000Z-[0-9a-f]{6}$")
        self.assertLess(early, late)

    def test_keys_and_report_names(self):
        self.assertEqual(
            records.raw_key("sel_events", "dev-1", "RUN", "his.txt"),
            "sel_events/raw/dev-1/RUN/his.txt",
        )
        self.assertEqual(
            records.normalized_key("sel_events", "RUN", "runs.jsonl"),
            "sel_events/normalized/RUN/runs.jsonl",
        )
        self.assertEqual(
            records.report_file_name("2026-09-13T16:48:22.988"),
            "event-20260913T164822988.eve",
        )

    def test_jsonl_round_trip(self):
        rows = [{"a": 1, "b": {"c": "x"}}, {"a": 2}]
        data = records.to_jsonl(rows)
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(records.from_jsonl(data), rows)
        self.assertEqual(records.to_jsonl([]), b"")


class TestSettings(unittest.TestCase):
    def test_defaults_and_profile(self):
        settings = archive_settings({"selEventArchive": {"bucket": "example-bucket"}})
        self.assertEqual(settings.bucket, "example-bucket")
        self.assertEqual(settings.prefix, "sel_events")
        self.assertIsNone(settings.profile)
        with_profile = archive_settings(
            {"selEventArchive": {"bucket": "example-bucket", "profile": "example-profile"}}
        )
        self.assertEqual(with_profile.profile, "example-profile")
        self.assertEqual(settings.events_per_run, 10)
        self.assertEqual(settings.event_report_families, ("sel651", "sel700g"))
        self.assertEqual(settings.read_timeout_seconds, 60.0)

    def test_bucket_is_required_for_s3(self):
        with self.assertRaisesRegex(ValueError, "selEventArchive.bucket"):
            archive_settings({"selEventArchive": {"store": "s3"}})

    def test_store_defaults(self):
        local = archive_settings({})
        self.assertEqual(local.store, "local")
        self.assertTrue(str(local.local_dir).endswith("sel-events"))
        self.assertIsNone(local.bucket)
        s3 = archive_settings({"selEventArchive": {"bucket": "b"}})
        self.assertEqual((s3.store, s3.local_dir), ("s3", None))
        custom = archive_settings({"selEventArchive": {"store": "local", "localDir": "/tmp/x", "bucket": "b"}})
        self.assertEqual((custom.store, str(custom.local_dir)), ("local", "/tmp/x"))
        with self.assertRaisesRegex(ValueError, "store"):
            archive_settings({"selEventArchive": {"store": "ftp"}})

    def test_rejects_bad_values(self):
        for bad in ({"eventsPerRun": 0}, {"maxSitesParallel": "8"},
                    {"eventReportFamilies": "sel700g"}, {"prefix": "a/"},
                    {"readTimeoutSeconds": 301}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    archive_settings({"selEventArchive": {"bucket": "b", **bad}})
