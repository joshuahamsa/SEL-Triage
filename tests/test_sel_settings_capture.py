from pathlib import Path
import shutil
import tempfile
import unittest

from sel_triage.integrations.devices.sel.settings.capture import (
    discover_devices,
    latest_identity_capture,
    latest_settings_capture,
    load_capture_run,
)


FIXTURES = Path(__file__).parent / "fixtures" / "sel"
READS = FIXTURES / "reads"


# The Alpha 751 has two captures built from one real capture: the older one
# has group 1 CTR edited to 100 and both have group 2 CTR edited to 120, so
# drift and group-consistency checks have something to find.
class TestLoadCaptureRun(unittest.TestCase):
    def test_file_read_run(self):
        run = load_capture_run(READS / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z")
        self.assertEqual(run["source"], "file_read")
        self.assertEqual(run["status"], "ok")
        self.assertEqual(run["captured_at"], "2026-06-01T12:00:00Z")
        self.assertEqual(run["identity"]["model"], "SEL-751")
        self.assertEqual(run["relay_type"], "SEL-751")
        self.assertEqual(sorted(run["settings"]), ["1", "2", "G", "P1"])
        self.assertEqual(run["settings"]["1"]["CTR"], "500")
        self.assertEqual(run["banner"]["time_source"], "Internal")

    def test_failed_run(self):
        run = load_capture_run(READS / "Delta Solar" / "192.0.2.42_2381" / "20260519T182329Z")
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["error"], "TimeoutError")
        self.assertEqual(run["settings"], {})
        self.assertNotIn("192.0.2", repr(run))

    def test_identity_only_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "Site" / "192.0.2.9_2381" / "20260101T000000Z"
            run_dir.mkdir(parents=True)
            shutil.copy(READS / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z" / "ID.txt", run_dir)
            run = load_capture_run(run_dir)
        self.assertEqual(run["status"], "identity_only")
        self.assertEqual(run["identity"]["model"], "SEL-751")

    def test_evidence_store_sho_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            device_dir = Path(tmp) / "20260929t172945z-aaaaaaaaaaaa-bbbbbbbbbbbb" / "lab-site-relay-cccccccccccc"
            device_dir.mkdir(parents=True)
            shutil.copy(FIXTURES / "700gt-id.txt", device_dir / "identity.txt")
            for name in ("global", "group", "logic"):
                shutil.copy(FIXTURES / "700gt-settings-{0}.txt".format(name), device_dir / "settings-{0}.txt".format(name))
            run = load_capture_run(device_dir)
        self.assertEqual(run["source"], "evidence")
        self.assertEqual(run["status"], "ok")
        self.assertEqual(run["captured_at"], "2026-09-29T17:29:45Z")
        self.assertEqual(run["identity"]["model"], "SEL-700GT")
        self.assertEqual(run["settings"]["G"]["EBMONX"], "Y")
        self.assertIn("1", run["settings"])
        self.assertIn("L1", run["settings"])


class TestDiscoverDevices(unittest.TestCase):
    def test_corpus_root_groups_runs_by_device(self):
        devices = discover_devices(READS)
        keys = [device["key"] for device in devices]
        self.assertEqual(len(devices), 8)
        self.assertIn("Alpha Solar/192.0.2.11_2381", keys)
        alpha = devices[keys.index("Alpha Solar/192.0.2.11_2381")]
        self.assertEqual(alpha["site"], "Alpha Solar")
        self.assertEqual([run["run"] for run in alpha["captures"]], ["20260519T165050Z", "20260601T120000Z"])

    def test_device_and_run_paths(self):
        device = discover_devices(READS / "Alpha Solar" / "192.0.2.11_2381")
        self.assertEqual(len(device), 1)
        self.assertEqual(device[0]["key"], "Alpha Solar/192.0.2.11_2381")
        run = discover_devices(READS / "Alpha Solar" / "192.0.2.11_2381" / "20260519T165050Z")
        self.assertEqual(len(run[0]["captures"]), 1)

    def test_latest_captures(self):
        devices = {device["key"]: device for device in discover_devices(READS)}
        alpha = devices["Alpha Solar/192.0.2.11_2381"]
        self.assertEqual(latest_identity_capture(alpha)["run"], "20260601T120000Z")
        self.assertEqual(latest_settings_capture(alpha)["run"], "20260601T120000Z")
        failed = devices["Delta Solar/192.0.2.42_2381"]
        self.assertIsNone(latest_identity_capture(failed))
        self.assertIsNone(latest_settings_capture(failed))

    def test_missing_path(self):
        with self.assertRaises(ValueError):
            discover_devices(READS / "nope")


if __name__ == "__main__":
    unittest.main()
