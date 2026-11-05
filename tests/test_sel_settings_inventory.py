from datetime import datetime, timezone
from pathlib import Path
import csv
import io
import unittest

from sel_triage.integrations.devices.sel.settings.capture import discover_devices
from sel_triage.integrations.devices.sel.settings.inventory import (
    build_inventory,
    firmware_order_key,
    inventory_csv,
)


READS = Path(__file__).parent / "fixtures" / "sel" / "reads"
NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)


def _device(site, endpoint, runs):
    return {"key": "{0}/{1}".format(site, endpoint), "site": site, "endpoint": endpoint, "captures": runs}


def _run(stamp, fid, status="ok"):
    from sel_triage.integrations.devices.sel.settings.files import parse_id_text

    identity = parse_id_text('"FID={0}"'.format(fid)) if fid else {}
    return {"run": stamp, "captured_at": stamp, "status": status, "identity": identity,
            "settings": {"1": {}} if status == "ok" else {}, "banner": {}}


class TestFirmwareOrder(unittest.TestCase):
    def test_revision_then_date_then_version(self):
        fids = [
            "SEL-735-R207-V3-Z102100-D20230203",
            "SEL-735-R208-V1-Z103100-D20240429",
            "SEL-735-R207-V1-Z102100-D20220601",
        ]
        ordered = sorted(fids, key=firmware_order_key)
        self.assertEqual(ordered[-1], "SEL-735-R208-V1-Z103100-D20240429")
        self.assertEqual(ordered[0], "SEL-735-R207-V1-Z102100-D20220601")


class TestBuildInventory(unittest.TestCase):
    def setUp(self):
        self.result = build_inventory(discover_devices(READS), now=NOW)
        self.rows = {row["device"]: row for row in self.result["rows"]}

    def test_one_row_per_device(self):
        self.assertEqual(len(self.result["rows"]), 8)
        alpha = self.rows["Alpha Solar/192.0.2.11_2381"]
        self.assertEqual(alpha["site"], "Alpha Solar")
        self.assertEqual(alpha["model"], "SEL-751")
        self.assertEqual(alpha["firmware_revision"], "R400")
        self.assertEqual(alpha["firmware_date"], "2024-10-31")
        self.assertEqual(alpha["capture_date"], "2026-06-01T12:00:00Z")
        self.assertEqual(alpha["captures"], 2)
        self.assertEqual(alpha["device_id"], "ALPHA RELAY")

    def test_mixed_firmware_and_behind_flags(self):
        older = self.rows["Bravo Solar/192.0.2.21_2381"]
        newer = self.rows["Bravo Solar/192.0.2.22_2381"]
        self.assertIn("firmware_behind", older["flags"])
        self.assertNotIn("firmware_behind", newer["flags"])
        self.assertIn("mixed_firmware_at_site", older["flags"])
        self.assertIn("mixed_firmware_at_site", newer["flags"])
        codes = [(f["code"], f["evidence"].get("device")) for f in self.result["findings"]]
        self.assertIn(("firmware_behind", "Bravo Solar/192.0.2.21_2381"), codes)

    def test_failed_device(self):
        row = self.rows["Delta Solar/192.0.2.42_2381"]
        self.assertIsNone(row["model"])
        self.assertEqual(row["failed_captures"], 1)
        self.assertIn("no_successful_capture", row["flags"])

    def test_stale_capture_threshold(self):
        self.assertFalse(any("capture_stale" in row["flags"] for row in self.result["rows"]))
        later = build_inventory(discover_devices(READS), now=NOW, max_age_days=35)
        stale = [row["device"] for row in later["rows"] if "capture_stale" in row["flags"]]
        self.assertIn("Charlie Solar/192.0.2.32_2381", stale)
        self.assertNotIn("Alpha Solar/192.0.2.11_2381", stale)

    def test_summary(self):
        summary = self.result["summary"]
        self.assertEqual(summary["devices"], 8)
        self.assertEqual(summary["capture_runs"], 9)
        self.assertEqual(summary["models"]["SEL-700G"], 2)
        self.assertEqual(
            summary["newest_firmware"]["SEL-700G"], "SEL-700G-R302-V0-Z008004-D20220826"
        )
        self.assertEqual(summary["flags"]["mixed_firmware_at_site"], 2)

    def test_identity_change_between_captures(self):
        device = _device("S", "e", [
            _run("2026-01-01T00:00:00Z", "SEL-751-R300-V1-Z008004-D20200603"),
            _run("2026-02-01T00:00:00Z", "SEL-751-R400-V4-Z100100-D20241031"),
        ])
        row = build_inventory([device], now=NOW)["rows"][0]
        self.assertIn("firmware_changed", row["flags"])
        self.assertEqual(row["firmware_revision"], "R400")

    def test_csv(self):
        text = inventory_csv(self.result)
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(len(rows), 8)
        self.assertIn("flags", rows[0])
        self.assertEqual(rows[0]["site"], "Alpha Solar")


if __name__ == "__main__":
    unittest.main()
