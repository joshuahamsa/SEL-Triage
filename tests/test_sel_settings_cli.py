import contextlib
import csv
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sel_triage import cli


READS = Path(__file__).parent / "fixtures" / "sel" / "reads"
ALPHA = READS / "Alpha Solar" / "192.0.2.11_2381"
NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)


class SelSettingsCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Path(self.tmp.name) / "config.json"
        self.cfg.write_text(json.dumps({}))

    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv) + ["--config", str(self.cfg)], now=NOW)
        return code, out.getvalue(), err.getvalue()

    def test_inventory_json(self):
        code, out, err = self.main("sel-inventory", str(READS))
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual(result["tool"], "sel-inventory")
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"]["devices"], 8)
        self.assertEqual(len(result["rows"]), 8)

    def test_inventory_csv(self):
        code, out, err = self.main("sel-inventory", str(READS), "--csv")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(out)))), 8)

    def test_inventory_render_and_age_threshold_from_config(self):
        self.cfg.write_text(json.dumps({"diagnosticThresholds": {"sel_capture_max_age_days": 35}}))
        code, out, err = self.main("sel-inventory", str(READS), "--render")
        self.assertEqual(code, 0, err)
        self.assertIn("sel-inventory", out)
        self.assertIn("SEL-700G", out)
        self.assertIn("capture_stale", out)

    def test_inventory_missing_folder(self):
        code, out, err = self.main("sel-inventory", str(READS / "nope"))
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_check_json_and_render(self):
        code, out, err = self.main("sel-settings", "check", str(READS))
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual(result["tool"], "sel-settings-check")
        self.assertIn("phase_rotation_acb", result["summary"]["findings_by_code"])
        code, out, err = self.main("sel-settings", "check", str(READS), "--render")
        self.assertEqual(code, 0, err)
        self.assertIn("phase_rotation_differs_site_peers", out)
        self.assertIn("Delta Solar/192.0.2.41_2381", out)

    def test_check_rules_listing(self):
        code, out, err = self.main("sel-settings", "rules")
        self.assertEqual(code, 0, err)
        self.assertIn("trip_equations_empty", json.loads(out)["rules"][7]["code"])

    def test_check_bad_rule_config(self):
        self.cfg.write_text(json.dumps({"selSettingsChecks": {"disabledRules": ["nope"]}}))
        code, out, err = self.main("sel-settings", "check", str(READS))
        self.assertEqual(code, 2)
        self.assertIn("nope", err)

    def test_diff(self):
        code, out, err = self.main("sel-settings", "diff", str(ALPHA))
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual(result["tool"], "sel-settings-diff")
        self.assertEqual(result["changes"], [{"class": "1", "key": "CTR", "a": "100", "b": "500"}])
        code, out, err = self.main(
            "sel-settings", "diff",
            str(READS / "Bravo Solar" / "192.0.2.21_2381"), str(READS / "Bravo Solar" / "192.0.2.22_2381"),
            "--render",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("CTRX", out)
        self.assertNotIn("BRAVO GEN", out)

    def test_threshold_names_are_registered(self):
        self.cfg.write_text(json.dumps({"diagnosticThresholds": {"sel_nominal_frequency_hz": 50}}))
        code, out, err = self.main("sel-settings", "check", str(READS))
        self.assertEqual(code, 0, err)
        self.assertIn("nominal_frequency_unexpected", json.loads(out)["summary"]["findings_by_code"])


if __name__ == "__main__":
    unittest.main()
