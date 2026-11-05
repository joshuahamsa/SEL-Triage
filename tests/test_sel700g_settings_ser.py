from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.adapters.sel700g import Sel700GAdapter
from sel_triage.integrations.devices.sel.parsers.common import parse_settings


FIXTURES = Path(__file__).parent / "fixtures" / "sel"


def fixture(name):
    return (FIXTURES / name).read_text()


# Fixtures are anonymized live SEL-700GT output (R302 firmware, 2026-09-29).
class TestSel700GSettings(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel700GAdapter()

    def test_fixtures_are_anonymized(self):
        for name in ("global", "group", "logic", "report"):
            with self.subTest(name=name):
                text = fixture("700gt-settings-{0}.txt".format(name))
                self.assertTrue(text.startswith("ANONYMIZED CAPTURE:"))
                self.assertNotIn("203.0.113.", text)
                if name == "group":
                    self.assertIn("TID      := LAB SITE", text)

    def test_global_breaker_monitor_settings(self):
        result = self.adapter.parse(
            "settings_global", fixture("700gt-settings-global.txt")
        )
        settings = result["settings"]
        self.assertEqual(settings["EBMONX"], "Y")
        self.assertEqual(settings["BKMONX"], "TRIPX")
        self.assertEqual(settings["COSP1X"], "10000")
        self.assertEqual(settings["KASP3X"], "20.00")
        self.assertEqual(settings["BKMONY"], "TRIPY")
        self.assertIn("Breaker Monitor Settings", result["sections"])
        self.assertNotIn("capture_only", result)

    def test_continuation_lines_fold_into_the_setting_above(self):
        result = self.adapter.parse(
            "settings_global", fixture("700gt-settings-global.txt")
        )
        self.assertEqual(
            result["settings"]["FAULT"],
            "51V OR 51C OR 50PX1P OR 46Q2 OR 67PY1P OR 67QY1P OR 67GY1P OR 67N1P "
            "OR 51PYP OR 51QYP OR 51GYP OR TRIP",
        )

    def test_group_settings_report_active_group_rotation_and_trip_logic(self):
        result = self.adapter.parse(
            "settings_group", fixture("700gt-settings-group.txt")
        )
        settings = result["settings"]
        self.assertEqual(result["group"], 1)
        self.assertEqual(settings["PHROT"], "ABC")
        self.assertEqual(settings["CTRX"], "40")
        self.assertEqual(settings["TRX"], "NOT 3PWRX1T")
        self.assertEqual(settings["ULTRX"], "3PWRX1T")
        self.assertEqual(settings["52AX"], "RMB2A")
        self.assertEqual(settings["LOPBLKX"], "SV13T OR FREQX < MV01")
        self.assertEqual(settings["TID"], "LAB SITE")

    def test_logic_and_report_settings(self):
        logic = self.adapter.parse(
            "settings_logic", fixture("700gt-settings-logic.txt")
        )
        self.assertEqual(logic["group"], 1)
        self.assertEqual(logic["settings"]["OUT101"], "TRIPX")
        self.assertEqual(logic["settings"]["TMB1A"], "TRIPX")
        self.assertEqual(
            logic["settings"]["MV01"], "FREQX * SV14 + MV01 * NOT SV14"
        )

        report = self.adapter.parse(
            "settings_report", fixture("700gt-settings-report.txt")
        )
        self.assertEqual(report["settings"]["ER"], "F_TRIG 3PWRX1P")
        self.assertEqual(report["settings"]["SER2"], "3PWRX1P")
        self.assertEqual(report["settings"]["ALIAS4"], "PB04 FP_TRIP PICKUP DROPOUT")
        self.assertEqual(
            report["settings"]["GSRTRG"], "CLOSEX AND ( 25C OR 25AX1 OR 25AX2 )"
        )
        self.assertEqual(report["settings"]["RA32TYPE"], "I")

    def test_report_prose_is_not_mistaken_for_settings(self):
        report = self.adapter.parse(
            "settings_report", fixture("700gt-settings-report.txt")
        )
        self.assertNotIn("SERn", report["settings"])
        self.assertNotIn("I", report["settings"])
        self.assertIn(
            "Use NA to disable setting.", [l.strip() for l in report["unparsed_lines"]]
        )
        self.assertNotIn("Use NA to disable setting.", report["sections"])

    def test_only_banners_and_prose_remain_unparsed(self):
        echoes = {"SHO G", "SHO", "SHO L", "SHO R", "=>"}
        for name in ("global", "group", "logic", "report"):
            with self.subTest(name=name):
                result = self.adapter.parse(
                    "settings_{0}".format(name),
                    fixture("700gt-settings-{0}.txt".format(name)),
                )
                leftovers = [
                    line
                    for line in result["unparsed_lines"]
                    if not line.startswith("ANONYMIZED CAPTURE:")
                    and line.strip() not in echoes
                    and not line.rstrip().endswith(".")
                    and "=" not in line.replace(":=", "")
                ]
                self.assertEqual(leftovers, [])

    def test_unassigned_lines_before_any_setting_are_kept(self):
        result = parse_settings("junk := \nStray text\n  indented\nFNOM     := 60\n")
        self.assertEqual(result["settings"], {"FNOM": "60"})
        self.assertIn("  indented", result["unparsed_lines"])

    def test_empty_values_and_duplicate_keys(self):
        result = parse_settings("DP12     := \nX1       := A\nX1       := B\n")
        self.assertEqual(result["settings"], {"DP12": "", "X1": "B"})


class TestSel700GSer(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel700GAdapter()

    def test_fixture_is_anonymized(self):
        text = fixture("700gt-ser.txt")
        self.assertTrue(text.startswith("ANONYMIZED CAPTURE:"))
        self.assertNotIn("203.0.113.", text)
        self.assertIn("Serial No = 0000000000", text)

    def test_ser_records_are_parsed_oldest_last_as_printed(self):
        result = self.adapter.parse("ser", fixture("700gt-ser.txt"))
        records = result["records"]
        self.assertEqual(len(records), 16)
        self.assertEqual(
            records[0],
            {
                "number": 1000,
                "timestamp": "2026-09-13T18:45:32.426",
                "element": "3PWRX1P",
                "state": "Deasserted",
            },
        )
        self.assertEqual(records[-1]["number"], 1)
        self.assertEqual(records[-1]["state"], "Asserted")
        self.assertEqual(result["clock"], "2026-09-29T13:23:44.443")
        self.assertEqual(result["time_source"], "internal")

    def test_ser_summary_counts_transitions_per_element(self):
        result = self.adapter.parse("ser", fixture("700gt-ser.txt"))
        self.assertEqual(
            result["element_summary"]["3PWRX1P"],
            {
                "asserted": 6,
                "deasserted": 6,
                "first": "2026-09-13T18:45:32.426",
                "last": "2026-09-26T13:52:58.571",
            },
        )
        self.assertEqual(result["element_summary"]["SALARM"]["asserted"], 2)

    def test_ser_leaves_only_banner_lines(self):
        result = self.adapter.parse("ser", fixture("700gt-ser.txt"))
        leftovers = [
            line
            for line in result["unparsed_lines"]
            if not line.startswith("ANONYMIZED CAPTURE:")
            and line.strip() not in {"SER", "=>"}
            and not line.strip().startswith(("Serial No", "CID ="))
        ]
        self.assertEqual(leftovers, [])

    def test_unrecognized_state_rows_stay_unparsed(self):
        text = fixture("700gt-ser.txt").replace(
            "SALARM                     Asserted", "SALARM                     Maybe", 1
        )
        result = self.adapter.parse("ser", text)
        self.assertEqual(len(result["records"]), 15)
        self.assertTrue(any("Maybe" in line for line in result["unparsed_lines"]))


if __name__ == "__main__":
    unittest.main()
