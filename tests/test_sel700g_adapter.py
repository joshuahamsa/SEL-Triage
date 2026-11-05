from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.integrations.devices.sel.adapters.sel700g import Sel700GAdapter


FIXTURES = Path(__file__).parent / "fixtures" / "sel"


def fixture(name):
    return (FIXTURES / name).read_text()


class TestSel700GAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel700GAdapter()

    def test_fixtures_are_marked_synthetic_or_anonymized(self):
        for capability in (
            "id",
            "status",
            "meter",
            "breaker",
            "history",
            "target",
        ):
            with self.subTest(capability=capability):
                text = fixture("700gt-{0}.txt".format(capability))
                self.assertTrue(
                    text.startswith("SYNTHETIC FIXTURE:")
                    or text.startswith("ANONYMIZED CAPTURE:")
                )
                self.assertNotIn("203.0.113.", text)

    def test_adapter_declares_snapshot_capabilities(self):
        self.assertEqual(self.adapter.family, "sel700g")
        self.assertEqual(
            self.adapter.capabilities,
            (
                "identity",
                "status",
                "meter",
                "breaker",
                "history",
                "target",
                "eve",
                "cev",
                "ser",
                "settings_global",
                "settings_group",
                "settings_logic",
                "settings_report",
            ),
        )

    def test_event_requests_number_recent_events_newest_first(self):
        from sel_triage.integrations.devices.sel.adapters.base import (
            EventSelector,
        )

        latest = list(self.adapter.event_requests(EventSelector.latest(2, "cev")))
        self.assertEqual(
            [(r.capability, r.argument, r.extension) for r in latest],
            [("cev", 1, "cev"), ("cev", 2, "cev")],
        )
        numbered = list(self.adapter.event_requests(EventSelector.number(23835)))
        self.assertEqual(
            [(r.capability, r.argument, r.extension) for r in numbered],
            [("eve", 23835, "eve")],
        )

    def test_700gt_identity_uses_labeled_identifiers(self):
        result = self.adapter.parse("identity", fixture("700gt-id.txt"))

        self.assertEqual(
            set(result),
            {"observed_model", "device_id", "firmware_id", "unparsed_lines"},
        )
        self.assertEqual(result["observed_model"], "SEL-700GT")
        self.assertEqual(result["device_id"], "LAB-RELAY-01")
        self.assertTrue(result["firmware_id"].startswith("SEL-700GT-"))
        self.assertIn("ID", result["unparsed_lines"])

    # The fixtures below are anonymized live SEL-700GT output (2026-09-25).

    def test_700gt_status_parses_clock_source_self_tests_and_enable(self):
        result = self.adapter.parse("status", fixture("700gt-status.txt"))

        self.assertEqual(result["clock"], "2026-09-25T16:23:31.819")
        self.assertEqual(result["time_source"], "internal")
        self.assertEqual(result["self_test"], "OK")
        details = result["details"]
        self.assertEqual(details["self_tests"]["FPGA"], "OK")
        self.assertEqual(details["self_tests"]["BATT"], 2.99)
        self.assertEqual(details["self_tests"]["-5.0V"], -4.97)
        self.assertEqual(details["option_cards"], {"CARD_C": "OK", "CARD_D": "OK", "CARD_E": "OK", "CARD_Z": "OK"})
        self.assertEqual(details["offsets_mv"]["ICX"], -1)
        self.assertEqual(details["offsets_mv"]["VS"], -1)
        self.assertTrue(details["relay_enabled"])

    def test_700gt_status_reports_warning_and_failure(self):
        text = fixture("700gt-status.txt")
        warn = self.adapter.parse("status", text.replace("OK    OK    OK    OK    OK", "OK    W     OK    OK    OK", 1))
        fail = self.adapter.parse("status", text.replace("OK    OK    OK    OK    OK", "OK    FAIL  OK    OK    OK", 1))
        self.assertEqual(warn["self_test"], "WARN")
        self.assertEqual(fail["self_test"], "FAIL")

    def test_700gt_meter_parses_phases_power_and_frequency(self):
        result = self.adapter.parse("meter", fixture("700gt-meter.txt"))

        self.assertEqual(result["frequency_hz"], 59.96)
        self.assertEqual(result["active_power_mw"], 1.111)
        self.assertEqual(
            result["phases"],
            [
                {"phase": "A", "voltage_kv": 7.84, "current_a": 48.0},
                {"phase": "B", "voltage_kv": 7.908, "current_a": 50.3},
                {"phase": "C", "voltage_kv": 7.8501, "current_a": 47.6},
            ],
        )
        details = result["details"]
        self.assertEqual(details["currents_a"]["IGX"], 0.5)
        self.assertEqual(details["voltages_v"]["VAY"], 0.0)
        self.assertEqual(details["power_kw"]["3PX"], 1111)
        self.assertEqual(details["reactive_kvar"]["AX"], 103)
        self.assertEqual(details["power_factor"]["BX"], 0.97)
        self.assertEqual(details["power_factor_direction"]["CX"], "LAG")
        self.assertEqual(details["frequencies_hz"], {"FREQX": 59.96, "FREQY": 60.0, "FREQS": 60.0})
        self.assertEqual(details["volts_per_hz_percent"], 103.6)

    def test_700gt_breaker_parses_counters_currents_and_wear(self):
        result = self.adapter.parse("breaker", fixture("700gt-breaker.txt"))

        self.assertEqual(result["breaker_wear_percent"], 100.0)
        self.assertEqual(result["operation_count"], 13234)
        details = result["details"]
        self.assertEqual(details["breaker"], "X")
        self.assertEqual(details["relay_trip_count"], 13234)
        self.assertEqual(details["external_trip_count"], 0)
        self.assertEqual(details["wear_percent"], {"A": 100, "B": 100, "C": 100})
        self.assertEqual(details["relay_trip_current_ka"], {"IA": 321.5, "IB": 368.5, "IC": 369.3})
        self.assertEqual(details["external_trip_current_ka"], {"IA": 0.0, "IB": 0.0, "IC": 0.0})
        self.assertEqual(details["last_reset"], "2024-10-11T10:05:18")

    def test_700gt_history_parses_event_rows(self):
        result = self.adapter.parse("history", fixture("700gt-history.txt"))

        self.assertEqual(len(result["events"]), 6)
        self.assertEqual(
            result["events"][0],
            {
                "event_number": 1,
                "timestamp": "2026-09-19T14:31:34.342",
                "event_type": "ER Trigger",
                "details": {
                    "reference": 23551,
                    "current_a": 30.2,
                    "frequency_x_hz": 60.1,
                    "frequency_y_hz": 60.0,
                    "targets": "11000000",
                },
            },
        )

    def test_700gt_target_parses_led_row(self):
        result = self.adapter.parse("target", fixture("700gt-target.txt"))

        self.assertEqual(result["targets"][0], {"name": "ENABLED", "asserted": True})
        self.assertEqual(result["targets"][1], {"name": "TRIP_LED", "asserted": False})
        self.assertEqual([t["name"] for t in result["targets"]][2:], ["TLED_0{0}".format(i) for i in range(1, 7)])

    def test_700gt_asserted_trip_led_is_reported(self):
        tripped = fixture("700gt-target.txt").replace("1         0", "1         1", 1)
        result = self.adapter.parse("target", tripped)
        self.assertEqual(result["targets"][1], {"name": "TRIP_LED", "asserted": True})

    def test_700gt_parsers_leave_little_unparsed(self):
        for capability, name in (("status", "status"), ("meter", "meter"), ("breaker", "breaker"),
                                 ("history", "history"), ("target", "target")):
            with self.subTest(capability=capability):
                result = self.adapter.parse(capability, fixture("700gt-{0}.txt".format(name)))
                leftovers = [
                    line for line in result["unparsed_lines"]
                    if not line.startswith("ANONYMIZED CAPTURE:")
                    and line.strip() not in {"STA", "MET", "BRE", "HIS", "TAR", "=>"}
                    and not line.strip().startswith(("SEL-700GT", "LAB SITE", "Serial Num", "CID =", "FID="))
                ]
                self.assertEqual(leftovers, [])

    def test_unlabeled_numbers_are_not_inferred(self):
        result = self.adapter.parse(
            "meter",
            "                FREQX  FREQY  FREQS\n"
            "Frequency (Hz)  60.00  60.00  60.00\n"
            "Unlabeled: 999 888 777\n=>\n",
        )

        self.assertEqual(result["frequency_hz"], 60.0)
        self.assertNotIn("active_power_mw", result)
        self.assertNotIn("phases", result)
        self.assertIn("Unlabeled: 999 888 777", result["unparsed_lines"])

    def test_unknown_capability_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported capability"):
            self.adapter.parse("settings", "")

    def test_model_hint_mismatch_uses_observed_identity(self):
        selection = adapter_for("SEL-700GT", "SEL-751")

        self.assertEqual(selection.adapter.family, "sel700g")
        self.assertEqual(selection.warning["code"], "model_mismatch")
        self.assertEqual(selection.warning["observed_model"], "SEL-700GT")
        self.assertEqual(selection.warning["model_hint"], "SEL-751")
        self.assertIn("SEL-751", selection.warning["message"])
        self.assertIn("SEL-700GT", selection.warning["message"])

    def test_700gt_hint_matches_700g_firmware_model_without_warning(self):
        # Live SEL-700GT: FID reports SEL-700G, DEVID reports SEL-700GT.
        selection = adapter_for("SEL-700G", "SEL-700GT")
        self.assertEqual(selection.adapter.family, "sel700g")
        self.assertIsNone(selection.warning)

    def test_700g_and_700gt_select_the_same_family(self):
        for model in ("SEL-700G", "sel-700gt"):
            with self.subTest(model=model):
                selection = adapter_for(model, None)
                self.assertEqual(selection.adapter.family, "sel700g")
                self.assertIsNone(selection.warning)


if __name__ == "__main__":
    unittest.main()
