from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.integrations.devices.sel.adapters.sel751 import Sel751Adapter


FIXTURES = Path(__file__).parent / "fixtures" / "sel"


def fixture(name):
    return (FIXTURES / name).read_text()


class TestSel751Adapter(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel751Adapter()

    def test_adapter_declares_snapshot_capabilities(self):
        self.assertEqual(self.adapter.family, "sel751")
        self.assertEqual(
            self.adapter.capabilities,
            ("identity", "status", "meter", "breaker", "history", "target"),
        )

    def test_command_policy_is_read_only_level1_set(self):
        from sel_triage.integrations.devices.sel.commands import COMMANDS_BY_FAMILY

        commands = COMMANDS_BY_FAMILY["sel751"]
        self.assertEqual(
            {name: command.wire_text for name, command in commands.items() if name != "help"},
            {"identity": "ID", "status": "STA", "meter": "MET", "breaker": "BRE", "history": "HIS", "target": "TAR", "eve": "EVE", "ser": "SER", "file_read": "FILE READ", "file_show": "FILE SHOW"},
        )

    def test_real_sanitized_identity_fixture_is_parsed(self):
        result = self.adapter.parse("identity", fixture("751-id.txt"))

        self.assertEqual(result["observed_model"], "SEL-751")
        self.assertEqual(result["device_id"], "LAB-RELAY-01")
        self.assertEqual(
            result["firmware_id"], "SEL-751-R400-V4-Z100100-D20241031"
        )
        self.assertIn("ID", result["unparsed_lines"])

    # Fixtures below are anonymized live SEL-751 output (2026-09-25).

    def test_status_parses_clock_self_tests_and_enable(self):
        result = self.adapter.parse("status", fixture("751-status.txt"))

        self.assertEqual(result["clock"], "2026-09-25T17:06:37.810")
        self.assertEqual(result["time_source"], "internal")
        self.assertEqual(result["self_test"], "OK")
        details = result["details"]
        self.assertEqual(details["self_tests"]["NON_VOL"], "OK")
        self.assertEqual(details["self_tests"]["BATT"], 2.97)
        self.assertEqual(details["option_cards"]["CARD_Z"], "OK")
        self.assertEqual(details["offsets_mv"]["VC"], 0)
        self.assertTrue(details["relay_enabled"])

    def test_meter_parses_phases_sequence_imbalance_power_and_frequency(self):
        result = self.adapter.parse("meter", fixture("751-meter.txt"))

        self.assertEqual(result["frequency_hz"], 60.01)
        self.assertEqual(result["active_power_mw"], -0.269)
        self.assertEqual(
            result["phases"],
            [
                {"phase": "A", "voltage_kv": 0.289, "current_a": 309.8},
                {"phase": "B", "voltage_kv": 0.2897, "current_a": 311.4},
                {"phase": "C", "voltage_kv": 0.2868, "current_a": 312.3},
            ],
        )
        d = result["details"]
        self.assertEqual(d["currents_a"]["IG"], 7.7)
        self.assertEqual(d["voltages_ll_v"], {"VAB": 502.6, "VBC": 498.9, "VCA": 497.4})
        self.assertEqual(d["voltages_ln_v"]["VG"], 0.3)
        self.assertEqual(d["sequence_magnitudes"], {"I1": 311.2, "3I2": 3.4, "V1": 288.5, "3V2": 5.4})
        self.assertEqual(d["average_current_a"], 311.2)
        self.assertEqual(d["current_imbalance_percent"], 0.0)
        self.assertEqual(d["average_phase_voltage_v"], 288)
        self.assertEqual(d["voltage_imbalance_percent"], 0.6)
        self.assertEqual(d["power_kw"]["3P"], -269)
        self.assertEqual(d["power_factor"]["A"], -1.0)
        self.assertEqual(d["power_factor_direction"]["3P"], "LEAD")

    def test_breaker_reports_monitor_disabled(self):
        result = self.adapter.parse("breaker", fixture("751-breaker.txt"))
        self.assertEqual(result["details"], {"monitor_enabled": False})
        self.assertNotIn("breaker_wear_percent", result)

    def test_history_parses_rows_with_location_column(self):
        result = self.adapter.parse("history", fixture("751-history.txt"))

        self.assertEqual(len(result["events"]), 16)
        self.assertEqual(
            result["events"][5],
            {
                "event_number": 6,
                "timestamp": "2026-09-13T13:05:25.945",
                "event_type": "27 Trip",
                "details": {"reference": 10545, "location": "$$$$$", "current_a": 1580.3,
                            "frequency_hz": 59.7, "targets": "11000000"},
            },
        )

    def test_751a_history_without_ref_and_location_columns(self):
        result = self.adapter.parse("history", fixture("751a-history.txt"))

        self.assertEqual(len(result["events"]), 7)
        self.assertEqual(
            result["events"][0],
            {
                "event_number": 1,
                "timestamp": "2025-03-23T14:47:36.339",
                "event_type": "Underfreq 81 Trip",
                "details": {"current_a": 33.0, "frequency_hz": 53.5, "targets": "11000010"},
            },
        )
        self.assertEqual(result["events"][1]["event_type"], "Trip")
        leftovers = [
            line for line in result["unparsed_lines"]
            if not line.startswith("ANONYMIZED CAPTURE:")
            and line.strip() not in {"HIS", "=>"}
            and not line.strip().startswith(("LAB RELAY", "FID ="))
        ]
        self.assertEqual(leftovers, [])

    def test_target_parses_led_row(self):
        result = self.adapter.parse("target", fixture("751-target.txt"))
        self.assertEqual(result["targets"][0], {"name": "ENABLED", "asserted": True})
        self.assertEqual(result["targets"][1], {"name": "TRIP_LED", "asserted": False})

    def test_parsers_leave_only_banner_lines_unparsed(self):
        for capability in ("status", "meter", "breaker", "history", "target"):
            with self.subTest(capability=capability):
                result = self.adapter.parse(capability, fixture("751-{0}.txt".format(capability)))
                leftovers = [
                    line for line in result["unparsed_lines"]
                    if not line.startswith("ANONYMIZED CAPTURE:")
                    and line.strip() not in {"STA", "MET", "BRE", "HIS", "TAR", "=>"}
                    and not line.strip().startswith(("SEL-751", "LAB SITE", "Serial Num", "CID =", "FID="))
                ]
                self.assertEqual(leftovers, [])
                self.assertNotIn("capture_only", result)

    def test_sequence_check_sees_normal_rotation(self):
        from sel_triage.integrations.devices.sel.diagnostics import diagnose_snapshot

        meter = self.adapter.parse("meter", fixture("751-meter.txt"))
        flags = diagnose_snapshot({"snapshot": {"meter": meter}}, None, None)
        self.assertNotIn("phase_sequence_reversed", [f["code"] for f in flags])

    def test_751_and_751a_select_the_same_family(self):
        for model in ("SEL-751", "sel-751a"):
            with self.subTest(model=model):
                selection = adapter_for(model)
                self.assertEqual(selection.adapter.family, "sel751")


if __name__ == "__main__":
    unittest.main()
