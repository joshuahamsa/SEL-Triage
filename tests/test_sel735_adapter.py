"""SEL-735 parsers, built from an anonymized live capture (2026-09-25)."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel import client as sel_client
from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.integrations.devices.sel.adapters.sel735 import Sel735Adapter
from sel_triage.integrations.devices.sel.commands import COMMANDS_BY_FAMILY


FIXTURES = Path(__file__).parent / "fixtures" / "sel"
IDENTITY = FIXTURES / "identity" / "id-sel-735.txt"


def fixture(name):
    return (FIXTURES / name).read_text()


class TestSel735Adapter(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel735Adapter()

    def test_735_selects_its_own_family(self):
        self.assertEqual(sel_client._family_for("SEL-735"), "sel735")
        self.assertEqual(adapter_for("SEL-735").adapter.family, "sel735")

    def test_capabilities_exclude_breaker(self):
        self.assertEqual(self.adapter.capabilities, ("identity", "status", "meter", "history", "target"))

    def test_command_policy_is_read_only_level1_set(self):
        commands = COMMANDS_BY_FAMILY["sel735"]
        self.assertEqual(
            {name: command.wire_text for name, command in commands.items() if name != "help"},
            {"identity": "ID", "status": "STA", "meter": "MET", "history": "HIS", "target": "TAR", "eve": "EVE", "ser": "SER", "file_read": "FILE READ", "file_show": "FILE SHOW"},
        )

    def test_identity_is_parsed_from_real_capture(self):
        result = self.adapter.parse("identity", IDENTITY.read_text())
        self.assertEqual(result["observed_model"], "SEL-735")
        self.assertEqual(result["device_id"], "LAB-RELAY-01")
        self.assertTrue(result["firmware_id"].startswith("SEL-735-R208"))

    def test_status_parses_clock_self_tests_battery_warning_and_enable(self):
        result = self.adapter.parse("status", fixture("735-status.txt"))

        self.assertEqual(result["clock"], "2026-09-25T12:57:01.119")
        self.assertEqual(result["time_source"], "internal")
        self.assertEqual(result["self_test"], "WARN")  # Batt 2.78W
        details = result["details"]
        self.assertEqual(details["self_tests"], {"RAM": "OK", "ROM": "OK", "CR_RAM": "OK", "NONVOL": "OK", "MISC_BRD": "OK", "PS": "OK"})
        self.assertEqual(details["battery_v"], 2.78)
        self.assertTrue(details["battery_warning"])
        self.assertEqual(details["temperature_c"], 35.0)
        self.assertEqual(details["offsets"]["IN"], 1)
        self.assertTrue(details["meter_enabled"])
        self.assertEqual(details["warning_items"], ["Batt"])

    def test_meter_parses_phases_power_sequence_and_frequency(self):
        result = self.adapter.parse("meter", fixture("735-meter.txt"))

        self.assertEqual(result["frequency_hz"], 60.0)
        self.assertEqual(result["active_power_mw"], 0.2778)
        self.assertEqual(
            result["phases"],
            [
                {"phase": "A", "voltage_kv": 0.28843, "current_a": 320.25},
                {"phase": "B", "voltage_kv": 0.28876, "current_a": 322.86},
                {"phase": "C", "voltage_kv": 0.28599, "current_a": 322.44},
            ],
        )
        d = result["details"]
        self.assertEqual(d["currents_a"]["N"], 8.43)
        self.assertEqual(d["current_angles_deg"]["B"], 121.67)
        self.assertEqual(d["voltages_ln_v"]["C"], 285.99)
        self.assertEqual(d["voltages_ll_v"], {"AB": 501.45, "BC": 497.28, "CA": 496.34})
        self.assertEqual(d["power_kw"]["3P"], 277.8)
        self.assertEqual(d["apparent_kva"]["B"], 93.23)
        self.assertEqual(d["reactive_kvar"]["rec_lead"]["3P"], 2.65)
        self.assertEqual(d["power_factor"]["3P"], 1.0)
        self.assertEqual(d["power_factor_direction"]["A"], "LEAD")
        self.assertEqual(d["sequence_magnitudes"], {"I1": 1.75, "3I2": 964.66, "3I0": 8.49, "V1": 1.81, "V2": 287.7, "3V0": 0.37})
        self.assertEqual(d["voltage_percent_nominal"]["A"], 104.07)
        self.assertEqual(d["frequency_percent_nominal"], 100.0)

    def test_history_parses_two_digit_year_rows(self):
        result = self.adapter.parse("history", fixture("735-history.txt"))

        self.assertEqual(len(result["events"]), 30)
        self.assertEqual(
            result["events"][0],
            {
                "event_number": 10289,
                "timestamp": "2026-09-13T16:48:22.988",
                "event_type": "ER",
                "details": {"frequency_hz": 59.98, "targets": "0001111"},
            },
        )

    def test_target_parses_led_row_including_star_column(self):
        result = self.adapter.parse("target", fixture("735-target.txt"))

        self.assertEqual(
            [(t["name"], t["asserted"]) for t in result["targets"]],
            [("LED6", False), ("LED5", False), ("LED4", False), ("LED3", True),
             ("LED2", True), ("LED1", True), ("*", False), ("ENABLE", True)],
        )

    def test_parsers_leave_only_banner_lines_unparsed(self):
        for capability in ("status", "meter", "history", "target"):
            with self.subTest(capability=capability):
                result = self.adapter.parse(capability, fixture("735-{0}.txt".format(capability)))
                leftovers = [
                    line for line in result["unparsed_lines"]
                    if not line.startswith("ANONYMIZED CAPTURE:")
                    and line.strip() not in {"STA", "MET", "HIS", "TAR", "=>", "W=Warn    F=Fail"}
                    and not line.strip().startswith(("FID=", "S/N:"))
                ]
                self.assertEqual(leftovers, [])
                self.assertNotIn("capture_only", result)

    def test_breaker_is_rejected(self):
        with self.assertRaises(ValueError):
            self.adapter.parse("breaker", "BRE\n=>\n")


if __name__ == "__main__":
    unittest.main()
