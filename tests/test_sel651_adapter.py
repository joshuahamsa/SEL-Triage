from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.integrations.devices.sel.adapters.sel651 import Sel651Adapter
from sel_triage.integrations.devices.sel import client as sel_client


FIXTURES = Path(__file__).parent / "fixtures" / "sel"


def fixture(name):
    return (FIXTURES / name).read_text()


class TestSel651Adapter(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel651Adapter()

    def test_adapter_declares_only_capture_backed_capabilities(self):
        self.assertEqual(self.adapter.family, "sel651")
        self.assertEqual(
            self.adapter.capabilities,
            (
                "identity",
                "status",
                "meter",
                "history",
                "eve",
                "cev",
                "cev_raw",
                "ser",
            ),
        )

    def test_651r2_identity_normalizes_hyphenated_firmware_model(self):
        result = self.adapter.parse("identity", fixture("651r2-id.txt"))

        self.assertEqual(result["observed_model"], "SEL-651R2")
        self.assertEqual(result["device_id"], "LAB-RECLOSER-01")
        self.assertEqual(
            result["firmware_id"],
            "SEL-651R-2-R411-V1-Z011003-D20211018",
        )
        self.assertIn("ID", result["unparsed_lines"])

    def test_client_identity_accepts_captured_651r2_firmware_spelling(self):
        identity = sel_client._normalize_identity(fixture("651r2-id.txt"))

        self.assertEqual(identity.observed_model, "SEL-651R2")
        self.assertEqual(sel_client._family_for(identity.observed_model), "sel651")

    def test_651r2_status_parses_clock_source_and_recloser_state(self):
        result = self.adapter.parse("status", fixture("651r2-status.txt"))

        self.assertEqual(result["clock"], "2026-07-15T13:07:41.041")
        self.assertEqual(result["time_source"], "internal")
        self.assertEqual(
            result["details"],
            {"recloser_state": "ENABLED", "temperature_c": 50.8},
        )
        self.assertIn("SELF TESTS", result["unparsed_lines"])

    def test_651r2_meter_parses_common_phase_and_power_fields(self):
        result = self.adapter.parse("meter", fixture("651r2-meter.txt"))

        self.assertEqual(result["frequency_hz"], 60.01)
        self.assertEqual(result["active_power_mw"], -0.0)
        self.assertEqual(
            result["phases"],
            [
                {"phase": "A", "voltage_kv": 7.095, "current_a": 0.012},
                {"phase": "B", "voltage_kv": 7.246, "current_a": 0.010},
                {"phase": "C", "voltage_kv": 7.301, "current_a": 0.015},
            ],
        )
        self.assertIn("Vbase (kV)       0.000", result["unparsed_lines"])

    def test_651r2_history_parses_number_time_type_and_retains_family_fields(self):
        result = self.adapter.parse("history", fixture("651r2-history.txt"))

        self.assertEqual(len(result["events"]), 4)
        self.assertEqual(result["events"][0]["event_number"], 1)
        self.assertEqual(
            result["events"][0]["timestamp"], "2026-07-15T09:33:58.858"
        )
        self.assertEqual(result["events"][0]["event_type"], "TRIP")
        self.assertIn("source_fields", result["events"][0]["details"])
        self.assertEqual(result["events"][1]["event_type"], "CAG T")

    def test_breaker_wear_is_explicitly_unavailable(self):
        with self.assertRaisesRegex(ValueError, "command_unavailable.*breaker"):
            self.adapter.parse("breaker", "")

    def test_unlabeled_meter_values_are_not_inferred(self):
        result = self.adapter.parse("meter", "FREQ  (Hz)  60.0\n999 888 777\n")

        self.assertEqual(result["frequency_hz"], 60.0)
        self.assertNotIn("phases", result)
        self.assertNotIn("active_power_mw", result)
        self.assertIn("999 888 777", result["unparsed_lines"])

    def test_current_only_phase_table_remains_unparsed(self):
        header = "A B C N G"
        row = "I MAG (A) 1.0 2.0 3.0 4.0 5.0"

        result = self.adapter.parse("meter", "{0}\n{1}\n".format(header, row))

        self.assertNotIn("phases", result)
        self.assertIn(header, result["unparsed_lines"])
        self.assertIn(row, result["unparsed_lines"])

    def test_voltage_only_phase_table_remains_unparsed(self):
        header = "VAY VBY VCY VAZ VBZ VCZ"
        row = "V MAG (kV) 1.0 2.0 3.0 4.0 5.0 6.0"

        result = self.adapter.parse("meter", "{0}\n{1}\n".format(header, row))

        self.assertNotIn("phases", result)
        self.assertIn(header, result["unparsed_lines"])
        self.assertIn(row, result["unparsed_lines"])

    def test_family_aliases_select_the_same_adapter(self):
        for model in ("SEL-651", "sel-651ra", "SEL-651R2"):
            with self.subTest(model=model):
                selection = adapter_for(model)
                self.assertEqual(selection.adapter.family, "sel651")


if __name__ == "__main__":
    unittest.main()
