"""SEL-851 parsers, built from an anonymized live capture (2026-09-25)."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel import client as sel_client
from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.integrations.devices.sel.adapters.sel851 import Sel851Adapter
from sel_triage.integrations.devices.sel.commands import COMMANDS_BY_FAMILY


FIXTURES = Path(__file__).parent / "fixtures" / "sel"
IDENTITY = FIXTURES / "identity" / "id-sel-851.txt"


def fixture(name):
    return (FIXTURES / name).read_text()


class TestSel851Adapter(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel851Adapter()

    def test_851_selects_its_own_family(self):
        self.assertEqual(sel_client._family_for("SEL-851"), "sel851")
        self.assertEqual(adapter_for("SEL-851").adapter.family, "sel851")

    def test_capabilities_and_read_only_command_policy(self):
        # A live 851 answers '"BRE" unknown.', so breaker is not applicable.
        self.assertEqual(self.adapter.capabilities, ("identity", "status", "meter", "history", "target"))
        self.assertEqual(self.adapter.not_applicable, ("breaker",))
        self.assertEqual(
            {name: command.wire_text for name, command in COMMANDS_BY_FAMILY["sel851"].items() if name != "help"},
            {"identity": "ID", "status": "STA", "meter": "MET", "history": "HIS", "target": "TAR", "eve": "EVE", "ser": "SER", "file_read": "FILE READ", "file_show": "FILE SHOW"},
        )

    def test_identity_is_parsed_from_real_capture(self):
        # This capture keeps SEL STX/ETX framing; SelClient.run strips it before parsing.
        text = IDENTITY.read_text().replace("\x02", "").replace("\x03", "")
        result = self.adapter.parse("identity", text)
        self.assertEqual(result["observed_model"], "SEL-851")
        self.assertEqual(result["device_id"], "LAB-RELAY-01")

    def test_status_parses_clock_self_tests_and_enable(self):
        result = self.adapter.parse("status", fixture("851-status.txt"))
        self.assertEqual(result["clock"], "2026-09-25T15:33:42.576")
        self.assertEqual(result["time_source"], "internal")
        self.assertEqual(result["self_test"], "OK")
        self.assertEqual(result["details"]["self_tests"]["CLK_BAT"], "OK")
        self.assertEqual(result["details"]["self_tests"]["DAQ"], "OK")
        self.assertTrue(result["details"]["relay_enabled"])

    def test_meter_parses_tables_short_rows_and_labeled_lines(self):
        result = self.adapter.parse("meter", fixture("851-meter.txt"))
        self.assertEqual(result["frequency_hz"], 59.98)
        self.assertEqual(result["active_power_mw"], 0.270741)
        self.assertEqual(
            result["phases"],
            [
                {"phase": "A", "voltage_kv": 0.28642, "current_a": 329.98},
                {"phase": "B", "voltage_kv": 0.28692, "current_a": 329.78},
                {"phase": "C", "voltage_kv": 0.28697, "current_a": 330.32},
            ],
        )
        d = result["details"]
        self.assertEqual(d["currents_a"]["IG"], 1.04)
        self.assertEqual(d["current_angles_deg"]["IC"], 137.5)
        self.assertEqual(d["voltages_ll_v"], {"VAB": 496.35, "VBC": 497.2, "VCA": 496.53, "VAVG": 496.69})
        self.assertEqual(d["voltage_ll_angles_deg"], {"VAB": 30.1, "VBC": -89.9, "VCA": 150.0})
        self.assertEqual(d["voltages_ln_v"]["3V0"], 0.19)
        self.assertEqual(d["sequence_magnitudes"], {"I1": 330.01, "3I2": 0.68, "V1": 286.77, "3V2": 0.9})
        self.assertEqual(d["average_current_a"], 330.03)
        self.assertEqual(d["power_kw"], 270.741)
        self.assertEqual(d["reactive_kvar"], -85.5)
        self.assertEqual(d["apparent_kva"], 283.921)
        self.assertEqual(d["power_factor"], 0.95)
        self.assertEqual(d["power_factor_direction"], "LEAD")

    def test_history_parses_multi_word_events(self):
        events = self.adapter.parse("history", fixture("851-history.txt"))["events"]
        self.assertEqual(len(events), 13)
        self.assertEqual(
            events[0],
            {"event_number": 10313, "timestamp": "2026-08-05T01:51:38.327", "event_type": "Undefined Trip",
             "details": {"current_a": 2.3, "frequency_hz": 60.03, "targets": "1101100010"}},
        )
        self.assertEqual(events[6]["event_type"], "Event Report Trigger")

    def test_target_parses_one_led_per_line(self):
        targets = self.adapter.parse("target", fixture("851-target.txt"))["targets"]
        self.assertEqual(targets[:2], [{"name": "EnaLED.Sta", "asserted": True}, {"name": "TripLED.Sta", "asserted": False}])
        self.assertEqual(len(targets), 8)

    def test_trip_led_asserted_is_flagged(self):
        from sel_triage.integrations.devices.sel.diagnostics import diagnose_snapshot

        text = fixture("851-target.txt").replace("TripLED.Sta                       0", "TripLED.Sta                       1")
        targets = self.adapter.parse("target", text)
        codes = [f["code"] for f in diagnose_snapshot({"snapshot": {"target": targets}}, None, None)]
        self.assertIn("trip_target_asserted", codes)

    def test_parsers_leave_only_banner_lines_unparsed(self):
        for capability in ("status", "meter", "history", "target"):
            with self.subTest(capability=capability):
                result = self.adapter.parse(capability, fixture("851-{0}.txt".format(capability)))
                leftovers = [
                    line for line in result["unparsed_lines"]
                    if not line.startswith("ANONYMIZED CAPTURE:")
                    and line.strip() not in {"STA", "MET", "HIS", "TAR", "=>"}
                    and not line.strip().startswith(("SEL-851", "LAB SITE", "Serial Num", "FID =", "PART NUM"))
                ]
                self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
