"""SEL-351 family parsers, built from anonymized live 351A/351S captures (2026-09-25)."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel import client as sel_client
from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.integrations.devices.sel.adapters.sel351 import Sel351Adapter
from sel_triage.integrations.devices.sel.commands import COMMANDS_BY_FAMILY


FIXTURES = Path(__file__).parent / "fixtures" / "sel"
IDENTITY = FIXTURES / "identity"


def fixture(name):
    return (FIXTURES / name).read_text()


class TestSel351Adapter(unittest.TestCase):
    def setUp(self):
        self.adapter = Sel351Adapter()

    def test_351_variants_select_the_same_family(self):
        for model in ("SEL-351", "SEL-351A", "sel-351s"):
            with self.subTest(model=model):
                self.assertEqual(sel_client._family_for(model.upper()), "sel351")
                selection = adapter_for(model)
                self.assertEqual(selection.adapter.family, "sel351")
                self.assertIsNone(selection.warning)

    def test_capabilities_and_read_only_command_policy(self):
        self.assertEqual(
            self.adapter.capabilities,
            ("identity", "status", "meter", "breaker", "history", "target"),
        )
        self.assertEqual(
            {name: command.wire_text for name, command in COMMANDS_BY_FAMILY["sel351"].items() if name != "help"},
            {"identity": "ID", "status": "STA", "meter": "MET", "breaker": "BRE", "history": "HIS", "target": "TAR", "eve": "EVE", "ser": "SER", "file_read": "FILE READ", "file_show": "FILE SHOW"},
        )

    def test_identity_is_parsed_for_each_variant(self):
        for model in ("SEL-351", "SEL-351A", "SEL-351S"):
            with self.subTest(model=model):
                text = (IDENTITY / "id-{0}.txt".format(model.lower())).read_text()
                result = self.adapter.parse("identity", text)
                self.assertEqual(result["observed_model"], model)
                self.assertEqual(result["device_id"], "LAB-RELAY-01")

    def test_status_parses_clock_self_tests_supplies_offsets_and_enable(self):
        result = self.adapter.parse("status", fixture("351a-status.txt"))

        self.assertEqual(result["clock"], "2026-09-25T21:21:44.750")
        self.assertEqual(result["self_test"], "OK")
        d = result["details"]
        self.assertEqual(d["self_tests"]["USB_BRD"], "OK")
        self.assertEqual(d["self_tests"]["RTC"], "OK")
        self.assertEqual(d["temperature_c"], 35.8)
        self.assertEqual(d["power_supplies_v"], {"15V_PS": 14.86, "5V_REG": 5.0, "3.3V_REG": 3.3})
        self.assertEqual(d["offsets"]["MOF"], 0)
        self.assertEqual(d["offsets_high"], {"IA": -1, "IB": 0, "IC": 0, "IN": 0})
        self.assertTrue(d["relay_enabled"])

    def test_status_na_self_test_is_not_a_warning(self):
        text = fixture("351a-status.txt").replace("COM_BRD \n", "COM_BRD IO_BRD\n").replace(
            "OK      OK      OK      OK      OK      OK      OK      OK      \n",
            "OK      OK      OK      OK      OK      OK      OK      OK      NA\n")
        result = self.adapter.parse("status", text)
        self.assertEqual(result["details"]["self_tests"]["IO_BRD"], "NA")
        self.assertEqual(result["self_test"], "OK")

    def test_meter_parses_kv_phases_mw_power_and_sequence_in_volts(self):
        result = self.adapter.parse("meter", fixture("351a-meter.txt"))

        self.assertEqual(result["frequency_hz"], 60.02)
        self.assertEqual(result["active_power_mw"], 0.0)
        self.assertEqual(
            result["phases"],
            [
                {"phase": "A", "voltage_kv": 13.951, "current_a": 0.0},
                {"phase": "B", "voltage_kv": 14.013, "current_a": 0.0},
                {"phase": "C", "voltage_kv": 13.942, "current_a": 0.0},
            ],
        )
        d = result["details"]
        self.assertEqual(d["currents_a"]["G"], 0.0)
        self.assertEqual(d["voltages_kv"]["S"], 0.0)
        self.assertEqual(d["voltage_angles_deg"]["B"], -120.19)
        self.assertEqual(d["power_mw"]["3P"], 0.0)
        self.assertEqual(d["reactive_mvar"]["A"], 0.0)
        self.assertEqual(d["power_factor"]["3P"], 1.0)
        self.assertEqual(d["power_factor_direction"]["3P"], "LAG")
        self.assertEqual(d["sequence_magnitudes"], {"I1": 0.0, "3I2": 0.0, "3I0": 0.0, "V1": 13968.0, "V2": 43.0, "3V0": 6.0})
        self.assertEqual(d["station_dc_v"], 24.1)

    def test_breaker_parses_wear_counts_currents_times_and_alarms(self):
        result = self.adapter.parse("breaker", fixture("351s-breaker.txt"))

        self.assertEqual(result["breaker_wear_percent"], 35.0)
        self.assertEqual(result["operation_count"], 3539)
        d = result["details"]
        self.assertEqual(d["wear_percent"], {"A": 35, "B": 35, "C": 35})
        self.assertEqual(d["relay_accum_current_ka"], {"A": 5.6, "B": 4.5, "C": 4.7})
        self.assertEqual(d["relay_trip_count"], 3539)
        self.assertEqual(d["external_trip_count"], 0)
        self.assertEqual(d["electrical_op_time_ms"]["average"]["close_c"], 52.8)
        self.assertEqual(d["mechanical_op_time_ms"]["last"], {"trip": 45.8, "close": 58.3})
        self.assertEqual(d["last_op_minimum_vdc"], {"trip": 23.9, "close": 24.2})
        self.assertEqual(d["operating_time_alarms"], {"mechanical": 7, "electrical": 24})
        self.assertEqual(d["last_reset"], "2022-05-03T20:03:37")

    def test_breaker_op_times_marked_over_range(self):
        text = fixture("351s-breaker.txt").replace("29.2    29.2    33.3", "45.9    50.0+   50.0+")
        d = self.adapter.parse("breaker", text)["details"]
        self.assertEqual(d["electrical_op_time_ms"]["last"]["trip_b"], 50.0)
        self.assertEqual(d["electrical_op_time_ms"]["over_range"], ["last.trip_b", "last.trip_c"])

    def test_history_parses_grp_shot_and_target_variants(self):
        a = self.adapter.parse("history", fixture("351a-history.txt"))["events"]
        self.assertEqual(a[0], {"event_number": 1, "timestamp": "2026-06-14T14:03:12.343", "event_type": "TRIP",
                                "details": {"location": "$$$$$$$", "current_a": 0, "frequency_hz": 59.96,
                                            "group": 1, "shot": None, "targets": "INST"}})
        self.assertEqual(a[2]["details"]["targets"], "")
        s = self.adapter.parse("history", fixture("351s-history.txt"))["events"]
        self.assertEqual(s[1], {"event_number": 2, "timestamp": "2026-07-28T11:30:32.940", "event_type": "BC",
                                "details": {"location": "-10.48", "current_a": 2235, "frequency_hz": 59.99,
                                            "group": 1, "shot": 0, "targets": "10000000 10000000"}})
        self.assertEqual(len(s), 25)

    def test_target_parses_named_and_numbered_columns(self):
        a = self.adapter.parse("target", fixture("351a-target.txt"))["targets"]
        self.assertEqual([(t["name"], t["asserted"]) for t in a][:3], [("EN", True), ("TRIP", True), ("INST", True)])
        self.assertEqual([t["name"] for t in a][5:], ["50", "51", "81"])
        s = self.adapter.parse("target", fixture("351s-target.txt"))["targets"]
        self.assertEqual(s[0], {"name": "TLED11", "asserted": True})

    def test_parsers_leave_only_banner_lines_unparsed(self):
        cases = [("351a", c) for c in ("status", "meter", "breaker", "history", "target")]
        cases += [("351s", c) for c in ("breaker", "history", "target")]
        for model, capability in cases:
            with self.subTest(model=model, capability=capability):
                result = self.adapter.parse(capability, fixture("{0}-{1}.txt".format(model, capability)))
                leftovers = [
                    line for line in result["unparsed_lines"]
                    if not line.startswith("ANONYMIZED CAPTURE:")
                    and line.strip() not in {"STA", "MET", "BRE", "HIS", "TAR", "=>", "W=Warn    F=Fail", "SELF TESTS", "LAB SITE"}
                    and not line.strip().startswith(("FID=", "LAB RELAY"))
                ]
                self.assertEqual(leftovers, [])

    def test_trip_target_and_burst_window(self):
        from sel_triage.integrations.devices.sel.diagnostics import diagnose_snapshot

        tripped = {"snapshot": {"target": self.adapter.parse("target", fixture("351a-target.txt"))}}
        codes = [f["code"] for f in diagnose_snapshot(tripped, None, None)]
        self.assertIn("trip_target_asserted", codes)
        bursty = {"clock": "2026-09-25T16:14:43.114",
                  "snapshot": {"history": self.adapter.parse("history", fixture("351s-history.txt"))}}
        # The 2026-02-28 burst is older than the default 30-day window.
        self.assertNotIn("event_burst", [f["code"] for f in diagnose_snapshot(bursty, None, None)])
        wide = diagnose_snapshot(bursty, None, {"event_burst_recent_days": 365})
        self.assertIn("event_burst", [f["code"] for f in wide])


if __name__ == "__main__":
    unittest.main()
