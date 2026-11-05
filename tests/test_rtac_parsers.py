"""RTAC web output parsers, against synthetic fixtures in the observed layouts."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.rtac import parsers


F = Path(__file__).parent / "fixtures" / "rtac"


def fixture(name):
    return (F / name).read_text()


class RtacParserTests(unittest.TestCase):
    def test_login_token(self):
        self.assertEqual(parsers.login_token(fixture("login.html")), "synthetictoken0123456789abcdef")
        self.assertIsNone(parsers.login_token("<html></html>"))

    def test_session_id_from_auth_response(self):
        self.assertEqual(parsers.session_id("ok 11111111-2222-3333-4444-555555555555"), "11111111-2222-3333-4444-555555555555")
        self.assertIsNone(parsers.session_id("[ ERROR: Login Failure: Invalid Username/Password ]"))

    def test_identity_from_home(self):
        self.assertEqual(
            parsers.parse_home(fixture("home.html")),
            {"observed_model": "SEL-3505-3", "device_id": "SEL-3505-3-000000000000", "communication_active": True},
        )

    def test_soe_rows_skip_blanks_and_normalize_timestamps(self):
        events = parsers.parse_soe(fixture("soe.csv"))
        self.assertEqual(len(events), 11)
        self.assertEqual(
            events[0],
            {"timestamp": "2024-01-10T08:00:00.100", "category": "Internal", "priority": "",
             "tag": "SystemTags.Power_Up_Description",
             "message": "RTAC started with firmware: SEL-3505-3-R146-V1-Z000009-D20200425, project: Factory Default",
             "device_name": "SEL_RTAC"},
        )

    def test_soe_summary(self):
        summary = parsers.summarize_soe(parsers.parse_soe(fixture("soe.csv")))
        self.assertEqual(summary["event_count"], 11)
        self.assertEqual(summary["first_event"], "2024-01-10T08:00:00.100")
        self.assertEqual(summary["last_event"], "2026-09-20T09:05:00.000")
        self.assertEqual(summary["firmware"], "SEL-3505-3-R147-V2-Z000010-D20210101")
        self.assertEqual(summary["project"], "LAB_Curtailment_R2")
        self.assertEqual(summary["last_power_up"], "2026-09-01T10:10:00.500")
        self.assertEqual(summary["power_up_count"], 3)
        self.assertEqual(summary["project_history"], [
            {"timestamp": "2024-01-10T08:00:00.100", "project": "Factory Default", "firmware": "SEL-3505-3-R146-V1-Z000009-D20200425"},
            {"timestamp": "2024-01-10T08:20:00.200", "project": "LAB_Curtailment_R1", "firmware": "SEL-3505-3-R146-V1-Z000009-D20200425"},
            {"timestamp": "2026-09-01T10:10:00.500", "project": "LAB_Curtailment_R2", "firmware": "SEL-3505-3-R147-V2-Z000010-D20210101"},
        ])
        self.assertEqual(summary["tag_counts"]["SystemTags.Unsuccessful_Log_On_Attempt"], 2)

    def test_alarms(self):
        self.assertEqual(parsers.parse_soe(fixture("alarms-none.csv")), [])
        active = parsers.parse_soe(fixture("alarms-active.csv"))
        self.assertEqual(active[0]["tag"], "LAB_INV_3.COMM_FAIL")
        self.assertEqual(active[0]["priority"], "High")

    def test_connected_ieds(self):
        ieds = parsers.parse_ied_table(fixture("ethernet_ieds.html"))
        self.assertEqual(len(ieds), 3)
        self.assertEqual(ieds[0], {"protocol": "Modbus Client", "remote_device": "LAB_INV_1", "interface": "Eth_01",
                                   "type": "Unknown", "local_ip": "192.0.2.10", "remote_ip": "192.0.2.20",
                                   "port": "", "capture": ""})
        self.assertEqual(ieds[2]["port"], "20000")
        self.assertEqual(parsers.parse_ied_table(fixture("serial_ieds.html")), [])


if __name__ == "__main__":
    unittest.main()
