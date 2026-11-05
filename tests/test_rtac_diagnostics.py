from datetime import datetime, timezone
from pathlib import Path
import unittest

from sel_triage.integrations.devices.rtac import parsers
from sel_triage.integrations.devices.rtac.diagnostics import DEFAULT_THRESHOLDS, diagnose_rtac


F = Path(__file__).parent / "fixtures" / "rtac"
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


def codes(flags):
    return {flag["code"]: flag for flag in flags}


class RtacDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.events = parsers.parse_soe((F / "soe.csv").read_text())
        self.home = parsers.parse_home((F / "home.html").read_text())

    def run_checks(self, alarms=(), thresholds=None, home=None, events=None):
        return codes(diagnose_rtac(events if events is not None else self.events, list(alarms),
                                   home or self.home, NOW, thresholds))

    def test_default_window(self):
        self.assertEqual(DEFAULT_THRESHOLDS["rtac_recent_days"], 30.0)

    def test_recent_failed_logins(self):
        flag = self.run_checks()["rtac_failed_logins"]
        self.assertEqual(flag["severity"], "warning")
        self.assertEqual(flag["evidence"]["count"], 2)
        self.assertEqual(flag["evidence"]["latest"], "2026-09-20T09:00:30.000")
        self.assertEqual(flag["evidence"]["days"], 30)

    def test_recent_settings_changes_include_project_change(self):
        flag = self.run_checks()["rtac_settings_changed"]
        self.assertEqual(flag["severity"], "info")
        kinds = [c["kind"] for c in flag["evidence"]["changes"]]
        self.assertEqual(kinds, ["settings_changed", "project_or_firmware_changed"])
        self.assertEqual(flag["evidence"]["changes"][1]["project"], "LAB_Curtailment_R2")

    def test_recent_restart(self):
        flag = self.run_checks()["rtac_restarted"]
        self.assertEqual(flag["severity"], "info")
        self.assertEqual(flag["evidence"]["last_power_up"], "2026-09-01T10:10:00.500")

    def test_old_events_are_outside_the_window(self):
        flags = self.run_checks(thresholds={"rtac_recent_days": 3})
        self.assertNotIn("rtac_failed_logins", flags)
        self.assertNotIn("rtac_restarted", flags)
        self.assertNotIn("rtac_settings_changed", flags)

    def test_active_alarms_and_inactive_communication(self):
        alarms = parsers.parse_soe((F / "alarms-active.csv").read_text())
        flags = self.run_checks(alarms=alarms, home={"communication_active": False})
        self.assertEqual(flags["rtac_active_alarms"]["evidence"]["count"], 1)
        self.assertEqual(flags["rtac_active_alarms"]["evidence"]["alarms"][0]["tag"], "LAB_INV_3.COMM_FAIL")
        self.assertEqual(flags["rtac_communication_inactive"]["severity"], "warning")

    def test_quiet_rtac_has_no_findings(self):
        quiet = [e for e in self.events if e["timestamp"] < "2025"]
        self.assertEqual(self.run_checks(events=quiet), {})


if __name__ == "__main__":
    unittest.main()
