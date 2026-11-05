from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.settings.capture import discover_devices
from sel_triage.integrations.devices.sel.settings.checks import (
    DEFAULT_THRESHOLDS,
    check_devices,
    check_run,
    rule_catalog,
)


READS = Path(__file__).parent / "fixtures" / "sel" / "reads"


def _run(model, settings, banner=None, captured_at="2026-05-19T16:00:00Z"):
    return {
        "run": "r",
        "captured_at": captured_at,
        "status": "ok",
        "identity": {"model": model, "fid": model + "-R100-V0-Z000000-D20200101"},
        "settings": settings,
        "banner": banner or {},
    }


def _codes(findings):
    return sorted({finding["code"] for finding in findings})


class TestDeviceRules(unittest.TestCase):
    def test_default_wear_curve_reuses_live_rule(self):
        settings = {"G": {"EBMON": "Y", "COSP1": "10000", "COSP2": "150", "COSP3": "12",
                          "KASP1": "1.20", "KASP2": "8.00", "KASP3": "20.00"}}
        findings = check_run(_run("SEL-751", settings))
        finding = [f for f in findings if f["code"] == "breaker_monitor_default_curve"][0]
        self.assertEqual(finding["evidence"]["sides"], [""])
        self.assertEqual(finding["evidence"]["curve"], "sel_factory")

    def test_651r_observed_default_curve_and_configurable_curves(self):
        settings = {"G": {"EBMON": "Y", "COSP1": "10000", "COSP2": "20", "COSP3": "20",
                          "KASP1": "0.10", "KASP2": "6.00", "KASP3": "6.00"}}
        self.assertIn("breaker_monitor_default_curve", _codes(check_run(_run("SEL-651R-2", settings))))
        config = {"selSettingsChecks": {"factoryWearCurves": {}}}
        self.assertNotIn(
            "breaker_monitor_default_curve", _codes(check_run(_run("SEL-651R-2", settings), config=config))
        )

    def test_monitor_disabled_on_protective_relay_only(self):
        settings = {"G": {"EBMONX": "N", "EBMONY": "N"}, "1": {"PHROT": "ABC", "CTRX": "800"}}
        self.assertIn("breaker_monitor_disabled", _codes(check_run(_run("SEL-700G", settings))))

    def test_ratios(self):
        findings = check_run(_run("SEL-351A", {"1": {"CTR": "1", "PTR": "120.00"}, "2": {"CTR": "1", "PTR": "60.00"}}))
        codes = _codes(findings)
        self.assertIn("ratio_unity", codes)
        self.assertIn("ratio_differs_between_groups", codes)
        differs = [f for f in findings if f["code"] == "ratio_differs_between_groups"][0]
        self.assertEqual(differs["evidence"]["ratios"], {"PTR": {"1": "120.00", "2": "60.00"}})
        missing = check_run(_run("SEL-751", {"1": {"PHROT": "ABC"}}))
        self.assertIn("ratio_missing", _codes(missing))

    def test_phase_rotation(self):
        self.assertIn("phase_rotation_missing", _codes(check_run(_run("SEL-751", {"1": {"CTR": "100"}}))))
        acb = [f for f in check_run(_run("SEL-751", {"G": {"PHROT": "ACB"}, "1": {"CTR": "100"}}))
               if f["code"] == "phase_rotation_acb"][0]
        self.assertEqual(acb["evidence"]["configured_rotation"], "ACB")
        self.assertIn("phase_sequence_reversed", acb["description"])

    def test_trip_equations(self):
        empty = {"1": {"TR": "0", "TRX": "NA", "CTR": "100", "PHROT": "ABC"}}
        finding = [f for f in check_run(_run("SEL-751", empty)) if f["code"] == "trip_equations_empty"][0]
        self.assertEqual(finding["evidence"]["trip_equations"], {"TR": "0", "TRX": "NA"})
        live = {"1": {"TR": "51PT", "TREA1": "0", "CTR": "100", "PHROT": "ABC"}}
        self.assertNotIn("trip_equations_empty", _codes(check_run(_run("SEL-751", live))))
        sel851 = {"1": {"Trip_01.Init": "0", "Trip_01.InitX": "0", "CTP.Rat": "320", "Sys.PhRot": "ABC"}}
        self.assertIn("trip_equations_empty", _codes(check_run(_run("SEL-851", sel851))))
        meter = {"1": {"TREA1": "0", "CTR": "40", "PHROT": "ABC"}}
        self.assertNotIn("trip_equations_empty", _codes(check_run(_run("SEL-735", meter))))

    def test_protection_elements(self):
        off = {"1": {"TR": "IN101", "CTR": "100", "PHROT": "ABC", "50P1P": "OFF", "51P1P": "OFF",
                     "27P1P": "OFF", "59P1P": "OFF", "81D1P": "OFF", "50P32P": "3.00"}}
        self.assertIn("protection_elements_off", _codes(check_run(_run("SEL-751", off))))
        oc_off = dict(off["1"], **{"27P1P": "50.00"})
        codes = _codes(check_run(_run("SEL-751", {"1": oc_off})))
        self.assertIn("overcurrent_elements_off", codes)
        self.assertNotIn("protection_elements_off", codes)
        sel851 = {"1": {"CTP.Rat": "320", "Sys.PhRot": "ABC", "Trip_01.Init": "IN_01.Sta",
                        "50P.Ena": "OFF", "51P.Ena": "OFF", "27PP.Ena": "OFF", "81.Ena": "OFF"}}
        self.assertIn("protection_elements_off", _codes(check_run(_run("SEL-851", sel851))))

    def test_time_source(self):
        settings = {"1": {"CTR": "100", "PHROT": "ABC"}, "P1": {"ESNTP": "OFF"}}
        free = check_run(_run("SEL-751", settings, banner={"time_source": "int"}))
        self.assertIn("clock_free_running", _codes(free))
        no_banner = check_run(_run("SEL-751", settings))
        self.assertIn("sntp_disabled", _codes(no_banner))
        self.assertNotIn("clock_free_running", _codes(no_banner))
        sntp = {"1": {"CTR": "100", "PHROT": "ABC"}, "P1": {"ESNTP": "UNICAST"}}
        self.assertNotIn("sntp_disabled", _codes(check_run(_run("SEL-751", sntp))))

    def test_clock_drift_from_banner(self):
        settings = {"1": {"CTR": "100", "PHROT": "ABC"}}
        aligned = _run("SEL-751", settings, banner={"relay_time": "2026-05-19T12:00:40"})
        self.assertNotIn("clock_drift", _codes(check_run(aligned)))
        drifted = _run("SEL-751", settings, banner={"relay_time": "2026-05-19T12:09:00"})
        finding = [f for f in check_run(drifted) if f["code"] == "clock_drift"][0]
        self.assertEqual(finding["evidence"]["offset_seconds"], -13860)
        self.assertEqual(finding["evidence"]["drift_seconds"], 540)
        loose = check_run(drifted, thresholds={"clock_drift_seconds": 600})
        self.assertNotIn("clock_drift", _codes(loose))

    def test_clock_far_outside_any_time_zone(self):
        settings = {"1": {"CTR": "100", "PHROT": "ABC"}}
        wrong = _run("SEL-751", settings, banner={"relay_time": "2000-01-01T16:00:00"})
        finding = [f for f in check_run(wrong) if f["code"] == "clock_drift"][0]
        self.assertTrue(finding["evidence"]["outside_time_zone_range"])
        self.assertEqual(finding["evidence"]["drift_seconds"], abs(finding["evidence"]["offset_seconds"]))

    def test_nominal_frequency_and_default_ids(self):
        settings = {"G": {"FNOM": "50"}, "1": {"CTR": "100", "PHROT": "ABC", "RID": "SEL-751", "TID": "STATION A"}}
        codes = _codes(check_run(_run("SEL-751", settings)))
        self.assertIn("nominal_frequency_unexpected", codes)
        self.assertIn("default_device_id", codes)

    def test_disabled_rules(self):
        settings = {"1": {"CTR": "1", "PHROT": "ABC"}}
        config = {"selSettingsChecks": {"disabledRules": ["ratio_unity"]}}
        self.assertNotIn("ratio_unity", _codes(check_run(_run("SEL-751", settings), config=config)))

    def test_unknown_config_rule_rejected(self):
        with self.assertRaises(ValueError):
            check_run(_run("SEL-751", {}), config={"selSettingsChecks": {"disabledRules": ["nope"]}})

    def test_catalog_lists_every_rule(self):
        codes = [rule["code"] for rule in rule_catalog()]
        self.assertIn("trip_equations_empty", codes)
        self.assertIn("phase_rotation_differs_site_peers", codes)
        self.assertEqual(len(codes), len(set(codes)))

    def test_thresholds_defaults(self):
        self.assertEqual(DEFAULT_THRESHOLDS["clock_drift_seconds"], 300.0)


class TestCheckDevicesOnFixtures(unittest.TestCase):
    def setUp(self):
        self.result = check_devices(discover_devices(READS))
        self.devices = {device["device"]: device for device in self.result["devices"]}

    def device_codes(self, key):
        return _codes(self.devices[key]["findings"])

    def test_alpha_751(self):
        codes = self.device_codes("Alpha Solar/192.0.2.11_2381")
        for code in ("phase_rotation_acb", "breaker_monitor_disabled", "ratio_differs_between_groups",
                     "clock_free_running", "clock_drift"):
            self.assertIn(code, codes)
        self.assertEqual(self.devices["Alpha Solar/192.0.2.11_2381"]["captured_at"], "2026-06-01T12:00:00Z")

    def test_charlie_351_unity_ct_and_no_drift(self):
        codes = self.device_codes("Charlie Solar/192.0.2.32_2381")
        self.assertIn("ratio_unity", codes)
        self.assertNotIn("clock_drift", codes)

    def test_delta_851_protection_off(self):
        self.assertIn("protection_elements_off", self.device_codes("Delta Solar/192.0.2.41_2381"))

    def test_site_peer_rules(self):
        site = [(f["code"], f["evidence"]["site"]) for f in self.result["site_findings"]]
        self.assertIn(("phase_rotation_differs_site_peers", "Bravo Solar"), site)
        self.assertIn(("ratio_differs_site_peers", "Bravo Solar"), site)
        self.assertIn(("utc_offset_differs_site_peers", "Alpha Solar"), site)

    def test_device_without_settings(self):
        self.assertEqual(self.devices["Delta Solar/192.0.2.42_2381"]["status"], "no_settings")
        self.assertEqual(self.result["summary"]["devices_without_settings"], 1)

    def test_summary_counts(self):
        summary = self.result["summary"]
        self.assertEqual(summary["devices_checked"], 7)
        self.assertGreaterEqual(summary["findings_by_code"]["phase_rotation_acb"], 2)

    def test_group_option(self):
        result = check_devices(discover_devices(READS / "Alpha Solar" / "192.0.2.11_2381"), group="2")
        self.assertEqual(result["group"], "2")
        device = result["devices"][0]
        self.assertEqual(device["group"], "2")


if __name__ == "__main__":
    unittest.main()
