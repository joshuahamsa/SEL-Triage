import unittest
from datetime import datetime, timezone


from sel_triage.core.diagnostics import Diagnostic
from sel_triage.integrations.devices.sel.diagnostics import diagnose_snapshot


def fixed_at(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class TestDiagnostic(unittest.TestCase):
    def test_frozen_diagnostic_serializes_to_plain_dict(self):
        diagnostic = Diagnostic(
            code="example",
            severity="warning",
            description="A measured condition was observed.",
            evidence={"field": "value"},
        )

        self.assertEqual(
            diagnostic.as_dict(),
            {
                "code": "example",
                "severity": "warning",
                "description": "A measured condition was observed.",
                "evidence": {"field": "value"},
            },
        )
        with self.assertRaises(AttributeError):
            diagnostic.code = "changed"


class TestDiagnoseSnapshot(unittest.TestCase):
    def setUp(self):
        self.now = fixed_at("2026-07-21T12:00:00Z")
        self.thresholds = {
            "clock_drift_seconds": 300,
            "phase_imbalance_percent": 10,
        }

    def test_clock_drift_flag_cites_measured_drift(self):
        flags = diagnose_snapshot(
            {"clock": "2026-07-21T16:10:00Z", "time_source": "Internal"},
            now=self.now,
            thresholds=self.thresholds,
        )

        self.assertEqual(flags[0]["code"], "relay_clock_unsynchronized")
        self.assertEqual(flags[0]["evidence"]["drift_seconds"], 15000)
        self.assertEqual(flags[0]["evidence"]["clock"], "2026-07-21T16:10:00Z")

    def test_threshold_defaults_are_300_seconds_and_10_percent(self):
        flags = diagnose_snapshot(
            {
                "clock": "2026-07-21T12:05:01Z",
                "phases": [
                    {"phase": "A", "current_a": 100.0},
                    {"phase": "B", "current_a": 100.0},
                    {"phase": "C", "current_a": 120.0},
                ],
            },
            now=self.now,
            thresholds=None,
        )

        self.assertEqual(
            [flag["code"] for flag in flags],
            ["relay_clock_unsynchronized", "phase_imbalance"],
        )

    def _codes(self, fields, thresholds=None):
        return {flag["code"]: flag for flag in diagnose_snapshot(fields, now=self.now, thresholds=thresholds)}

    def test_capture_only_sections_are_reported_as_info_not_missing(self):
        codes = self._codes({"completed_capabilities": ["meter"],
                             "snapshot": {"meter": {"capture_only": True, "unparsed_lines": ["x"]}}})
        self.assertEqual(codes["capture_only_output"]["severity"], "info")
        self.assertEqual(codes["capture_only_output"]["evidence"], {"capabilities": ["meter"]})
        self.assertNotIn("missing_measurement", codes)

    def _meter_section(self, parser_module, fixture_name):
        from pathlib import Path

        text = (Path(__file__).parent / "fixtures" / "sel" / fixture_name).read_text()
        return {"completed_capabilities": ["meter"], "snapshot": {"meter": parser_module.parse_meter(text)}}

    def test_phase_sequence_reversed_on_live_735_and_700gt_captures(self):
        from sel_triage.integrations.devices.sel.parsers import sel700g, sel735

        flag = self._codes(self._meter_section(sel735, "735-meter.txt"))["phase_sequence_reversed"]
        self.assertEqual(flag["severity"], "warning")
        self.assertEqual(flag["evidence"]["positive_sequence_v"], 1.81)
        self.assertEqual(flag["evidence"]["negative_sequence_v"], 287.7)
        self.assertEqual(flag["evidence"]["positive_sequence_a"], 1.75)
        self.assertAlmostEqual(flag["evidence"]["negative_sequence_a"], 321.553, places=3)
        self.assertEqual(flag["evidence"]["threshold_ratio"], 2.0)

        flag = self._codes(self._meter_section(sel700g, "700gt-meter.txt"))["phase_sequence_reversed"]
        self.assertEqual(flag["evidence"]["positive_sequence_v"], 44.7)
        self.assertAlmostEqual(flag["evidence"]["negative_sequence_v"], 7865.967, places=3)

    def test_normal_rotation_or_dead_bus_is_not_flagged(self):
        normal = {"snapshot": {"meter": {"details": {"sequence_magnitudes": {"V1": 288.0, "V2": 1.2, "I1": 320.0, "3I2": 4.0}}}}}
        dead = {"snapshot": {"meter": {"details": {"voltages_v": {"V1X": 0.0, "3V2X": 30.0}}}}}
        self.assertNotIn("phase_sequence_reversed", self._codes(normal))
        self.assertNotIn("phase_sequence_reversed", self._codes(dead))

    def test_self_test_warning_names_warned_items(self):
        from sel_triage.integrations.devices.sel.parsers import sel735
        from pathlib import Path

        text = (Path(__file__).parent / "fixtures" / "sel" / "735-status.txt").read_text()
        flag = self._codes({"snapshot": {"status": sel735.parse_status(text)}})["self_test_warning"]
        self.assertEqual(flag["severity"], "warning")
        self.assertEqual(flag["evidence"], {"self_test": "WARN", "warning_items": ["Batt"]})
        self.assertNotIn("self_test_warning", self._codes({"self_test": "OK"}))

    def _751_sections(self):
        from pathlib import Path
        from sel_triage.integrations.devices.sel.parsers import sel751

        F = Path(__file__).parent / "fixtures" / "sel"
        return {
            "snapshot": {
                "status": sel751.parse_status((F / "751-status.txt").read_text()),
                "history": sel751.parse_history((F / "751-history.txt").read_text()),
            }
        }

    def test_recent_trips_measured_from_relay_clock(self):
        flag = self._codes(self._751_sections())["recent_trip"]
        evidence = flag["evidence"]
        self.assertEqual(flag["severity"], "warning")
        self.assertEqual(evidence["days"], 30)
        self.assertEqual(evidence["reference_time"], "2026-09-25T17:06:37.810")
        self.assertEqual(evidence["trip_count"], 4)
        self.assertEqual(evidence["most_recent"], "2026-09-13T20:48:30.780")
        self.assertEqual(
            evidence["trips"][3],
            {"event_number": 6, "timestamp": "2026-09-13T13:05:25.945", "event_type": "27 Trip", "current_a": 1580.3},
        )

    def test_recent_trip_window_is_configurable_and_er_triggers_do_not_count(self):
        codes = self._codes(self._751_sections(), {"recent_trip_days": 200})
        self.assertEqual(codes["recent_trip"]["evidence"]["trip_count"], 6)
        self.assertNotIn("recent_trip", self._codes(self._751_sections(), {"recent_trip_days": 5}))
        triggers = {"events": [{"event_number": 1, "timestamp": "2026-07-21T11:00:00", "event_type": "ER Trigger"}]}
        self.assertNotIn("recent_trip", self._codes(triggers))

    def test_recent_trip_falls_back_to_now_without_relay_clock(self):
        events = {"events": [{"event_number": 1, "timestamp": "2026-07-20T09:00:00.000", "event_type": "TRIP"}]}
        self.assertEqual(self._codes(events)["recent_trip"]["evidence"]["reference_time"], "2026-07-21T12:00:00")

    def test_new_threshold_defaults(self):
        from sel_triage.integrations.devices.sel.diagnostics import DEFAULT_THRESHOLDS

        self.assertEqual(DEFAULT_THRESHOLDS["breaker_wear_percent"], 80.0)
        self.assertEqual(DEFAULT_THRESHOLDS["breaker_operation_count"], 5000.0)
        self.assertEqual(DEFAULT_THRESHOLDS["event_burst_count"], 5.0)
        self.assertEqual(DEFAULT_THRESHOLDS["event_burst_window_seconds"], 600.0)
        self.assertEqual(DEFAULT_THRESHOLDS["phase_sequence_ratio"], 2.0)
        self.assertEqual(DEFAULT_THRESHOLDS["recent_trip_days"], 30.0)
        self.assertEqual(DEFAULT_THRESHOLDS["event_burst_recent_days"], 30.0)

    def test_breaker_wear_at_or_above_threshold_is_flagged(self):
        flags = self._codes({"breaker_wear_percent": 100.0, "details": {"wear_percent": {"A": 100, "B": 100, "C": 100}}})
        flag = flags["breaker_wear_high"]
        self.assertEqual(flag["severity"], "warning")
        self.assertEqual(flag["evidence"]["breaker_wear_percent"], 100.0)
        self.assertEqual(flag["evidence"]["threshold_percent"], 80.0)
        self.assertNotIn("breaker_wear_high", self._codes({"breaker_wear_percent": 79.0}))
        self.assertIn("breaker_wear_high", self._codes({"breaker_wear_percent": 60.0}, {"breaker_wear_percent": 50}))

    def test_breaker_wear_uses_breaker_section_details(self):
        snapshot = {
            "snapshot": {
                "breaker": {"breaker_wear_percent": 90.0, "operation_count": 10,
                            "details": {"wear_percent": {"A": 90, "B": 40, "C": 40}}},
                "meter": {"details": {"power_kw": {"3PX": 1}}},
            }
        }
        flag = self._codes(snapshot)["breaker_wear_high"]
        self.assertEqual(flag["evidence"]["wear_percent"], {"A": 90, "B": 40, "C": 40})

    def test_breaker_operation_count_is_flagged(self):
        flag = self._codes({"operation_count": 13234})["breaker_operations_high"]
        self.assertEqual(flag["evidence"], {"operation_count": 13234, "threshold_count": 5000})
        self.assertNotIn("breaker_operations_high", self._codes({"operation_count": 4999}))

    def _settings_snapshot(self, **overrides):
        from pathlib import Path
        from sel_triage.integrations.devices.sel.adapters.sel700g import Sel700GAdapter

        fixtures = Path(__file__).parent / "fixtures" / "sel"
        adapter = Sel700GAdapter()
        sections = {
            "breaker": adapter.parse("breaker", (fixtures / "700gt-breaker.txt").read_text()),
            "meter": adapter.parse("meter", (fixtures / "700gt-meter.txt").read_text()),
        }
        for name in ("global", "group", "logic", "report"):
            sections["settings_" + name] = adapter.parse(
                "settings_" + name,
                (fixtures / "700gt-settings-{0}.txt".format(name)).read_text(),
            )
        for key, value in overrides.items():
            sections["settings_global"]["settings"][key] = value
        return {"snapshot": sections}

    def test_breaker_findings_cite_monitor_settings_and_trip_logic(self):
        flags = self._codes(self._settings_snapshot(), {})
        operations = flags["breaker_operations_high"]["evidence"]
        self.assertEqual(operations["monitor_settings"]["EBMONX"], "Y")
        self.assertEqual(operations["monitor_settings"]["BKMONX"], "TRIPX")
        self.assertEqual(operations["trip_equations"], {"TRX": "NOT 3PWRX1T"})
        self.assertEqual(
            flags["breaker_wear_high"]["evidence"]["monitor_settings"]["COSP1X"], "10000"
        )

    def test_factory_wear_curve_is_reported_per_enabled_side(self):
        flags = self._codes(self._settings_snapshot(), {})
        flag = flags["breaker_monitor_default_curve"]
        self.assertEqual(flag["severity"], "info")
        self.assertEqual(flag["evidence"]["sides"], ["X", "Y"])

        flags = self._codes(self._settings_snapshot(EBMONY="N", COSP1X="5000"), {})
        self.assertNotIn("breaker_monitor_default_curve", flags)

        flags = self._codes(self._settings_snapshot(KASP1X="1.2"), {})
        self.assertEqual(flags["breaker_monitor_default_curve"]["evidence"]["sides"], ["X", "Y"])

    def test_phase_sequence_finding_cites_configured_rotation(self):
        flag = self._codes(self._settings_snapshot(), {})["phase_sequence_reversed"]
        self.assertEqual(flag["evidence"]["configured_rotation"], "ABC")

    def test_no_settings_leaves_breaker_evidence_unchanged(self):
        flag = self._codes({"operation_count": 13234})["breaker_operations_high"]
        self.assertNotIn("monitor_settings", flag["evidence"])
        self.assertNotIn("breaker_monitor_default_curve", self._codes({"operation_count": 13234}))

    def _events(self, seconds_apart, count, event_type="ER Trigger", start="2026-09-19T14:25:00.000"):
        base = datetime.fromisoformat(start)
        from datetime import timedelta
        return [
            {"event_number": i + 1, "timestamp": (base + timedelta(seconds=seconds_apart * i)).isoformat(timespec="milliseconds"),
             "event_type": event_type}
            for i in range(count)
        ]

    def test_event_burst_reports_busiest_window(self):
        events = self._events(15, 21) + self._events(3600, 2, "TRIP", "2026-09-10T00:00:00.000")
        flag = self._codes({"events": events, "clock": "2026-09-25T12:00:00"})["event_burst"]
        self.assertEqual(flag["severity"], "warning")
        evidence = flag["evidence"]
        self.assertEqual(evidence["event_count"], 21)
        self.assertEqual(evidence["window_seconds"], 600)
        self.assertEqual(evidence["threshold_count"], 5)
        self.assertEqual(evidence["first_event"], "2026-09-19T14:25:00.000")
        self.assertEqual(evidence["last_event"], "2026-09-19T14:30:00.000")
        self.assertEqual(evidence["event_types"], {"ER Trigger": 21})
        self.assertEqual(evidence["recent_days"], 30)

    def test_event_burst_ignores_bursts_outside_recent_window(self):
        old_burst = self._events(15, 21, start="2026-06-01T10:00:00.000")
        self.assertNotIn("event_burst", self._codes({"events": old_burst, "clock": "2026-09-25T12:00:00"}))
        self.assertIn("event_burst", self._codes({"events": old_burst, "clock": "2026-09-25T12:00:00"},
                                                 {"event_burst_recent_days": 120}))
        # without a relay clock the snapshot time is the reference (setUp: 2026-07-21)
        self.assertIn("event_burst", self._codes({"events": self._events(15, 6, start="2026-07-20T10:00:00.000")}))
        future = self._events(15, 6, start="2026-09-26T10:00:00.000")
        self.assertNotIn("event_burst", self._codes({"events": future, "clock": "2026-09-25T12:00:00"}))

    def test_spread_out_or_few_events_are_not_a_burst(self):
        clock = "2026-09-25T12:00:00"
        self.assertNotIn("event_burst", self._codes({"events": self._events(300, 10), "clock": clock}))  # 3 per 600s
        self.assertNotIn("event_burst", self._codes({"events": self._events(10, 4), "clock": clock}))
        self.assertNotIn("event_burst", self._codes({"events": [{"event_number": 1, "timestamp": "garbage"}] * 9}))

    def test_failed_self_test_cites_normalized_value(self):
        flags = diagnose_snapshot(
            {"self_test": "FAIL"}, self.now, self.thresholds
        )

        self.assertEqual(flags[0]["code"], "self_test_failed")
        self.assertEqual(flags[0]["evidence"], {"self_test": "FAIL"})

    def test_asserted_trip_target_cites_only_asserted_trip_targets(self):
        flags = diagnose_snapshot(
            {
                "targets": [
                    {"name": "TRIP", "asserted": True},
                    {"name": "OVERFREQUENCY", "asserted": True},
                    {"name": "TRIP_COIL", "asserted": False},
                ]
            },
            self.now,
            self.thresholds,
        )

        self.assertEqual(flags[0]["code"], "trip_target_asserted")
        self.assertEqual(
            flags[0]["evidence"],
            {"targets": [{"name": "TRIP", "asserted": True}]},
        )

    def test_phase_imbalance_uses_three_positive_phase_currents(self):
        phases = [
            {"phase": "A", "current_a": 90.0},
            {"phase": "B", "current_a": 100.0},
            {"phase": "C", "current_a": 110.0},
        ]

        flags = diagnose_snapshot(
            {"phases": phases}, self.now, self.thresholds
        )

        self.assertEqual(flags[0]["code"], "phase_imbalance")
        self.assertEqual(flags[0]["evidence"]["measurement"], "current_a")
        self.assertEqual(flags[0]["evidence"]["imbalance_percent"], 20.0)
        self.assertEqual(flags[0]["evidence"]["phases"], phases)

    def test_missing_or_zero_phase_measurements_make_no_imbalance_conclusion(self):
        samples = (
            {},
            {"phases": [{"current_a": 1.0}, {"current_a": 2.0}]},
            {
                "phases": [
                    {"current_a": 0.0},
                    {"current_a": 10.0},
                    {"current_a": 20.0},
                ]
            },
        )

        for sample in samples:
            with self.subTest(sample=sample):
                flags = diagnose_snapshot(sample, self.now, self.thresholds)
                self.assertNotIn("phase_imbalance", [f["code"] for f in flags])

    def test_incomplete_phase_measurements_produce_an_availability_warning(self):
        flags = diagnose_snapshot(
            {
                "phases": [
                    {"phase": "A", "current_a": 0.0},
                    {"phase": "B", "current_a": 10.0},
                    {"phase": "C"},
                ]
            },
            self.now,
            self.thresholds,
        )

        self.assertEqual(
            [flag["code"] for flag in flags],
            ["missing_measurement", "partial_snapshot"],
        )
        self.assertEqual(
            flags[0]["evidence"],
            {
                "capability": "meter",
                "field": "phases",
                "phases": [
                    {"phase": "A", "current_a": 0.0},
                    {"phase": "B", "current_a": 10.0},
                    {"phase": "C"},
                ],
            },
        )

    def test_completed_meter_without_phases_reports_missing_measurement(self):
        flags = diagnose_snapshot(
            {
                "snapshot": {"meter": {"frequency_hz": 60.0}},
                "completed_capabilities": ["meter"],
                "unavailable_capabilities": [],
                "errors": [],
            },
            self.now,
            self.thresholds,
        )

        self.assertEqual(flags[0]["code"], "missing_measurement")
        self.assertEqual(
            flags[0]["evidence"],
            {"capability": "meter", "field": "phases", "available": False},
        )
        self.assertNotIn("phase_imbalance", [flag["code"] for flag in flags])

    def test_model_mismatch_cites_requested_and_observed_models(self):
        flags = diagnose_snapshot(
            {"model_hint": "SEL-751", "observed_model": "SEL-700GT"},
            self.now,
            self.thresholds,
        )

        self.assertEqual(flags[0]["code"], "model_mismatch")
        self.assertEqual(
            flags[0]["evidence"],
            {"model_hint": "SEL-751", "observed_model": "SEL-700GT"},
        )

    def test_same_family_hint_is_not_a_mismatch(self):
        # Live SEL-700GT: firmware ID model SEL-700G, sheet hint SEL-700GT.
        flags = diagnose_snapshot(
            {"model_hint": "SEL-700GT", "observed_model": "SEL-700G"},
            self.now,
            self.thresholds,
        )
        self.assertNotIn("model_mismatch", [flag["code"] for flag in flags])

    def test_hint_matching_device_id_is_not_a_mismatch(self):
        flags = diagnose_snapshot(
            {"model_hint": "SEL-3505", "observed_model": "SEL-3505-3", "device_id": "SEL-3505"},
            self.now,
            self.thresholds,
        )
        self.assertNotIn("model_mismatch", [flag["code"] for flag in flags])

    def test_device_unreachable_and_authentication_failed_are_structured(self):
        flags = diagnose_snapshot(
            {
                "reachable": False,
                "errors": [
                    {
                        "category": "authentication_failed",
                        "reachable": True,
                    }
                ],
            },
            self.now,
            self.thresholds,
        )

        self.assertEqual(
            [flag["code"] for flag in flags[:2]],
            ["device_unreachable", "authentication_failed"],
        )
        self.assertEqual(flags[0]["evidence"], {"reachable": False})
        self.assertEqual(
            flags[1]["evidence"],
            {"category": "authentication_failed", "reachable": True},
        )

    def test_command_unavailable_and_partial_snapshot_cite_capabilities(self):
        flags = diagnose_snapshot(
            {
                "errors": [
                    {
                        "category": "command_unavailable",
                        "capability": "breaker",
                        "reachable": True,
                    }
                ],
                "completed_capabilities": ["status", "meter", "history"],
                "unavailable_capabilities": ["breaker", "target"],
                "phases": [
                    {"phase": "A", "current_a": 10.0},
                    {"phase": "B", "current_a": 10.0},
                    {"phase": "C", "current_a": 10.0},
                ],
            },
            self.now,
            self.thresholds,
        )

        self.assertEqual(
            [flag["code"] for flag in flags],
            ["command_unavailable", "partial_snapshot"],
        )
        self.assertEqual(
            flags[0]["evidence"],
            {"capability": "breaker", "reachable": True},
        )
        self.assertEqual(
            flags[1]["evidence"],
            {
                "unavailable_capabilities": ["breaker", "target"],
                "error_categories": ["command_unavailable"],
            },
        )

    def test_partial_snapshot_omits_empty_context_and_keeps_error_causes(self):
        flags = diagnose_snapshot(
            {
                "errors": [
                    {"category": "evidence_write_failed", "reachable": True},
                    {"category": "evidence_write_failed", "reachable": True},
                    {"category": "logout_failed", "reachable": True},
                ],
                "completed_capabilities": [],
                "unavailable_capabilities": [],
            },
            self.now,
            self.thresholds,
        )

        partial = next(flag for flag in flags if flag["code"] == "partial_snapshot")
        self.assertEqual(
            partial["evidence"],
            {"error_categories": ["evidence_write_failed", "logout_failed"]},
        )
        self.assertEqual(
            partial["description"],
            "Snapshot completed with one or more evidence or session errors.",
        )

    def test_diagnostic_descriptions_do_not_recommend_operations(self):
        flags = diagnose_snapshot(
            {
                "reachable": False,
                "self_test": "FAIL",
                "targets": [{"name": "TRIP", "asserted": True}],
                "model_hint": "SEL-751",
                "observed_model": "SEL-700GT",
            },
            self.now,
            self.thresholds,
        )

        recommendations = ("should", "recommend", "open", "close", "reset", "operate")
        for flag in flags:
            with self.subTest(code=flag["code"]):
                words = flag["description"].lower()
                self.assertFalse(any(word in words for word in recommendations))


if __name__ == "__main__":
    unittest.main()
