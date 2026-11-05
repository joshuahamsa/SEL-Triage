import math
from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.eventreport.analysis import digital_transitions, phasor_at, sample_times_ms
from sel_triage.integrations.devices.sel.eventreport.eve_parser import parse_eve

FIXTURES = Path(__file__).parent / "fixtures" / "sel" / "events"


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.event = parse_eve(FIXTURES / "minimal.eve")

    def test_trigger_is_zero_ms(self):
        times = sample_times_ms(self.event)
        self.assertAlmostEqual(times[4], 0.0)
        self.assertAlmostEqual(times[0], -1000 / 60, places=6)

    def test_four_sample_sine_has_expected_rms(self):
        result = phasor_at(self.event, "IA", 4)
        self.assertIsNotNone(result)
        self.assertTrue(math.isclose(result.rms, 1000 / math.sqrt(2), rel_tol=1e-6))

    def test_returns_none_without_complete_cycle(self):
        self.assertIsNone(phasor_at(self.event, "IA", 2))

    def test_lists_assert_and_deassert_transitions(self):
        transitions = digital_transitions(self.event)
        simplified = [(t.signal, round(t.time_ms, 6), t.asserted) for t in transitions]
        self.assertIn(("protection_and_control_elements.TRIP", 0.0, True), simplified)
        self.assertIn(("protection_and_control_elements.TRIP", round(2 * 1000 / 240, 6), False), simplified)
