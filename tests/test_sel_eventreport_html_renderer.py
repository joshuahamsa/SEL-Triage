from pathlib import Path
import tempfile
import unittest

from sel_triage.integrations.devices.sel.eventreport.eve_parser import parse_eve
from sel_triage.integrations.devices.sel.eventreport.cev_parser import parse_cev
from sel_triage.integrations.devices.sel.eventreport.html_renderer import render_html

FIXTURES = Path(__file__).parent / "fixtures" / "sel" / "events"


class HtmlRendererTests(unittest.TestCase):
    def test_renders_offline_analysis_controls_and_event_data(self):
        event = parse_eve(FIXTURES / "minimal.eve")
        with tempfile.TemporaryDirectory() as temp:
            path = render_html(event, Path(temp) / "report.html")
            html = path.read_text()
            for identifier in ["analog-current", "analog-voltage", "digital-timeline", "phasor-current", "cursor-readout"]:
                self.assertIn(f'id="{identifier}"', html)
            self.assertIn('"event_number":42', html)
            self.assertNotIn("<script src=", html)
            self.assertNotIn("<link rel=", html)
            self.assertNotIn("fetch(", html)

    def test_enables_display_only_smoothing_by_default(self):
        event = parse_eve(FIXTURES / "minimal.eve")
        with tempfile.TemporaryDirectory() as temp:
            path = render_html(event, Path(temp) / "report.html")
            html = path.read_text()
            self.assertIn('id="smooth-waveforms"', html)
            self.assertIn('id="smooth-waveforms" type="checkbox" checked', html)
            self.assertIn('id="sample-markers" type="checkbox"', html)
            self.assertNotIn('id="sample-markers" type="checkbox" checked', html)
            self.assertIn("function smoothPath(points)", html)
            self.assertIn("display-only", html)
            self.assertIn("cursor values are measured samples", html)
            self.assertIn("samples/cycle", html)

    def test_renders_sel651r2_cev_at_32_samples_per_cycle(self):
        event = parse_cev(FIXTURES / "sel651r2_event_10259_raw.cev")
        with tempfile.TemporaryDirectory() as temp:
            html = render_html(event, Path(temp) / "report.html").read_text()
            self.assertIn('"samples_per_cycle":32', html)
            self.assertIn('"sample_count":512', html)
            self.assertIn("Smooth waveforms", html)
            self.assertNotIn("<script src=", html)
            self.assertNotIn("<link rel=", html)
