from pathlib import Path
import tempfile
import unittest

from sel_triage.integrations.devices.sel.eventreport.eve_parser import EveParseError, parse_eve

FIXTURES = Path(__file__).parent / "fixtures" / "sel" / "events"


class EveParserTests(unittest.TestCase):
    def test_parses_metadata_channels_samples_and_trigger(self):
        event = parse_eve(FIXTURES / "minimal.eve")
        self.assertEqual(event.metadata.event_number, 42)
        self.assertEqual(event.metadata.station, "TEST-STATION")
        self.assertEqual(
            [c.name for c in event.analog_channels],
            ["IA", "IB", "IC", "IG", "VAY", "VBY", "VCY", "Freq"],
        )
        self.assertEqual(len(event.samples), 8)
        self.assertEqual(event.samples[4].analog["IA"], 0.0)
        self.assertEqual([s.index for s in event.samples if s.trigger], [4])
        self.assertEqual(event.samples_per_cycle, 4)

    def test_parses_sel651r2_fault_summary(self):
        event = parse_eve(FIXTURES / "sel651r2_event_10259.eve")
        self.assertEqual(event.metadata.event_number, 10259)
        self.assertEqual(len(event.samples), 60)
        self.assertEqual(event.reported_currents["A"], 2697.0)
        self.assertEqual(event.reported_currents["G"], 1338.0)

    def test_rejects_missing_trigger(self):
        text = (FIXTURES / "minimal.eve").read_text().replace(">", "")
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / "missing-trigger.eve"
            bad.write_text(text)
            with self.assertRaisesRegex(EveParseError, "exactly one trigger"):
                parse_eve(bad)


class TestDigitalOnlyTrigger(unittest.TestCase):
    def test_er_report_takes_the_trigger_from_the_digital_table(self):
        from sel_triage.integrations.devices.sel.eventreport.eve_parser import parse_eve_bytes

        source = (FIXTURES / "sel651r2_event_10259.eve").read_bytes()
        original = parse_eve_bytes(source)
        trigger = next(sample.index for sample in original.samples if sample.trigger)
        # drop the analog trigger marker; the digital tables still carry theirs
        lines = source.decode("latin-1").split("\n")
        header = next(i for i, line in enumerate(lines) if line.lstrip().startswith("IA "))
        end = next(i for i, line in enumerate(lines) if line.startswith("Protection and Control Elements"))
        for i in range(header + 1, end):
            lines[i] = lines[i].replace(">", " ")
        event = parse_eve_bytes("\n".join(lines).encode("latin-1"))
        self.assertEqual(next(sample.index for sample in event.samples if sample.trigger), trigger)
        self.assertIn("trigger taken from the digital table (no analog trigger marker)", event.warnings)


if __name__ == "__main__":
    unittest.main()
