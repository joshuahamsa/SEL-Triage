from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.eventreport.cev_parser import CevParseError, parse_cev, parse_cev_text

FIXTURES = Path(__file__).parent / "fixtures" / "sel" / "events"


class CevParserTests(unittest.TestCase):
    def test_parses_metadata_and_analog_samples(self):
        event = parse_cev(FIXTURES / "minimal.cev")
        self.assertEqual(event.metadata.station, "TEST-DEVICE")
        self.assertEqual(event.metadata.device, "TEST-STATION")
        self.assertEqual(event.metadata.event_number, 42)
        self.assertEqual(event.metadata.timestamp, "07/15/2026 09:33:57.200")
        self.assertEqual(event.metadata.time_source, "CEV event record")
        self.assertEqual(event.samples_per_cycle, 4)
        self.assertEqual(len(event.samples), 4)
        self.assertEqual(
            [channel.name for channel in event.analog_channels],
            ["IA", "IB", "IC", "IN", "IG", "VAY", "VBY", "VCY", "VAZ", "VBZ", "VCZ", "Freq"],
        )
        self.assertEqual(event.samples[1].analog["IA"], 1000.0)
        self.assertTrue(event.samples[1].trigger)
        self.assertEqual(event.samples[3].raw_suffix, "*")
        self.assertEqual(
            event.reported_currents,
            {"A": 1000.0, "B": 0.0, "C": 0.0, "G": 1000.0, "Q": 1000.0},
        )
        self.assertIn("line checksums were not independently validated", event.warnings)

    def test_rejects_wrong_waveform_count(self):
        text = (FIXTURES / "minimal.cev").read_text().replace(
            '-1000,0,0,0,-1000,0,0.9,-0.9,0,0,0,60.00,"*","0","0000"\n',
            "",
        )
        with self.assertRaisesRegex(CevParseError, "expected 4 waveform rows, found 3"):
            parse_cev_text(text)

    def test_rejects_required_record_invariants(self):
        base = (FIXTURES / "minimal.cev").read_text()
        cases = [
            (base.replace("SEL-651R-2-R411-TEST", "SEL-751-R100"), "unsupported CEV relay family"),
            (base.replace("42,60.00,4,4,1", "42,60.00,4,8,1"), "sample rates differ"),
            (base.replace(',">","A","0000"', ',,"A","0000"'), "expected exactly one trigger"),
            (base.replace("RID     :=TEST-DEVICE", ""), "missing RID"),
        ]
        for text, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(CevParseError, message):
                    parse_cev_text(text)

    def test_decodes_relay_word_high_bit_first_and_omits_placeholders(self):
        event = parse_cev(FIXTURES / "minimal.cev")
        signals = {signal.name: signal.raw_states for signal in event.digital_signals}
        self.assertEqual(
            signals,
            {
                "relay_word.EN": ("1", "1", "1", "."),
                "relay_word.TRIP": (".", "1", "1", "."),
                "relay_word.AUX": (".", ".", "1", "."),
            },
        )

    def test_rejects_relay_word_width_mismatch(self):
        text = (FIXTURES / "minimal.cev").read_text().replace('"A","0000"', '"AA","0000"', 1)
        with self.assertRaisesRegex(CevParseError, "relay-word width"):
            parse_cev_text(text)

    def test_rejects_non_hexadecimal_relay_word(self):
        text = (FIXTURES / "minimal.cev").read_text().replace('"A","0000"', '"Z","0000"', 1)
        with self.assertRaisesRegex(CevParseError, "invalid relay word"):
            parse_cev_text(text)

    def test_disambiguates_duplicate_named_bits(self):
        text = (FIXTURES / "minimal.cev").read_text().replace("EN * TRIP AUX", "EN * EN AUX")
        event = parse_cev_text(text)
        names = [signal.name for signal in event.digital_signals]
        self.assertIn("relay_word.EN__bit_0000", names)
        self.assertIn("relay_word.EN__bit_0002", names)

    def test_parses_sel651r2_raw_event_at_32_samples_per_cycle(self):
        event = parse_cev(FIXTURES / "sel651r2_event_10259_raw.cev")
        self.assertEqual(event.metadata.event_number, 10259)
        self.assertEqual(event.metadata.station, "LAB-FDR-01")
        self.assertEqual(event.metadata.device, "LABRLY1")
        self.assertEqual(event.nominal_frequency_hz, 60.0)
        self.assertEqual(event.samples_per_cycle, 32)
        self.assertEqual(len(event.samples), 512)
        triggers = [sample for sample in event.samples if sample.trigger]
        self.assertEqual(len(triggers), 1)
        self.assertEqual(triggers[0].index, 159)
        self.assertEqual(triggers[0].analog["IA"], 2421.0)
        self.assertEqual(triggers[0].analog["IG"], 2511.0)
        self.assertEqual(len(event.digital_signals), len({signal.name for signal in event.digital_signals}))
        signals = {signal.name: signal.raw_states for signal in event.digital_signals}
        self.assertEqual(signals["relay_word.EN"][159], "1")
        self.assertEqual(signals["relay_word.TRIPLED"][159], ".")
        self.assertEqual(signals["relay_word.TRIPLED"][175], "1")


class TestSel651raCev(unittest.TestCase):
    def test_parses_a_live_651ra_cev(self):
        event = parse_cev(FIXTURES / "sel651ra_event_13470.cev")
        self.assertTrue(event.metadata.firmware_id.startswith("SEL-651RA-"))
        self.assertEqual((event.metadata.event_number, event.metadata.event_type), (13470, "TRIP"))
        self.assertEqual(event.metadata.station, "LAB01")
