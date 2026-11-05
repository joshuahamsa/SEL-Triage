import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sel_triage.integrations.devices.sel.eventreport.eve_parser import parse_eve
from sel_triage.integrations.devices.sel.eventreport.cev_parser import parse_cev
from sel_triage.integrations.devices.sel.eventreport.exporters import export_data

FIXTURES = Path(__file__).parent / "fixtures" / "sel" / "events"


class ExporterTests(unittest.TestCase):
    def test_exports_deterministic_data_artifacts(self):
        event = parse_eve(FIXTURES / "minimal.eve")
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            export_data(event, output)
            with (output / "analog.csv").open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            metadata = json.loads((output / "metadata.json").read_text())
            self.assertEqual(len(rows), 8)
            self.assertEqual(float(rows[4]["time_ms"]), 0.0)
            self.assertEqual((output / "source.eve").read_bytes(), event.source_bytes)
            self.assertEqual(metadata["source_sha256"], hashlib.sha256(event.source_bytes).hexdigest())
            self.assertEqual(metadata["event_number"], 42)

    def test_preserves_cev_source_extension_and_bytes(self):
        event = parse_cev(FIXTURES / "minimal.cev")
        with tempfile.TemporaryDirectory() as temp:
            manifest = export_data(event, Path(temp))
            self.assertEqual(manifest.source_event.name, "source.cev")
            self.assertEqual(manifest.source_event.read_bytes(), event.source_bytes)
