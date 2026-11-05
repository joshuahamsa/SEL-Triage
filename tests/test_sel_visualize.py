"""sel-visualize in-process (ported from sel-visualizer's CLI tests)."""

from pathlib import Path
import shutil
import tempfile
import unittest

from sel_triage.render import render
from sel_triage.tools import sel_visualize

FIXTURES = Path(__file__).parent / "fixtures" / "sel" / "events"
EVE_ARTIFACTS = {"report.html", "analog.csv", "digital.csv", "metadata.json", "source.eve"}


def target(result):
    return result["targets"][0]


class TestSelVisualize(unittest.TestCase):
    def test_single_file_generates_all_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            result = sel_visualize.run([str(FIXTURES / "minimal.eve")], str(output))
            self.assertTrue(result["ok"])
            self.assertEqual({p.name for p in output.iterdir()}, EVE_ARTIFACTS)
            self.assertEqual(target(result)["reports"], [str(output / "report.html")])
            event = target(result)["events"][0]
            self.assertEqual((event["station"], event["event_number"]), ("TEST-STATION", 42))
            self.assertFalse(result["provenance"]["external_process"])

    def test_single_cev_keeps_source_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            result = sel_visualize.run([str(FIXTURES / "minimal.cev")], str(output))
            self.assertTrue(result["ok"])
            self.assertEqual((output / "source.cev").read_bytes(), (FIXTURES / "minimal.cev").read_bytes())

    def test_651r2_raw_cev_at_32_samples_per_cycle(self):
        with tempfile.TemporaryDirectory() as temp:
            result = sel_visualize.run([str(FIXTURES / "sel651r2_event_10259_raw.cev")], str(Path(temp) / "r"))
        event = target(result)["events"][0]
        self.assertEqual((event["samples_per_cycle"], event["samples"]), (32, 512))

    def test_existing_output_needs_overwrite_and_only_holds_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            sel_visualize.run([str(FIXTURES / "minimal.eve")], str(output))
            again = sel_visualize.run([str(FIXTURES / "minimal.eve")], str(output))
            self.assertFalse(again["ok"])
            self.assertEqual(target(again)["errors"][0]["category"], "output_exists")
            self.assertTrue(sel_visualize.run([str(FIXTURES / "minimal.eve")], str(output), overwrite=True)["ok"])
            (output / "notes.txt").write_text("mine")
            refused = sel_visualize.run([str(FIXTURES / "minimal.eve")], str(output), overwrite=True)
            self.assertFalse(refused["ok"])
            self.assertTrue((output / "notes.txt").exists())

    def test_batch_continues_after_a_bad_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "good.eve").write_bytes((FIXTURES / "minimal.eve").read_bytes())
            (root / "bad.eve").write_text("not an event")
            result = sel_visualize.run([str(root)], str(root / "out"))
            self.assertFalse(result["ok"])
            self.assertTrue(result["partial"])
            self.assertTrue((root / "out" / "good" / "report.html").exists())
            self.assertEqual(target(result)["errors"][0]["category"], "event_parse_failed")

    def test_directory_discovers_eve_and_cev(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copy(FIXTURES / "minimal.eve", root / "one.eve")
            shutil.copy(FIXTURES / "minimal.cev", root / "two.cev")
            result = sel_visualize.run([str(root)], str(root / "out"))
            self.assertTrue(result["ok"])
            self.assertTrue((root / "out" / "one" / "source.eve").exists())
            self.assertTrue((root / "out" / "two" / "source.cev").exists())

    def test_input_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            text = Path(temp) / "notes.txt"
            text.write_text("x")
            for inputs in ([], [str(text)], [str(Path(temp) / "missing.eve")], [temp]):
                with self.subTest(inputs=inputs):
                    with self.assertRaises(ValueError):
                        sel_visualize.run(inputs, str(Path(temp) / "out"))
            with self.assertRaises(ValueError):
                sel_visualize.run([str(FIXTURES / "minimal.eve")], "")

    def test_same_stem_inputs_collide(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            shutil.copy(FIXTURES / "minimal.eve", root / "a" / "x.eve")
            shutil.copy(FIXTURES / "minimal.eve", root / "b" / "x.eve")
            with self.assertRaises(sel_visualize.OutputCollision):
                sel_visualize.run([str(root / "a" / "x.eve"), str(root / "b" / "x.eve")], str(root / "out"))

    def test_render_lists_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            result = sel_visualize.run([str(FIXTURES / "minimal.eve")], str(Path(temp) / "r"))
            self.assertIn("report: ", render(result))


if __name__ == "__main__":
    unittest.main()
