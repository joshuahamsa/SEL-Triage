"""Pack a FILE READ capture into a .rdb, read it back, and write it out as a capture again."""

from pathlib import Path
import tempfile
import unittest

from sel_triage.integrations.devices.sel.rdb.pack import pack_rdb, read_ole_streams
from sel_triage.integrations.devices.sel.rdb.read import extract_streams, read_rdb, write_capture
from sel_triage.integrations.devices.sel.settings.capture import load_capture_run

ALPHA = Path(__file__).parent / "fixtures" / "sel" / "reads" / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z"


class TestRdbRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rdb = Path(self.tmp.name) / "alpha.rdb"
        pack_rdb(ALPHA, str(self.rdb), "Alpha Relay")

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_matches_the_capture(self):
        (relay,) = read_rdb(self.rdb)["relays"]
        capture = load_capture_run(ALPHA)
        self.assertEqual(relay["device"], "Alpha Relay")
        self.assertEqual(relay["relay_type"], "SEL-751")
        self.assertEqual(relay["settings"], capture["settings"])
        self.assertEqual(relay["unparsed_line_count"], 0)
        self.assertIn("Misc/Cfg.txt", relay["streams"])

    def test_write_capture_restores_the_relay_files(self):
        out = write_capture(self.rdb, "Alpha Relay", Path(self.tmp.name) / "capture")
        for original in ALPHA.glob("set_*.txt"):
            self.assertEqual((out / original.name).read_bytes(), original.read_bytes(), original.name)
        self.assertEqual((out / "CFG.TXT").read_bytes(), (ALPHA / "CFG.TXT").read_bytes())
        self.assertEqual(load_capture_run(out)["settings"], load_capture_run(ALPHA)["settings"])
        with self.assertRaises(ValueError):
            write_capture(self.rdb, "Nope", Path(self.tmp.name) / "x")

    def test_extract_streams_mirrors_the_tree(self):
        names = extract_streams(self.rdb, Path(self.tmp.name) / "tree")
        self.assertEqual(names, sorted(read_ole_streams(str(self.rdb))))
        self.assertTrue((Path(self.tmp.name) / "tree" / "Relays" / "Alpha Relay" / "set_1.txt").is_file())

    def test_not_an_rdb(self):
        bogus = Path(self.tmp.name) / "bogus.rdb"
        bogus.write_text("not ole")
        with self.assertRaises(ValueError):
            read_rdb(bogus)


if __name__ == "__main__":
    unittest.main()


class TestSelRdbTool(unittest.TestCase):
    def test_pack_all_and_read(self):
        import shutil
        from sel_triage.render import render
        from sel_triage.tools import sel_rdb

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "captures"
            shutil.copytree(ALPHA.parent.parent.parent, root)  # the synthetic Reads fixture tree
            result = sel_rdb.run_pack_all(root, Path(tmp) / "rdb",
                                          endpoints={"192.0.2.11_2381": ("Alpha Solar Farm/Main Relay", "Alpha Solar Farm")})
            alpha = next(p for p in result["packed"] if p["device"] == "Alpha Solar/192.0.2.11_2381")
            self.assertTrue(alpha["rdb"].endswith("Alpha Solar Farm/Main Relay.rdb"))
            self.assertEqual(alpha["mode"], "subset")
            read = sel_rdb.run_read(Path(alpha["rdb"]), as_capture=Path(tmp) / "back")
            self.assertEqual(read["relays"][0]["device"], "Main Relay")
            self.assertNotIn("settings", read["relays"][0])
            self.assertTrue((Path(tmp) / "back" / "set_1.txt").is_file())
            self.assertIn("packed", render(result))
            self.assertIn("Main Relay", render(read))

    def test_pack_needs_a_capture_folder(self):
        from sel_triage.tools import sel_rdb

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                sel_rdb.run_pack(Path(tmp))
