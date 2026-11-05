from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.settings.diff import diff_runs, resolve_diff_inputs


READS = Path(__file__).parent / "fixtures" / "sel" / "reads"
ALPHA = READS / "Alpha Solar" / "192.0.2.11_2381"


def _run(device_id, settings, fid="SEL-751-R400-V4-Z100100-D20241031", run="r1"):
    return {"run": run, "captured_at": "2026-05-19T16:00:00Z", "status": "ok",
            "identity": {"fid": fid, "model": fid.split("-R")[0], "device_id": device_id},
            "settings": settings, "banner": {}}


class TestDiffRuns(unittest.TestCase):
    def test_drift_between_captures_of_one_device(self):
        older, newer, same = resolve_diff_inputs(ALPHA / "20260519T165050Z", ALPHA / "20260601T120000Z")
        self.assertTrue(same)
        result = diff_runs(older, newer, same_device=same)
        self.assertEqual(result["changes"], [{"class": "1", "key": "CTR", "a": "100", "b": "500"}])
        self.assertEqual(result["summary"]["changed"], 1)

    def test_single_device_path_diffs_last_two_captures(self):
        older, newer, same = resolve_diff_inputs(ALPHA, None)
        self.assertTrue(same)
        self.assertEqual(older["run"], "20260519T165050Z")
        self.assertEqual(newer["run"], "20260601T120000Z")

    def test_single_capture_device_cannot_diff_alone(self):
        with self.assertRaises(ValueError):
            resolve_diff_inputs(READS / "Delta Solar" / "192.0.2.41_2381", None)

    def test_peers_ignore_identity_and_address_keys(self):
        a = _run("RELAY A", {"1": {"RID": "RELAY A", "CTR": "200", "PHROT": "ABC"},
                             "P1": {"IPADDR": "192.0.2.5", "ESNTP": "OFF"}})
        b = _run("RELAY B", {"1": {"RID": "RELAY B", "CTR": "400", "PHROT": "ABC"},
                             "P1": {"IPADDR": "192.0.2.6", "ESNTP": "OFF"}, "L1": {"TR": "0"}})
        result = diff_runs(a, b, same_device=False)
        self.assertEqual(result["changes"], [{"class": "1", "key": "CTR", "a": "200", "b": "400"}])
        self.assertEqual(result["classes_only_in_b"], ["L1"])
        self.assertEqual(result["ignored"]["identity"], 2)
        everything = diff_runs(a, b, same_device=False, include_identity=True)
        self.assertEqual(len(everything["changes"]), 3)

    def test_volatile_energy_registers_ignored(self):
        a = _run("M", {"1": {"CTR": "40"}, "E": {"KWHA_REC": "100"}, "TOU": {"TOU": "x1"}})
        b = _run("M", {"1": {"CTR": "40"}, "E": {"KWHA_REC": "250"}, "TOU": {"TOU": "x2"}})
        result = diff_runs(a, b, same_device=True)
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["ignored"]["volatile"], 2)

    def test_render_truncates_long_values(self):
        from sel_triage.integrations.devices.sel.settings.report import render_diff

        a = _run("M", {"L": {"SV01": "A" * 500}})
        b = _run("M", {"L": {"SV01": "B" * 500}})
        text = "\n".join(render_diff(diff_runs(a, b, same_device=True)))
        self.assertIn("(500 chars)", text)
        self.assertNotIn("A" * 100, text)

    def test_added_and_removed_keys_and_identity_changes(self):
        a = _run("R", {"1": {"CTR": "200", "OLD": "1"}})
        b = _run("R", {"1": {"CTR": "200", "NEW": "2"}}, fid="SEL-751-R401-V0-Z100100-D20250101")
        result = diff_runs(a, b, same_device=True)
        self.assertEqual(result["changes"], [
            {"class": "1", "key": "NEW", "a": None, "b": "2"},
            {"class": "1", "key": "OLD", "a": "1", "b": None},
        ])
        self.assertEqual(result["identity_changes"]["fid"],
                         ["SEL-751-R400-V4-Z100100-D20241031", "SEL-751-R401-V0-Z100100-D20250101"])

    def test_model_mismatch_noted(self):
        a = _run("A", {"1": {"CTR": "1"}})
        b = _run("B", {"1": {"CTR": "1"}}, fid="SEL-735-R208-V1-Z103100-D20240429")
        self.assertIn("models differ", " ".join(diff_runs(a, b, same_device=False)["notes"]))

    def test_extra_ignore_patterns(self):
        a = _run("R", {"1": {"CTR": "200", "PTR": "4"}})
        b = _run("R", {"1": {"CTR": "300", "PTR": "5"}})
        result = diff_runs(a, b, same_device=True, ignore=["CT.*"])
        self.assertEqual([c["key"] for c in result["changes"]], ["PTR"])
        with self.assertRaises(ValueError):
            diff_runs(a, b, same_device=True, ignore=["("])


if __name__ == "__main__":
    unittest.main()
