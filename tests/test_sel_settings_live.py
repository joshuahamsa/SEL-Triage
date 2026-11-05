"""Live settings capture flow (ported from SEL-Audit cli_read_settings) against a fake client."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sel_triage.core.errors import TriageError
from sel_triage.integrations.devices.sel.client import _normalize_identity
from sel_triage.integrations.devices.sel.settings.capture import discover_devices
from sel_triage.integrations.devices.sel.settings.live import (
    CaptureOptions,
    FileShowError,
    capture_settings,
    cfg_classes,
    extract_show_payload,
)

ALPHA = Path(__file__).parent / "fixtures" / "sel" / "reads" / "Alpha Solar" / "192.0.2.11_2381" / "20260601T120000Z"
NO_PAUSE = CaptureOptions(pause_seconds=0)


class FakeClient:
    """Serves files by name; records what was asked and how."""

    def __init__(self, files, family="sel751", id_name="ID.txt", fail=()):
        self.files = {name.upper(): data for name, data in files.items()}
        self.family = family
        self.identity = _normalize_identity((ALPHA / id_name).read_text())
        self.fail = {name.upper(): error for name, error in dict(fail).items()}
        self.help_error = None
        self.calls = []

    def read_file(self, name, *, start_retries, block_timeout, settle_seconds):
        self.calls.append(("read", name, start_retries))
        return self._serve(name)

    def run_bytes(self, capability, name=None):
        self.calls.append((capability, name))
        if capability == "help":
            if self.help_error is not None:
                raise self.help_error
            return b"HELP\r\nMET      Metering data\r\nSTA      Relay status\r\n=>"
        if name.upper() not in self.files:
            return b"FILE SHOW " + name.encode() + b"\r\n\x02\r\nInvalid File Name\r\n\x03\x02\r\n=>\x03"
        body = self.files[name.upper()].replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        return b"FILE SHOW " + name.encode() + b"\r\n\x02\r\n" + body + b"\x03\x02\r\n=>\x03"

    def _serve(self, name):
        if name.upper() in self.fail:
            raise self.fail[name.upper()]
        if name.upper() not in self.files:
            raise TriageError("FILE READ {0} failed: no frame".format(name), category="file_transfer_failed", reachable=True)
        return self.files[name.upper()]


def alpha_files():
    return {path.name: path.read_bytes() for path in ALPHA.iterdir() if path.name.upper() == "CFG.TXT" or path.name.startswith("set_")}


class TestCaptureSettings(unittest.TestCase):
    def test_file_read_capture_writes_the_sel_audit_layout(self):
        files = alpha_files()
        files["SET_HMI.TXT"] = b"[INFO]\r\nRELAYTYPE=SEL-751\r\n"
        client = FakeClient(files)
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "Alpha Solar" / "192.0.2.11_2381" / "20261012T120000Z"
            manifest = capture_settings(client, run_dir, transcript=lambda: b"=ACC\r\nPassword: \r\n=>", options=NO_PAUSE)

            names = sorted(p.name for p in run_dir.iterdir())
            self.assertEqual(
                names,
                ["CFG.TXT", "HELP.txt", "ID.txt", "SET_HMI.TXT", "manifest.json", "set_1.txt", "set_2.txt", "set_G.txt", "set_P1.txt", "transcript.txt"],
            )
            self.assertEqual((run_dir / "set_1.txt").read_bytes(), files["set_1.txt"])
            self.assertEqual(manifest["method"], "file_read")
            self.assertEqual(manifest["classes"], ["P1", "G", "1", "2"])
            self.assertEqual(manifest["skipped"], [])
            self.assertEqual(manifest["files"]["set_1.txt"]["sha256"], hashlib.sha256(files["set_1.txt"]).hexdigest())
            self.assertEqual(json.loads((run_dir / "manifest.json").read_text())["files"], manifest["files"])
            self.assertEqual([c[1] for c in client.calls], ["CFG.TXT", "set_P1.txt", "set_G.txt", "set_1.txt", "set_2.txt", "SET_HMI.TXT", None])
            self.assertEqual(client.calls[-2][2], NO_PAUSE.hmi_start_retries)
            self.assertEqual(client.calls[-1], ("help", None))

            devices = discover_devices(Path(tmp))
            self.assertEqual(len(devices), 1)
            run = devices[0]["captures"][-1]
            self.assertEqual(devices[0]["key"], "Alpha Solar/192.0.2.11_2381")
            self.assertEqual(run["captured_at"], "2026-10-12T12:00:00Z")
            self.assertEqual(run["status"], "ok")
            self.assertEqual(run["settings"]["1"]["CTR"], "500")
            self.assertEqual(run["identity"]["model"], "SEL-751")

    def test_a_stream_that_will_not_transfer_is_skipped(self):
        client = FakeClient(alpha_files())  # no SET_HMI.TXT on this device
        with tempfile.TemporaryDirectory() as tmp:
            manifest = capture_settings(client, Path(tmp) / "run", options=NO_PAUSE)
        self.assertEqual([s["file"] for s in manifest["skipped"]], ["SET_HMI.TXT"])
        self.assertIn("set_2.txt", manifest["files"])

    def test_a_missing_cfg_fails_the_capture(self):
        client = FakeClient({})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TriageError) as raised:
                capture_settings(client, Path(tmp) / "run", options=NO_PAUSE)
        self.assertEqual(raised.exception.category, "file_transfer_failed")

    def test_a_dropped_session_is_not_treated_as_a_skipped_stream(self):
        dropped = TriageError("closed", category="transport_eof", reachable=True)
        client = FakeClient(alpha_files(), fail={"set_G.txt": dropped})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TriageError) as raised:
                capture_settings(client, Path(tmp) / "run", options=NO_PAUSE)
        self.assertEqual(raised.exception.category, "transport_eof")

    def test_735_uses_file_show_and_no_hmi_stream(self):
        client = FakeClient(alpha_files(), family="sel735")
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            manifest = capture_settings(client, run_dir, options=NO_PAUSE)
            self.assertEqual((run_dir / "set_1.txt").read_bytes(), alpha_files()["set_1.txt"].replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        self.assertEqual(manifest["method"], "file_show")
        # the 735 has no HELP command (per its manual): only FILE SHOW is sent
        self.assertTrue(all(call[0] == "file_show" for call in client.calls))
        self.assertNotIn("SET_HMI.TXT", [call[1] for call in client.calls])

    def test_unexpected_class_codes_are_never_sent(self):
        files = alpha_files()
        files["CFG.TXT"] = b'[CLASSES]\r\n1,"Group 1"\r\n../X,"Odd"\r\nG;SET,"Odd"\r\n'
        client = FakeClient(files)
        with tempfile.TemporaryDirectory() as tmp:
            manifest = capture_settings(client, Path(tmp) / "run", options=NO_PAUSE)
        sent = [call[1] for call in client.calls if call[0] != "help"]
        self.assertEqual(sent, ["CFG.TXT", "set_1.txt", "SET_HMI.TXT"])
        self.assertEqual(
            [s["file"] for s in manifest["skipped"] if s["reason"] == "unexpected_class_code"],
            ["set_../X.txt", "set_G;SET.txt"],
        )

    def test_help_failure_keeps_the_settings(self):
        client = FakeClient(alpha_files())
        client.help_error = TriageError("Telnet read deadline expired", category="transport_timeout", reachable=True)
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            manifest = capture_settings(client, run_dir, options=NO_PAUSE)
            self.assertTrue((run_dir / "set_1.txt").is_file())
            self.assertFalse((run_dir / "HELP.txt").exists())
        self.assertIn("HELP.txt", [s["file"] for s in manifest["skipped"]])

    def test_help_can_be_turned_off(self):
        client = FakeClient(alpha_files())
        with tempfile.TemporaryDirectory() as tmp:
            capture_settings(client, Path(tmp) / "run", options=CaptureOptions(pause_seconds=0, capture_help=False))
        self.assertNotIn("help", [c[0] for c in client.calls])

    def test_pause_between_transfers(self):
        sleeps = []
        client = FakeClient(alpha_files())
        with tempfile.TemporaryDirectory() as tmp:
            capture_settings(client, Path(tmp) / "run", options=CaptureOptions(pause_seconds=0.3), sleep=sleeps.append)
        self.assertEqual(sleeps, [0.3] * 5)

    def test_transcript_is_redacted(self):
        client = FakeClient(alpha_files())
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            capture_settings(
                client, run_dir, transcript=lambda: b"ACC\r\nsecret-pass\r\n=>",
                redact=lambda text: text.replace("secret-pass", "[REDACTED]"), options=NO_PAUSE,
            )
            self.assertNotIn(b"secret-pass", (run_dir / "transcript.txt").read_bytes())


class TestHelpers(unittest.TestCase):
    def test_cfg_classes_accepts_quoted_codes(self):
        cfg = b'[INFO]\r\nRELAYTYPE=SEL-651R\r\n[CLASSES]\r\n"G","Global"\r\n"1","Group 1"\r\nL1,"Logic 1"\r\n[OTHER]\r\nX,"no"\r\n'
        self.assertEqual(cfg_classes(cfg), ["G", "1", "L1"])

    def test_extract_show_payload(self):
        raw = b"FILE SHOW CFG.TXT\r\n\x02\r\n[INFO]\r\nRELAYTYPE=SEL-735\r\n\x03\x02\r\n=>\x03"
        self.assertEqual(extract_show_payload(raw, "CFG.TXT"), b"[INFO]\r\nRELAYTYPE=SEL-735\r\n")

    def test_extract_show_payload_reports_device_errors(self):
        raw = b"FILE SHOW SET_9.TXT\r\n\x02\r\nInvalid File Name\r\n\x03\x02\r\n=>\x03"
        with self.assertRaises(FileShowError):
            extract_show_payload(raw, "SET_9.TXT")

    def test_extract_show_payload_without_framing_falls_back_to_text(self):
        self.assertEqual(extract_show_payload(b"\r\nA,B\r\n", "CFG.TXT"), b"A,B\r\n")


if __name__ == "__main__":
    unittest.main()
