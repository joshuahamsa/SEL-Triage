"""Live settings capture may only read: ACC/ID at login, then FILE READ / FILE SHOW of settings files."""

from pathlib import Path
import re
import unittest

from sel_triage.render import render

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "sel_triage" / "integrations" / "devices" / "sel" / "settings" / "live.py",
    ROOT / "sel_triage" / "integrations" / "devices" / "sel" / "settings" / "xmodem.py",
    ROOT / "sel_triage" / "tools" / "sel_capture.py",
]
VPN = re.compile(r"vpn_connect|vpn_disconnect|vpn_session|prompt\s*=\s*True|interactive\s*=\s*True|/usr/bin/open")
CUSTOMER = re.compile(r"\b(?:10|172|192\.168)\.\d+\.\d+")
WIRE = re.compile(r"write_line|sendall|\.send\(|socket\.")


class TestSelSettingsCapturePublicSafety(unittest.TestCase):
    def test_never_touches_vpn_or_prompts(self):
        for path in FILES:
            with self.subTest(path=path.name):
                self.assertIsNone(VPN.search(path.read_text()))

    def test_no_customer_specific_values(self):
        for path in FILES:
            with self.subTest(path=path.name):
                self.assertIsNone(CUSTOMER.search(path.read_text()))

    def test_capture_code_never_writes_wire_text_itself(self):
        # Wire text comes only from the client's allowlisted command policy.
        for path in FILES:
            with self.subTest(path=path.name):
                self.assertIsNone(WIRE.search(path.read_text()))

    def test_only_settings_file_reads_are_issued(self):
        text = "\n".join(path.read_text() for path in FILES)
        self.assertEqual(set(re.findall(r'run_bytes\(\s*"(\w+)"', text)), {"file_show", "help"})
        self.assertEqual(set(re.findall(r"client\.(\w+)\(", text)), {"login", "read_file", "run_bytes", "logout"})

    def test_xmodem_only_receives(self):
        source = (FILES[1]).read_text()
        sent = set(re.findall(r"write\(bytes\(\[(\w+)\]\)\)", source))
        self.assertEqual(sent, {"CRC_C", "ACK", "NAK"})

    def test_not_exposed_over_mcp(self):
        for path in (ROOT / "sel_triage" / "mcp").rglob("*.py"):
            text = path.read_text()
            self.assertIsNone(re.search(r"tools\.sel_capture|import sel_capture|settings\.live|sel-settings-capture", text))

    def test_render(self):
        text = render({
            "tool": "sel-settings-capture", "ran_at": "2026-10-12T12:00:00Z", "ok": False, "root": "/tmp/x",
            "devices_selected": 2, "devices_attempted": 2, "devices_captured": 1, "stopped_early": False,
            "results": [
                {"device": "A/R1", "observed_model": "SEL-751", "method": "file_read", "ok": True,
                 "files": ["CFG.TXT", "set_1.txt"], "skipped": ["SET_HMI.TXT"]},
                {"device": "B/R1", "ok": False, "error_category": "authentication_failed"},
            ],
            "recent_skipped": [{"device": "C/R1", "captured_at": "2026-10-01T00:00:00Z"}],
        })
        self.assertIn("captured 1 of 2 attempted", text)
        self.assertIn("authentication_failed", text)
        self.assertIn("skipped SET_HMI.TXT", text)
        self.assertIn("recent capture kept: C/R1", text)


if __name__ == "__main__":
    unittest.main()
