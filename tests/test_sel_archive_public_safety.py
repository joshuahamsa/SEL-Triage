from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILES = sorted((ROOT / "sel_triage" / "sel_archive").glob("*.py"))
VPN = re.compile(r"vpn_connect|vpn_disconnect|vpn_session|prompt\s*=\s*True|interactive\s*=\s*True|/usr/bin/open")
CUSTOMER = re.compile(r"example-data-lake|111122223333")
# bare BRE is a Level 1 read in every manual (tests/test_sel_reference.py); BRE R/W are never sent
ALLOWED_DEVICE_CALLS = {"history", "ser", "eve", "breaker"}


class TestSelArchivePublicSafety(unittest.TestCase):
    def test_files_exist(self):
        self.assertGreaterEqual(len(FILES), 8)

    def test_never_touches_vpn_or_prompts(self):
        for path in FILES:
            with self.subTest(path=path.name):
                self.assertIsNone(VPN.search(path.read_text()))

    def test_no_customer_specific_values(self):
        for path in FILES:
            with self.subTest(path=path.name):
                self.assertIsNone(CUSTOMER.search(path.read_text()))

    def test_only_level1_reads_are_sent(self):
        for path in FILES:
            calls = set(re.findall(r'run_bytes\(\s*"(\w+)"', path.read_text()))
            with self.subTest(path=path.name):
                self.assertTrue(calls <= ALLOWED_DEVICE_CALLS, calls)

    def test_not_exposed_over_mcp(self):
        for path in (ROOT / "sel_triage" / "mcp").rglob("*.py"):
            self.assertNotIn("sel_archive", path.read_text())
