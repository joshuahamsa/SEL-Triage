"""Repository-wide guard: nothing that identifies a real site, network or person ships.

Every tracked text file is scanned for:

- IPv4 addresses outside the documentation ranges (RFC 5737: 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) and a few universal addresses;
- e-mail addresses outside example domains;
- absolute home-directory paths (``/Users/<name>``, ``/home/<name>``);
- any term listed, one per line, in an optional, git-ignored ``.denylist.local``
  at the repository root. Put customer, site and employer names there; the
  file never leaves your machine, and the test passes when it is absent.
"""

import ipaddress
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DENYLIST = ROOT / ".denylist.local"

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HOME_PATH = re.compile(r"/(?:Users|home)/(?!<|\$|\{)[A-Za-z0-9._-]+")

DOC_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
ALLOWED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.0", "255.255.255.255"}
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid", "noreply.github.com")
BINARY_SUFFIXES = {".rdb", ".png", ".jpg", ".gif", ".pdf", ".sqlite", ".xlsx"}


def _tracked_files():
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
        ).stdout.decode()
        names = [name for name in out.split("\0") if name]
    except (OSError, subprocess.CalledProcessError):
        names = [
            str(path.relative_to(ROOT))
            for path in ROOT.rglob("*")
            if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts
        ]
    return [ROOT / name for name in names if Path(name).suffix.lower() not in BINARY_SUFFIXES]


def _text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _is_allowed_ip(text):
    if text in ALLOWED_IPS:
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True  # not an address (e.g. a version string like 1.2.3.4000)
    if any(address in network for network in DOC_NETWORKS):
        return True
    # dotted version numbers are not network addresses; only flag private or routable-looking ones
    return not (address.is_private or address.is_global)


def _local_denylist():
    if not DENYLIST.is_file():
        return []
    terms = []
    for line in DENYLIST.read_text(encoding="utf-8").splitlines():
        term = line.strip()
        if term and not term.startswith("#"):
            terms.append(term)
    return terms


class TestRepositoryPublicData(unittest.TestCase):
    def setUp(self):
        self.files = [path for path in _tracked_files() if path.name != DENYLIST.name]

    def test_only_documentation_ip_addresses(self):
        for path in self.files:
            found = [ip for ip in IPV4.findall(_text(path)) if not _is_allowed_ip(ip)]
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertEqual(found, [])

    def test_no_real_email_addresses(self):
        for path in self.files:
            found = [
                address
                for address in EMAIL.findall(_text(path))
                if not address.lower().endswith(ALLOWED_EMAIL_DOMAINS)
            ]
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertEqual(found, [])

    def test_no_home_directory_paths(self):
        for path in self.files:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertEqual(HOME_PATH.findall(_text(path)), [])

    def test_no_locally_denylisted_terms(self):
        terms = _local_denylist()
        if not terms:
            self.skipTest("no .denylist.local")
        pattern = re.compile("|".join(re.escape(term) for term in terms), re.IGNORECASE)
        for path in self.files:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertEqual(sorted(set(pattern.findall(_text(path)))), [])


if __name__ == "__main__":
    unittest.main()
