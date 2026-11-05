import plistlib
from pathlib import Path
import tempfile
import unittest

from sel_triage.sel_archive import agent


class TestAgent(unittest.TestCase):
    def test_plist_runs_sweep_with_absolute_config(self):
        data = plistlib.loads(agent.build_plist("/venv/bin/python", "/repo", "/repo/config.local.json", 7, "/logs/s.log"))
        self.assertEqual(data["Label"], agent.LABEL)
        self.assertEqual(data["ProgramArguments"],
                         ["/venv/bin/python", "-m", "sel_triage", "sel-event-sweep", "--config", "/repo/config.local.json"])
        self.assertEqual(data["WorkingDirectory"], "/repo")
        self.assertEqual(data["StartCalendarInterval"], {"Hour": 7, "Minute": 0})

    def test_install_writes_plist_and_bootstraps(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent.plist"
            result = agent.install_agent("/py", "/repo", "/repo/c.json", 6, path=path,
                                         log_path=str(Path(tmp) / "log"),
                                         launchctl=lambda args: calls.append(args) or 0)
            self.assertTrue(path.is_file())
            self.assertTrue(result["installed"])
        self.assertEqual(calls[0][0], "bootout")
        self.assertEqual(calls[1][0], "bootstrap")

    def test_install_rejects_bad_hour_and_relative_config(self):
        with self.assertRaises(ValueError):
            agent.install_agent("/py", "/repo", "/repo/c.json", 24, launchctl=lambda a: 0)
        with self.assertRaises(ValueError):
            agent.install_agent("/py", "/repo", "c.json", 6, launchctl=lambda a: 0)

    def test_bootstrap_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                agent.install_agent("/py", "/repo", "/repo/c.json", 6, path=Path(tmp) / "a.plist",
                                    log_path=str(Path(tmp) / "log"),
                                    launchctl=lambda args: 0 if args[0] == "bootout" else 5)

    def test_sweep_client_factory_raises_command_deadline(self):
        from sel_triage.core.inventory import DeviceTarget

        target = DeviceTarget("Lab/Relay", "sel", "192.0.2.1", 23, "SEL-751", "sel/access1", 10)
        client = agent.sweep_client_factory(120.0)(target)
        self.assertEqual(client._command_seconds, 120.0)
        self.assertEqual(client._transport.read_timeout, 120.0)
