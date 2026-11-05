"""sel-settings-capture orchestration with fake clients (no network, no Keychain)."""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from sel_triage.core.errors import TriageError
from sel_triage.integrations.devices.sel.settings.capture import discover_devices
from sel_triage.integrations.devices.sel.settings.live import CaptureOptions
from sel_triage.tools import sel_capture
from tests.test_sel_settings_live import FakeClient, alpha_files

NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
SECRET = "synthetic-level1"


def config(*devices):
    return {
        "defaults": {"credentialRef": "sel/access1", "timeoutSeconds": 5},
        "devices": [
            {"name": name, "kind": "sel", "host": host, "port": 2381, "site": site}
            for name, site, host in devices
        ],
    }


class Provider:
    def __init__(self):
        self.calls = []

    def get(self, ref):
        self.calls.append(ref)
        return SECRET


class LoggingClient(FakeClient):
    def __init__(self, *args, login_error=None, transcript=b"", **kwargs):
        super().__init__(*args, **kwargs)
        self.login_error = login_error
        self.logins = []
        self.logouts = 0
        self.transcript = transcript
        self._identity = self.identity
        self.identity = None

    def login(self, password):
        self.logins.append(password)
        if self.login_error is not None:
            raise self.login_error
        self.identity = self._identity
        return self.identity

    def logout(self):
        self.logouts += 1


def deps(clients, gp=True, provider=None):
    made = []

    def factory(target):
        client = clients[target.name]
        made.append(client)
        return client

    gp_values = list(gp) if isinstance(gp, (list, tuple)) else None
    return sel_capture.CaptureDeps(
        network_up=(lambda: gp_values.pop(0) if gp_values else False) if gp_values is not None else (lambda: gp),
        client_factory=factory,
        secret_provider=provider or Provider(),
        clock=lambda: NOW,
        sleep=lambda seconds: None,
    ), made


def settings(root, **overrides):
    values = dict(root=Path(root), options=CaptureOptions(pause_seconds=0), max_sites_parallel=2)
    values.update(overrides)
    return sel_capture.CaptureSettings(**values)


class TestCaptureTool(unittest.TestCase):
    def test_captures_into_sel_audit_layout_that_offline_tools_read(self):
        cfg = config(("Alpha/Relay 1", "Alpha Solar", "192.0.2.11"))
        client = LoggingClient(alpha_files(), transcript=b"=ACC\r\nPassword: " + SECRET.encode() + b"\r\n=>")
        d, _ = deps({"Alpha/Relay 1": client})
        with tempfile.TemporaryDirectory() as tmp:
            summary = sel_capture.run_capture(cfg, sel_capture.select_items(cfg), settings(tmp), d)
            run_dir = Path(tmp) / "Alpha Solar" / "192.0.2.11_2381" / "20261012T120000Z"
            self.assertTrue((run_dir / "set_1.txt").is_file())
            self.assertNotIn(SECRET.encode(), (run_dir / "transcript.txt").read_bytes())
            devices = discover_devices(Path(tmp))
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["devices_captured"], 1)
        self.assertEqual(client.logins, [SECRET])
        self.assertEqual(client.logouts, 1)
        self.assertEqual(devices[0]["captures"][-1]["status"], "ok")
        self.assertEqual(summary["results"][0]["skipped"], ["SET_HMI.TXT"])

    def test_failed_login_is_not_retried_and_leaves_an_error_file(self):
        cfg = config(("Beta/Relay", "Beta Solar", "192.0.2.21"))
        failure = TriageError("SEL Access Level 1 authentication failed", category="authentication_failed", reachable=True)
        client = LoggingClient(alpha_files(), login_error=failure, transcript=b"Password: " + SECRET.encode())
        d, made = deps({"Beta/Relay": client})
        with tempfile.TemporaryDirectory() as tmp:
            summary = sel_capture.run_capture(cfg, sel_capture.select_items(cfg), settings(tmp), d)
            error = (Path(tmp) / "Beta Solar" / "192.0.2.21_2381" / "20261012T120000Z" / "ERROR.txt").read_text()
            run = discover_devices(Path(tmp))[0]["captures"][-1]
        self.assertFalse(summary["ok"])
        self.assertEqual(len(made), 1)
        self.assertEqual(client.logins, [SECRET])
        self.assertEqual(summary["failures"], [{"device": "Beta/Relay", "category": "authentication_failed",
                                               "path": "Beta Solar/192.0.2.21_2381/20261012T120000Z"}])
        self.assertIn("authentication_failed", error)
        self.assertNotIn(SECRET, error)
        self.assertEqual(run["status"], "failed")

    def test_vpn_down_contacts_nothing(self):
        cfg = config(("Alpha/Relay 1", "Alpha Solar", "192.0.2.11"))
        provider = Provider()
        d, made = deps({}, gp=False, provider=provider)
        with tempfile.TemporaryDirectory() as tmp:
            summary = sel_capture.run_capture(cfg, sel_capture.select_items(cfg), settings(tmp), d)
        self.assertEqual(summary["skipped"], "network_unreachable")
        self.assertFalse(summary["ok"])
        self.assertEqual(made, [])
        self.assertEqual(provider.calls, [])

    def test_recent_ok_captures_are_skipped(self):
        cfg = config(("Alpha/Relay 1", "Alpha Solar", "192.0.2.11"), ("Gamma/Relay", "Gamma Solar", "192.0.2.31"))
        clients = {"Alpha/Relay 1": LoggingClient(alpha_files()), "Gamma/Relay": LoggingClient(alpha_files())}
        with tempfile.TemporaryDirectory() as tmp:
            first, _ = deps(clients)
            sel_capture.run_capture(cfg, sel_capture.select_items(cfg, name="Alpha/Relay 1"), settings(tmp), first)
            clients["Alpha/Relay 1"].logins.clear()
            again, made = deps(clients)
            summary = sel_capture.run_capture(cfg, sel_capture.select_items(cfg), settings(tmp, max_age_days=30), again)
        self.assertEqual([r["device"] for r in summary["recent_skipped"]], ["Alpha/Relay 1"])
        self.assertEqual([c for c in made], [clients["Gamma/Relay"]])
        self.assertEqual(clients["Alpha/Relay 1"].logins, [])

    def test_sweep_stops_when_unreachable_devices_span_sites_and_gp_is_down(self):
        sites = [("S{0}/Relay".format(i), "Site {0}".format(i), "192.0.2.{0}".format(40 + i)) for i in range(6)]
        cfg = config(*sites)
        down = TriageError("unable to establish Telnet connection", category="route_or_tcp", reachable=False)
        clients = {name: LoggingClient(alpha_files(), login_error=down) for name, _, _ in sites}
        d, made = deps(clients, gp=[True, False])
        with tempfile.TemporaryDirectory() as tmp:
            summary = sel_capture.run_capture(
                cfg, sel_capture.select_items(cfg), settings(tmp, max_sites_parallel=1, unreachable_stop_after=3), d
            )
        self.assertTrue(summary["stopped_early"])
        self.assertFalse(summary["ok"])
        self.assertEqual(len(made), 3)

    def test_select_by_name_requires_an_sel_device(self):
        cfg = config(("Alpha/Relay 1", "Alpha Solar", "192.0.2.11"))
        cfg["devices"].append({"name": "Alpha/Inverter", "kind": "sma", "host": "192.0.2.12", "port": 443, "site": "Alpha Solar"})
        self.assertEqual([i.site for i in sel_capture.select_items(cfg, name="Alpha/Relay 1")], ["Alpha Solar"])
        with self.assertRaises(ValueError):
            sel_capture.select_items(cfg, name="Alpha/Inverter")

    def test_a_device_listed_twice_gets_one_login(self):
        cfg = config(("Mud/Relay", "Mud Lake", "192.0.2.51"), ("Mud/Relay (dup)", "Mud Lake", "192.0.2.51"))
        client = LoggingClient(alpha_files())
        d, made = deps({"Mud/Relay": client})
        with tempfile.TemporaryDirectory() as tmp:
            summary = sel_capture.run_capture(cfg, sel_capture.select_items(cfg), settings(tmp), d)
        self.assertEqual(len(made), 1)
        self.assertEqual(summary["duplicate_endpoints"], [{"device": "Mud/Relay (dup)", "same_endpoint_as": "Mud/Relay"}])
        self.assertEqual(summary["devices_attempted"], 1)

    def test_folder_names_are_safe(self):
        self.assertEqual(sel_capture.folder_name(' Lowes: 1030/Anaheim? '), "Lowes_ 1030_Anaheim_")
        self.assertEqual(sel_capture.folder_name("..."), "(unnamed)")


if __name__ == "__main__":
    unittest.main()
