from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from sel_triage.core.errors import TriageError
from sel_triage.core.inventory import DeviceTarget
from sel_triage.integrations.devices.rtac.credentials import read_keychain_login
from sel_triage.integrations.devices.rtac.workflow import run_rtac_snapshot


F = Path(__file__).parent / "fixtures" / "rtac"
SID = "11111111-2222-3333-4444-555555555555"
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
TARGET = DeviceTarget(name="Lab Site/RTAC", kind="rtac", host="192.0.2.1", port=4443,
                      model_hint=None, credential_ref="rtac/Lab Site", timeout_seconds=30)


class FakeClient:
    def __init__(self, fail_login=None, fail_fetch=None):
        self.fail_login = fail_login
        self.fail_fetch = fail_fetch or {}
        self.calls = []
        self.logged_in = False

    @property
    def redactions(self):
        return (SID,) if self.logged_in else ()

    def login(self, username, password):
        self.calls.append(("login", username))
        if self.fail_login:
            raise self.fail_login
        self.logged_in = True
        return (F / "home.html").read_text()

    def fetch(self, name):
        self.calls.append(("fetch", name))
        if name in self.fail_fetch:
            raise self.fail_fetch[name]
        files = {"soe": "soe.csv", "alarms": "alarms-none.csv", "diagnostics": "diagnostics.txt",
                 "ethernet_ieds": "ethernet_ieds.html", "serial_ieds": "serial_ieds.html"}
        return (F / files[name]).read_text()

    def logout(self):
        self.calls.append(("logout",))
        self.logged_in = False


def login_reader(service):
    assert service == "rtac/Lab Site"
    return "labuser", "secret-pw"


class RtacWorkflowTests(unittest.TestCase):
    def run_snapshot(self, client, reader=login_reader):
        with tempfile.TemporaryDirectory() as directory:
            result = run_rtac_snapshot(TARGET, reader, Path(directory), lambda target: client, NOW, None)
            stored = {p.name: p.read_text() for p in Path(directory).rglob("*") if p.is_file()}
        return result, stored

    def test_snapshot_collects_parses_redacts_and_logs_out(self):
        client = FakeClient()
        result, stored = self.run_snapshot(client)
        target = result["targets"][0]
        self.assertEqual(result["tool"], "rtac-snapshot")
        self.assertTrue(target["reachable"])
        self.assertTrue(target["ok"], target["errors"])
        self.assertEqual(target["identity"]["observed_model"], "SEL-3505-3")
        snapshot = target["snapshot"]
        self.assertEqual(snapshot["soe"]["project"], "LAB_Curtailment_R2")
        self.assertEqual(snapshot["alarms"], [])
        self.assertEqual(len(snapshot["ethernet_ieds"]), 3)
        self.assertEqual(snapshot["serial_ieds"], [])
        self.assertIn("rtac_failed_logins", [d["code"] for d in target["diagnostics"]])
        self.assertEqual(client.calls[-1], ("logout",))
        self.assertEqual(sorted(n.rsplit(".", 1)[0] for n in stored if not n.startswith("manifest")),
                         ["alarms", "diagnostics", "ethernet-ieds", "home", "serial-ieds", "soe"])
        for text in stored.values():
            self.assertNotIn(SID, text)
            self.assertNotIn("secret-pw", text)

    def test_missing_login_skips_contact(self):
        def no_login(service):
            raise TriageError("no saved RTAC login", category="credentials_missing")
        client = FakeClient()
        result, _ = self.run_snapshot(client, no_login)
        target = result["targets"][0]
        self.assertEqual(client.calls, [])
        self.assertIsNone(target["reachable"])
        self.assertEqual(target["errors"][0]["category"], "credentials_missing")

    def test_failed_login_is_reported_and_not_retried(self):
        client = FakeClient(fail_login=TriageError("rejected", category="authentication_failed", reachable=True))
        result, _ = self.run_snapshot(client)
        target = result["targets"][0]
        self.assertEqual([c[0] for c in client.calls], ["login", "logout"])
        self.assertIn("authentication_failed", [e["category"] for e in target["errors"]])

    def test_one_failed_endpoint_leaves_a_partial_result(self):
        client = FakeClient(fail_fetch={"diagnostics": TriageError("HTTP 500", category="rtac_http_error", reachable=True)})
        result, _ = self.run_snapshot(client)
        target = result["targets"][0]
        self.assertFalse(target["ok"])
        self.assertTrue(target["partial"])
        self.assertIn("soe", target["snapshot"])
        self.assertEqual(client.calls[-1], ("logout",))


class KeychainLoginTests(unittest.TestCase):
    def fake_runner(self, attrs_rc=0, password="pw"):
        def runner(cmd, capture_output, text, timeout):
            if "-w" in cmd:
                return subprocess.CompletedProcess(cmd, 0 if password else 44, stdout=(password or "") + "\n", stderr="")
            return subprocess.CompletedProcess(cmd, attrs_rc, stdout='    "acct"<blob>="site-user"\n', stderr="")
        return runner

    def test_reads_username_and_password(self):
        self.assertEqual(read_keychain_login("rtac/Lab Site", runner=self.fake_runner()), ("site-user", "pw"))

    def test_missing_entry_is_credentials_missing(self):
        with self.assertRaises(TriageError) as ctx:
            read_keychain_login("rtac/Lab Site", runner=self.fake_runner(attrs_rc=44))
        self.assertEqual(ctx.exception.category, "credentials_missing")
        self.assertIn("security add-generic-password -s 'rtac/Lab Site' -a <username> -w", str(ctx.exception))


class RtacCliTests(unittest.TestCase):
    def setUp(self):
        import json
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Path(self.tmp.name) / "config.json"
        self.cfg.write_text(json.dumps({"diagnosticThresholds": {"rtac_recent_days": 7, "breaker_wear_percent": 90}}))
        (Path(self.tmp.name) / "devices.json").write_text(json.dumps({"devices": [
            {"name": "Lab Site/RTAC", "site": "Lab Site", "kind": "rtac", "host": "192.0.2.1", "port": 4443,
             "credentialRef": "rtac/Lab Site"},
            {"name": "Lab Site/Relay", "site": "Lab Site", "kind": "sel", "host": "192.0.2.2", "port": 2381,
             "credentialRef": "sel/access1"},
        ]}))

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, argv):
        import contextlib
        import io
        from unittest import mock
        from sel_triage import cli
        from sel_triage.integrations.devices.rtac import workflow

        out, err = io.StringIO(), io.StringIO()
        envelope = {"tool": "rtac-snapshot", "ran_at": "t", "ok": True, "targets": [{
            "name": "Lab Site/RTAC", "reachable": True, "identity": {"observed_model": "SEL-3505-3", "device_id": "X"},
            "snapshot": {"soe": {"event_count": 11, "firmware": "R147", "project": "LAB", "last_power_up": "2026-09-01"},
                         "alarms": [], "ethernet_ieds": [{}, {}], "serial_ieds": []},
            "diagnostics": [{"code": "rtac_failed_logins", "severity": "warning"}], "evidence": [], "errors": []}],
            "errors": []}
        with mock.patch.object(workflow, "run_rtac_snapshot", return_value=envelope) as run, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue(), run

    def test_rtac_snapshot_resolves_rtac_target_and_thresholds(self):
        code, out, err, run = self.invoke(["rtac-snapshot", "--config", str(self.cfg), "--name", "Lab Site/RTAC", "--render"])
        self.assertEqual((code, err), (0, ""))
        target = run.call_args.args[0]
        self.assertEqual((target.name, target.kind, target.credential_ref), ("Lab Site/RTAC", "rtac", "rtac/Lab Site"))
        self.assertEqual(run.call_args.kwargs["thresholds"], {"rtac_recent_days": 7, "breaker_wear_percent": 90})
        self.assertIn("model=SEL-3505-3", out)
        self.assertIn("project=LAB", out)
        self.assertIn("diagnostic[warning]: rtac_failed_logins", out)

    def test_rtac_snapshot_rejects_non_rtac_device(self):
        code, out, err, run = self.invoke(["rtac-snapshot", "--config", str(self.cfg), "--name", "Lab Site/Relay"])
        self.assertEqual(code, 2)
        self.assertIn("not an RTAC", err)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
