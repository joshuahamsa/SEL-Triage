from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from sel_triage.core.errors import TriageError
from sel_triage.sel_archive import records
from sel_triage.sel_archive.archive import MemoryArchive
from sel_triage.sel_archive.settings import archive_settings
from sel_triage.sel_archive.state import SweepState, open_state
from sel_triage.sel_archive.sweep import (
    SweepDeps,
    UnreachableGuard,
    fleet_items,
    run_sweep,
)

NOW = datetime(2026, 10, 6, 7, 0, tzinfo=timezone.utc)
HIS = b"HIS\r\nSEL-751  Date: 10/06/2026  Time: 03:00:00.000\r\n=>"


def config(devices):
    return {
        "secretKeychainService": "sel-triage",
        "requestTimeoutSeconds": 5,
        "devices": devices,
        "selEventArchive": {"bucket": "b", "unreachableStopAfter": 2, "maxSitesParallel": 2},
    }


def device(site, label, host="192.0.2.1"):
    return {"name": "{0}/{1}".format(site, label), "site": site, "label": label, "kind": "sel",
            "host": host, "port": 23, "modelHint": "SEL-751", "credentialRef": "sel/access1"}


class Identity:
    observed_model = "SEL-751"
    device_id = "DEV"


class Client:
    def __init__(self, target):
        self.target = target

    def login(self, password):
        if self.target.host == "192.0.2.99":
            raise TriageError("down", "connection_failed", reachable=False)
        return Identity()

    def run_bytes(self, capability, argument=None):
        return HIS if capability == "history" else b"SER\r\n=>"

    def logout(self):
        pass


class Secrets:
    def get(self, ref):
        return "synthetic-password"


def deps(archive=None, gp=True, aws=True, notes=None):
    return SweepDeps(
        network_up=lambda: gp, aws_ok=lambda: aws,
        notify=(notes.append if notes is not None else (lambda m: None)),
        client_factory=Client, secret_provider=Secrets(),
        archive=archive or MemoryArchive(), clock=lambda: NOW,
    )


class TestFleetItems(unittest.TestCase):
    def test_filters_sel_and_site(self):
        cfg = config([device("Alpha", "Relay"), device("Beta", "Meter"),
                      dict(device("Alpha", "Inverter"), kind="sma")])
        self.assertEqual([i.target.name for i in fleet_items(cfg)], ["Alpha/Relay", "Beta/Meter"])
        self.assertEqual([i.site for i in fleet_items(cfg, site="alp")], ["Alpha"])
        self.assertEqual([i.target.name for i in fleet_items(cfg, name="Beta/Meter")], ["Beta/Meter"])
        self.assertEqual(fleet_items(cfg, name="Beta"), [])


class TestGuard(unittest.TestCase):
    def test_stops_after_distinct_sites(self):
        guard = UnreachableGuard(2)
        self.assertFalse(guard.observe("A", False))
        self.assertFalse(guard.observe("A", False))  # same site twice is not enough
        self.assertTrue(guard.observe("B", False))
        guard = UnreachableGuard(2)
        guard.observe("A", False)
        guard.observe("C", True)  # reachable resets
        self.assertFalse(guard.observe("B", False))


class TestRunSweep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_path = Path(self.tmp.name) / "sel-events.sqlite"

    def tearDown(self):
        self.tmp.cleanup()

    def settings(self, cfg):
        return archive_settings(cfg)

    def test_skips_without_vpn_and_notifies_when_stale(self):
        notes = []
        cfg = config([device("Alpha", "Relay")])
        summary = run_sweep(cfg, self.settings(cfg), deps(gp=False, notes=notes), self.state_path)
        self.assertEqual(summary["skipped"], "network_unreachable")
        self.assertTrue(summary["ok"])
        self.assertEqual(len(notes), 1)  # never succeeded counts as stale

    def test_skips_without_aws(self):
        cfg = config([device("Alpha", "Relay")])
        summary = run_sweep(cfg, self.settings(cfg), deps(aws=False), self.state_path)
        self.assertEqual(summary["skipped"], "aws_session_invalid")

    def test_full_sweep_commits_and_records_state(self):
        archive = MemoryArchive()
        cfg = config([device("Alpha", "Relay"), device("Beta", "Meter")])
        summary = run_sweep(cfg, self.settings(cfg), deps(archive), self.state_path)
        self.assertIsNone(summary["skipped"])
        self.assertEqual(summary["devices_attempted"], 2)
        self.assertEqual(summary["devices_succeeded"], 2)
        run_id = summary["run_id"]
        self.assertEqual(archive.puts[-1], records.normalized_key("sel_events", run_id, "runs.jsonl"))
        conn = open_state(self.state_path)
        try:
            state = SweepState(conn)
            self.assertEqual(state.last_success(records.device_key("Alpha/Relay")), "2026-10-06T07:00:00Z")
        finally:
            conn.close()

    def test_failed_commit_leaves_state_untouched(self):
        archive = MemoryArchive()
        archive.fail_on = "runs.jsonl"
        cfg = config([device("Alpha", "Relay")])
        with self.assertRaises(RuntimeError):
            run_sweep(cfg, self.settings(cfg), deps(archive), self.state_path)
        conn = open_state(self.state_path)
        try:
            self.assertIsNone(SweepState(conn).latest_success_any())
        finally:
            conn.close()
        # the lock was released: a new sweep runs
        summary = run_sweep(cfg, self.settings(cfg), deps(MemoryArchive()), self.state_path)
        self.assertIsNone(summary["skipped"])

    def test_early_stop_when_vpn_drops(self):
        cfg = config([device("A", "R", "192.0.2.99"), device("B", "R", "192.0.2.99"),
                      device("C", "R", "192.0.2.99"), device("D", "R", "192.0.2.99")])
        cfg["selEventArchive"]["maxSitesParallel"] = 1  # deterministic order
        answers = iter([True, False])  # up at preflight, down when the guard trips
        sweep_deps = deps()
        sweep_deps.network_up = lambda: next(answers)
        summary = run_sweep(cfg, self.settings(cfg), sweep_deps, self.state_path)
        self.assertTrue(summary["stopped_early"])
        self.assertEqual(summary["devices_attempted"], 2)
        self.assertEqual(summary["devices_succeeded"], 0)

    def test_oldest_success_goes_first(self):
        cfg = config([device("Alpha", "Relay"), device("Beta", "Meter")])
        conn = open_state(self.state_path)
        SweepState(conn).record(records.device_key("Alpha/Relay"), "2026-10-05T07:00:00Z", None, None, [])
        conn.close()
        archive = MemoryArchive()
        cfg["selEventArchive"]["maxSitesParallel"] = 1
        summary = run_sweep(cfg, self.settings(cfg), deps(archive), self.state_path)
        runs = records.from_jsonl(archive.objects[records.normalized_key("sel_events", summary["run_id"], "runs.jsonl")])
        self.assertEqual([r["name"] for r in runs], ["Beta/Meter", "Alpha/Relay"])

    def test_dead_devices_first_do_not_stop_a_healthy_sweep(self):
        # never-succeeded dead devices sort first; GP is still up, so keep going
        dead = [device("Dead{0}".format(n), "R", "192.0.2.99") for n in range(6)]
        live = [device("Live{0}".format(n), "R") for n in range(3)]
        cfg = config(dead + live)
        cfg["selEventArchive"]["maxSitesParallel"] = 1
        conn = open_state(self.state_path)
        state = SweepState(conn)
        for n in range(3):
            state.record(records.device_key("Live{0}/R".format(n)), "2026-10-05T07:00:00Z", None, None, [])
        conn.close()
        gp_checks = []
        sweep_deps = deps()
        sweep_deps.network_up = lambda: gp_checks.append(1) or True
        summary = run_sweep(cfg, self.settings(cfg), sweep_deps, self.state_path)
        self.assertFalse(summary["stopped_early"])
        self.assertEqual(summary["devices_attempted"], 9)
        self.assertEqual(summary["devices_succeeded"], 3)
        self.assertGreater(len(gp_checks), 1)  # the guard re-checked the tunnel
