import contextlib
import io
import json
from unittest import mock
import unittest

from sel_triage import cli
from sel_triage.sel_archive import sweep as sweep_mod


def invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestSweepCli(unittest.TestCase):
    def test_sweep_dispatches_and_prints_summary(self):
        summary = {"tool": "sel-event-sweep", "ok": True, "skipped": "network_unreachable"}
        with mock.patch.object(cli, "_sel_event_sweep_inputs", return_value=({}, object(), object(), "/tmp/x")), \
                mock.patch.object(sweep_mod, "run_sweep", return_value=summary) as run:
            code, out, _ = invoke(["sel-event-sweep", "--config", "config.example.json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["skipped"], "network_unreachable")
        run.assert_called_once()

    def test_failed_sweep_returns_2(self):
        with mock.patch.object(cli, "_sel_event_sweep_inputs", return_value=({}, object(), object(), "/tmp/x")), \
                mock.patch.object(sweep_mod, "run_sweep", side_effect=RuntimeError("upload failed")):
            code, _, err = invoke(["sel-event-sweep", "--config", "config.example.json"])
        self.assertEqual(code, 2)
        self.assertIn("sweep_failed", err)
