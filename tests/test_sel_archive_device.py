from datetime import datetime, timezone
from pathlib import Path
import unittest

from sel_triage.core.errors import TriageError
from sel_triage.core.inventory import DeviceTarget
from sel_triage.sel_archive.device import (
    SweepItem,
    valid_device_ts,
    detect_gap,
    device_clock_offset,
    select_reports,
    sweep_device,
)
from sel_triage.sel_archive.settings import archive_settings
from sel_triage.sel_archive.state import DevicePrior

FIXTURES = Path(__file__).parent / "fixtures" / "sel"
NOW = datetime(2026, 10, 6, 7, 0, tzinfo=timezone.utc)
SETTINGS = archive_settings({"selEventArchive": {"bucket": "b", "eventsPerRun": 2}})


def fixture(name):
    return (FIXTURES / name).read_bytes()


def item(model="SEL-700GT"):
    return SweepItem(
        "Lab Site",
        DeviceTarget(
            name="Lab Site/Relay", kind="sel", host="192.0.2.10", port=23,
            model_hint=model, credential_ref="sel/access1", timeout_seconds=5,
        ),
    )


class FakeIdentity:
    def __init__(self, model):
        self.observed_model = model
        self.device_id = "LAB-RELAY-01"


class FakeSecrets:
    def get(self, credential_ref):
        return "synthetic-password"


class FakeClient:
    """Responses: capability -> bytes, list of bytes (consumed in order), or exception."""

    def __init__(self, model, responses, login_error=None):
        self.model = model
        self.responses = dict(responses)
        self.login_error = login_error
        self.calls = []
        self.logout_calls = 0

    def login(self, password):
        self.calls.append(("login",))
        if self.login_error is not None:
            raise self.login_error
        return FakeIdentity(self.model)

    def run_bytes(self, capability, argument=None):
        self.calls.append((capability, argument))
        if capability == "breaker" and capability not in self.responses:
            return b"BRE\r\n=>"  # a device whose BRE output the test does not care about
        value = self.responses[(capability, argument)] if (capability, argument) in self.responses \
            else self.responses[capability]
        if isinstance(value, list):
            value = value.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def logout(self):
        self.logout_calls += 1


def run(client, prior=DevicePrior(), sweep_item=None, settings=SETTINGS):
    return sweep_device(
        sweep_item or item(client.model), prior, secret_provider=FakeSecrets(),
        client_factory=lambda target: client, settings=settings, clock=lambda: NOW,
    )


class TestHelpers(unittest.TestCase):
    def test_detect_gap(self):
        self.assertIsNone(detect_gap(None, ["2026-01-01T00:00:00"]))
        self.assertTrue(detect_gap("2026-01-01T00:00:00", ["2026-01-02T00:00:00"]))
        self.assertFalse(detect_gap("2026-01-02T00:00:00", ["2026-01-01T00:00:00", "2026-01-03T00:00:00"]))
        self.assertFalse(detect_gap("2026-01-02T00:00:00", []))

    def test_select_reports_oldest_first_and_capped(self):
        events = [
            {"event_number": 1, "timestamp": "2026-01-03T00:00:00"},
            {"event_number": 2, "timestamp": "2026-01-02T00:00:00"},
            {"event_number": 3, "timestamp": "2026-01-01T00:00:00"},
        ]
        chosen, pending = select_reports(events, frozenset({("2026-01-01T00:00:00", "eve")}), 1)
        self.assertEqual([e["event_number"] for e in chosen], [2])
        self.assertEqual(pending, 2)

    def test_clock_offset_from_his_header(self):
        text = fixture("735-history.txt").decode()
        read_at = datetime(2026, 9, 25, 16, 57, 2, tzinfo=timezone.utc)
        self.assertAlmostEqual(device_clock_offset(text, read_at), -14399.172, places=3)
        self.assertIsNone(device_clock_offset("no header here", read_at))


class TestDeviceTs(unittest.TestCase):
    def test_valid_device_ts(self):
        self.assertTrue(valid_device_ts("2026-09-13T16:48:22.988"))
        self.assertTrue(valid_device_ts("2026-09-13T16:48:22"))
        self.assertFalse(valid_device_ts("2026-13-09T16:48:22.988"))  # DMY relay
        self.assertFalse(valid_device_ts("2026-02-30T00:00:00"))
        self.assertFalse(valid_device_ts(None))


class TestSweepDevice(unittest.TestCase):
    def test_700g_reads_his_reports_and_ser(self):
        his = fixture("700gt-history.txt")
        client = FakeClient("SEL-700GT", {
            "history": [his, his],
            "eve": b"EVENT REPORT TEXT",
            "ser": fixture("700gt-ser.txt"),
            "breaker": fixture("700gt-breaker.txt"),
        })
        result = run(client)
        row = result.run_row
        self.assertTrue(result.success)
        self.assertTrue(row["ok"], row["errors"])
        self.assertEqual(row["family"], "sel700g")
        self.assertEqual(row["his_parse"], "parsed")
        self.assertEqual(row["ser_parse"], "parsed")
        self.assertGreater(row["ser_rows"], 0)
        self.assertEqual(row["reports_fetched"], min(2, row["his_rows"]))
        self.assertIn("his.txt", result.raw)
        self.assertIn("ser.txt", result.raw)
        self.assertEqual(len(result.report_rows), row["reports_fetched"])
        # every fetched report gets a summary (parsed or a parse_failed row), never an exception
        self.assertEqual(set(result.event_summaries), {r["raw_name"] for r in result.report_rows})
        self.assertTrue(all(s["report_parse"] in ("parsed", "parse_failed") for s in result.event_summaries.values()))
        ser_at = client.calls.index(("ser", None))
        first_eve = next(i for i, c in enumerate(client.calls) if c[0] == "eve")
        self.assertLess(ser_at, first_eve)  # SER before event reports
        self.assertEqual(client.logout_calls, 1)
        oldest = sorted(r["device_ts"] for r in result.history_rows)[0]
        self.assertEqual(result.report_rows[0]["device_ts"], oldest)
        # BRE is read last, after SER and the event reports
        self.assertEqual(client.calls[-1], ("breaker", None))
        self.assertEqual(result.breaker["bre_parse"], "parsed")
        self.assertEqual(result.breaker["breaker_wear_percent"], 100.0)
        self.assertEqual(result.breaker["operation_count"], 13234)
        self.assertIn("bre.txt", result.raw)

    def test_invalid_timestamps_are_dropped_not_loaded(self):
        his = fixture("735-history.txt").replace(b"09/13/26 16:48:22.988", b"13/09/26 16:48:22.988")
        client = FakeClient("SEL-735", {"history": his, "ser": b"SER\r\n=>"})
        result = run(client)
        self.assertTrue(result.success)
        self.assertIn("invalid_device_ts", result.run_row["warnings"])
        self.assertTrue(all(valid_device_ts(r["device_ts"]) for r in result.history_rows))
        self.assertEqual(result.run_row["his_rows"], len(result.history_rows))
        self.assertGreater(len(result.history_rows), 0)

    def test_ser_without_a_table_parses_to_no_rows_and_keeps_raw(self):
        client = FakeClient("SEL-751", {
            "history": fixture("751-history.txt"),
            "ser": b"SER\r\nraw text with no table\r\n=>",
        })
        result = run(client)
        row = result.run_row
        self.assertTrue(result.success)
        self.assertEqual(row["ser_parse"], "parsed")
        self.assertEqual(row["ser_rows"], 0)
        self.assertEqual(result.ser_rows, [])
        self.assertEqual(result.raw["ser.txt"], b"SER\r\nraw text with no table\r\n=>")

    def test_751_ser_rows_from_a_live_capture(self):
        ser = (Path(__file__).parent / "fixtures" / "sel" / "ser" / "751-ser.txt").read_bytes()
        client = FakeClient("SEL-751", {"history": fixture("751-history.txt"), "ser": ser})
        result = run(client)
        self.assertEqual(result.run_row["ser_parse"], "parsed")
        self.assertGreater(len(result.ser_rows), 10)
        self.assertIn(("Relay Settings Changed", "Event"), {(r["element"], r["state"]) for r in result.ser_rows})
        self.assertEqual(result.run_row["parser_version"], 3)
        self.assertNotIn(("eve", 1), client.calls)  # sel751 not in eventReportFamilies

    def test_751a_history_rows_without_ref_and_location_columns(self):
        ser = (Path(__file__).parent / "fixtures" / "sel" / "ser" / "751a-ser.txt").read_bytes()
        client = FakeClient("SEL-751A", {"history": fixture("751a-history.txt"), "ser": ser})
        result = run(client)
        self.assertEqual(result.run_row["his_parse"], "parsed")
        self.assertEqual(result.run_row["his_rows"], 7)
        self.assertEqual(result.history_rows[0]["event_type"], "Underfreq 81 Trip")

    def test_empty_history_still_archives_raw(self):
        client = FakeClient("SEL-751", {
            "history": b"HIS\r\nSEL-751  Date: 10/06/2026  Time: 03:00:00.000\r\n=>",
            "ser": b"SER\r\n=>",
        })
        result = run(client)
        self.assertTrue(result.success)
        self.assertEqual(result.run_row["his_rows"], 0)
        self.assertEqual(result.history_rows, [])
        self.assertEqual(result.run_row["reports_fetched"], 0)

    def test_gap_flagged_when_oldest_record_is_newer_than_stored(self):
        client = FakeClient("SEL-700GT", {
            "history": [fixture("700gt-history.txt")] * 2,
            "eve": b"x", "ser": fixture("700gt-ser.txt"),
        })
        result = run(client, prior=DevicePrior("1999-01-01T00:00:00", "1999-01-01T00:00:00"))
        self.assertTrue(result.run_row["ser_gap"])
        self.assertTrue(result.run_row["his_gap"])

    def test_clock_reset_does_not_flag_gap(self):
        client = FakeClient("SEL-700GT", {
            "history": [fixture("700gt-history.txt")] * 2,
            "eve": b"x", "ser": fixture("700gt-ser.txt"),
        })
        result = run(client, prior=DevicePrior("2099-01-01T00:00:00", "2099-01-01T00:00:00"))
        self.assertFalse(result.run_row["ser_gap"])
        self.assertFalse(result.run_row["his_gap"])
        self.assertGreater(len(result.ser_rows), 0)

    def test_history_change_discards_reports(self):
        his = fixture("700gt-history.txt").decode()
        header = "#  REF      DATE        TIME        EVENT        CURRENT   FREQX FREQY TARGETS"
        self.assertIn(header, his)
        # a new event arrives between the first HIS read and the re-check
        newer = his.replace(
            header,
            header + "\n1  23552 09/20/2026 08:00:00.000 ER Trigger         30.0   60.0  60.0  11000000",
        )
        client = FakeClient("SEL-700GT", {
            "history": [his.encode(), newer.encode()],
            "eve": b"x", "ser": fixture("700gt-ser.txt"),
        })
        result = run(client)
        self.assertIn("history_changed_during_sweep", result.run_row["warnings"])
        self.assertEqual(result.report_rows, [])
        self.assertFalse(any(name.startswith("event-") for name in result.raw))
        self.assertEqual(result.run_row["reports_fetched"], 0)
        self.assertTrue(result.success)

    def test_event_report_failure_does_not_block_ser(self):
        client = FakeClient("SEL-700GT", {
            "history": [fixture("700gt-history.txt")] * 2,
            "eve": TriageError("slow", "transport_timeout", reachable=True),
            "ser": fixture("700gt-ser.txt"),
        })
        result = run(client)
        self.assertTrue(result.success)
        self.assertIn("ser.txt", result.raw)
        self.assertGreater(len(result.ser_rows), 0)
        self.assertEqual(result.report_rows, [])
        self.assertIn("transport_timeout", result.run_row["errors"])
        self.assertGreater(result.run_row["reports_pending"], 0)

    def test_oversize_ser_skips_event_reports(self):
        client = FakeClient("SEL-700GT", {
            "history": [fixture("700gt-history.txt")] * 2,
            "eve": b"x",
            "ser": TriageError("too large", "response_too_large", reachable=True),
        })
        result = run(client)
        self.assertFalse(any(c[0] == "eve" for c in client.calls))  # session closed

    def test_oversize_ser_keeps_history(self):
        client = FakeClient("SEL-700GT", {
            "history": [fixture("700gt-history.txt")] * 2,
            "eve": b"x",
            "ser": TriageError("too large", "response_too_large", reachable=True),
        })
        result = run(client)
        self.assertTrue(result.success)
        self.assertFalse(result.run_row["ok"])
        self.assertEqual(result.run_row["error_category"], "response_too_large")
        self.assertNotIn("ser.txt", result.raw)

    def test_login_failure_is_recorded_without_retry(self):
        client = FakeClient("SEL-700GT", {}, login_error=TriageError("bad", "authentication_failed", reachable=True))
        result = run(client)
        self.assertFalse(result.success)
        self.assertEqual(result.run_row["error_category"], "authentication_failed")
        self.assertTrue(result.run_row["reachable"])
        self.assertEqual([c for c in client.calls if c == ("login",)], [("login",)])

    def test_unreachable_device(self):
        def factory(target):
            raise TriageError("connect failed", "connection_failed", reachable=False)

        result = sweep_device(item(), DevicePrior(), secret_provider=FakeSecrets(),
                              client_factory=factory, settings=SETTINGS, clock=lambda: NOW)
        self.assertFalse(result.run_row["reachable"])
        self.assertEqual(result.run_row["error_category"], "connection_failed")


class TestReportFormats(unittest.TestCase):
    def test_651ra_reports_are_fetched_with_cev(self):
        cev = (FIXTURES / "events" / "sel651r2_event_10259_raw.cev").read_bytes()
        his = fixture("651r2-history.txt")
        client = FakeClient("SEL-651RA", {"history": [his, his], "cev": cev, "ser": b"SER\r\n=>"})
        result = run(client)
        self.assertTrue(any(call[0] == "cev" for call in client.calls))
        self.assertFalse(any(call[0] == "eve" for call in client.calls))
        self.assertTrue(result.report_rows)
        self.assertTrue(all(r["format"] == "cev" and r["raw_name"].endswith(".cev") for r in result.report_rows))

    def test_a_rejected_report_command_archives_nothing(self):
        his = fixture("651r2-history.txt")
        client = FakeClient("SEL-651R2", {"history": [his, his], "eve": b"EVE 40\r\n\r\nInvalid Command\r\n=>",
                                          "ser": b"SER\r\n=>"})
        result = run(client)
        self.assertEqual(result.report_rows, [])
        self.assertIn("report_command_rejected", result.run_row["warnings"])
        self.assertEqual(sum(1 for call in client.calls if call[0] == "eve"), 1)  # stops after the first refusal
