"""SER parsing for every SEL family, against anonymized live captures (tests/fixtures/sel/ser)."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.adapters import adapter_for
from sel_triage.integrations.devices.sel.parsers.common import parse_ser_table

SER = Path(__file__).parent / "fixtures" / "sel" / "ser"
FIXTURE_MODELS = {
    "351-5": "SEL-351", "351a": "SEL-351A", "351s-7": "SEL-351S", "651r2": "SEL-651R2", "651ra": "SEL-651RA",
    "735": "SEL-735", "751": "SEL-751", "751a": "SEL-751A", "851": "SEL-851",
}


def text(name):
    return (SER / "{0}-ser.txt".format(name)).read_text()


class TestParseSerTable(unittest.TestCase):
    def test_every_capture_parses_every_row(self):
        for name in FIXTURE_MODELS:
            with self.subTest(fixture=name):
                result = parse_ser_table(text(name))
                body = [line for line in text(name).splitlines() if line.strip()[:1].isdigit() and "/" in line]
                self.assertEqual(len(result["records"]), len(body))
                leftover = [l for l in result["unparsed_lines"] if not l.startswith("ANONYMIZED CAPTURE")]
                self.assertEqual(leftover, [], leftover[:3])
                self.assertTrue(result["clock"])

    def test_two_digit_years_and_numbering(self):
        result = parse_ser_table(text("351-5"))
        newest = result["records"][-1]
        self.assertEqual(newest["number"], 1)
        self.assertTrue(newest["timestamp"].startswith("2026-10-11T12:54:33"))
        self.assertEqual((newest["element"], newest["state"]), ("50Q1", "Deasserted"))
        self.assertEqual(result["records"][0]["number"], 1024)

    def test_four_digit_years_with_leading_spaces(self):
        record = parse_ser_table(text("651r2"))["records"][-1]
        self.assertTrue(record["timestamp"].startswith("2026-08-06T08:22:07"))
        self.assertEqual((record["element"], record["state"]), ("51P", "Deasserted"))

    def test_message_rows_are_classified_events(self):
        rows = parse_ser_table(text("735"))["records"]
        power = [r for r in rows if r["event"] == "power_loss"]
        self.assertTrue(power)
        self.assertEqual((power[0]["element"], power[0]["state"]), ("Power loss", "Event"))
        self.assertIn("power_restored", {r["event"] for r in rows})
        self.assertIn("settings_changed", {r["event"] for r in rows})
        self.assertIn("settings_changed", {r["event"] for r in parse_ser_table(text("751"))["records"]})
        events_651 = {r["event"] for r in parse_ser_table(text("651r2"))["records"]}
        self.assertTrue({"sleep", "restarted"} <= events_651, events_651)
        events_851 = {r["event"] for r in parse_ser_table(text("851"))["records"]}
        self.assertTrue({"powered_up", "enabled", "archive_cleared"} <= events_851, events_851)

    def test_event_categories(self):
        from sel_triage.integrations.devices.sel.parsers.common import ser_event_category as cat

        for message, expected in (("Time changed by ASCII +07226.0s", "time_changed"),
                                  ("BREAKER CLOSED", "breaker_closed"), ("BREAKER OPEN", "breaker_open"),
                                  ("CONTROL LOCAL", "control_local"), ("CONTROL REMOTE", "control_remote"),
                                  ("Relay Disabled", "disabled"), ("Relay newly powered up", "powered_up"),
                                  ("Relay Settings Changed", "settings_changed"), ("Something new", "other")):
            with self.subTest(message=message):
                self.assertEqual(cat(message), expected)

    def test_pickup_dropout_and_dotted_elements(self):
        rows_751 = parse_ser_table(text("751"))["records"]
        self.assertIn(("FP_CLOSE", "PICKUP"), {(r["element"], r["state"]) for r in rows_751})
        rows_851 = parse_ser_table(text("851"))["records"]
        self.assertIn(("Trip_01.Unlt", "Asserted"), {(r["element"], r["state"]) for r in rows_851})
        self.assertIsNone(next(r for r in rows_851 if r["element"] == "Trip_01.Unlt")["event"])

    def test_element_summary_counts_every_state(self):
        summary = parse_ser_table(text("751"))["element_summary"]
        self.assertGreaterEqual(summary["FP_CLOSE"]["pickup"], 1)
        self.assertIn("asserted", summary["IN101"])

    def test_no_table_means_no_records(self):
        result = parse_ser_table("SER\r\n\r\nInvalid Command\r\n=>")
        self.assertEqual(result["records"], [])


class TestSynthetic751Ser(unittest.TestCase):
    """The R300-V1 SEL-751 layout (synthetic values): newest = 1, stateless rows, PICKUP/DROPOUT."""

    def setUp(self):
        self.result = parse_ser_table(text("751-synthetic"))

    def test_records_run_oldest_first_and_newest_is_number_one(self):
        records = self.result["records"]
        self.assertEqual([r["number"] for r in records], list(range(12, 0, -1)))
        self.assertEqual(records[-1]["timestamp"], "2026-10-05T16:34:40.625")
        self.assertEqual((records[-1]["element"], records[-1]["state"], records[-1]["event"]), ("52A", "Deasserted", None))
        leftover = [l for l in self.result["unparsed_lines"] if not l.startswith("SYNTHETIC CAPTURE")]
        self.assertEqual(leftover, [])

    def test_rows_without_a_state_are_categorized_events(self):
        messages = {(r["element"], r["state"], r["event"]) for r in self.result["records"] if r["event"]}
        self.assertEqual(messages, {
            ("Relay Powered Up", "Event", "powered_up"),
            ("Relay Settings Changed", "Event", "settings_changed"),
        })

    def test_element_summary_counts_every_state(self):
        summary = self.result["element_summary"]
        self.assertEqual(summary["52A"], {
            "asserted": 1, "deasserted": 1,
            "first": "2026-09-28T07:02:11.206", "last": "2026-10-05T16:34:40.625",
        })
        self.assertEqual((summary["FP_OPEN"]["pickup"], summary["FP_OPEN"]["dropout"]), (1, 1))
        self.assertEqual(summary["Relay Powered Up"]["event"], 1)


class TestAdaptersParseSer(unittest.TestCase):
    def test_every_family_adapter_parses_ser(self):
        for name, model in FIXTURE_MODELS.items():
            with self.subTest(model=model):
                adapter = adapter_for(model).adapter
                self.assertGreater(len(adapter.parse("ser", text(name))["records"]), 0)

    def test_ser_is_not_added_to_snapshot_capabilities(self):
        # snapshots run adapter.capabilities; SER stays a sweep/event-collection read
        for model in ("SEL-351", "SEL-735", "SEL-751", "SEL-851"):
            with self.subTest(model=model):
                self.assertNotIn("ser", adapter_for(model).adapter.capabilities)


if __name__ == "__main__":
    unittest.main()
