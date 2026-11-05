"""sel-breaker-trend math and archive reading (synthetic readings)."""

import unittest

from sel_triage.render import render
from sel_triage.sel_archive import records
from sel_triage.sel_archive.archive import MemoryArchive
from sel_triage.sel_archive.breaker_trend import run_trend, trend_device


def reading(day, wear, ops, last_reset="2024-01-01T00:00:00", enabled=True):
    return {"read_at": "2026-{0}T07:00:00Z".format(day), "bre_parse": "parsed", "breaker_wear_percent": wear,
            "operation_count": ops, "last_reset": last_reset, "monitor_enabled": enabled,
            "wear_percent": {"A": wear, "B": wear, "C": wear}, "breaker_parser_version": 1}


META = {"name": "Lab/Relay", "site": "Lab", "model": "SEL-351S"}


def codes(result):
    return [f["code"] for f in result["findings"]]


class TestTrendDevice(unittest.TestCase):
    def test_rates_and_projection(self):
        rows = [reading("01-01", 50.0, 1000), reading("07-02", 60.0, 1500)]
        result = trend_device("dev", rows, META, {})
        self.assertAlmostEqual(result["wear_rate_percent_per_year"], 20.055, places=2)
        self.assertGreater(result["operation_rate_per_year"], 1000)
        self.assertEqual(result["projected_threshold_date"][:4], "2027")  # 20 points at ~20 %/yr
        self.assertIn("wear_reaches_threshold_soon", codes(result))

    def test_over_thresholds_with_overrides(self):
        rows = [reading("01-01", 85.0, 6000), reading("03-01", 86.0, 6001)]
        self.assertIn("wear_over_threshold", codes(trend_device("dev", rows, META, {})))
        self.assertIn("operations_over_threshold", codes(trend_device("dev", rows, META, {})))
        relaxed = trend_device("dev", rows, META, {"breaker_wear_percent": 90, "breaker_operation_count": 10000})
        self.assertNotIn("wear_over_threshold", codes(relaxed))
        self.assertNotIn("operations_over_threshold", codes(relaxed))

    def test_reset_restarts_the_rate(self):
        rows = [reading("01-01", 70.0, 4000), reading("03-01", 2.0, 10, last_reset="2026-02-15T00:00:00"),
                reading("06-01", 5.0, 40, last_reset="2026-02-15T00:00:00")]
        result = trend_device("dev", rows, META, {})
        self.assertIn("counters_reset", codes(result))
        self.assertGreater(result["wear_rate_percent_per_year"], 0)  # from the post-reset readings only
        self.assertLess(result["wear_rate_percent_per_year"], 15)

    def test_short_history_and_disabled_monitor(self):
        self.assertIn("insufficient_history", codes(trend_device("dev", [reading("01-01", 10.0, 5)], META, {})))
        disabled = {"read_at": "2026-01-01T00:00:00Z", "bre_parse": "parsed", "monitor_enabled": False,
                    "breaker_wear_percent": None, "operation_count": None}
        result = trend_device("dev", [disabled], META, {})
        self.assertEqual(codes(result), ["monitor_disabled"])


class TestRunTrend(unittest.TestCase):
    def test_reads_committed_runs_and_filters(self):
        archive = MemoryArchive()
        for index, (run, wear) in enumerate((("20260101T070000Z-a", 40.0), ("20260601T070000Z-b", 45.0))):
            runs = [{"kind": "sweep", "device_key": "dev-1", "name": "Lab/Relay", "site": "Lab",
                     "observed_model": "SEL-351S"}]
            row = dict(reading(("01-01", "06-01")[index], wear, 100 + index), device_key="dev-1", seen_run=run)
            archive.put(records.normalized_key("p", run, "breaker.jsonl"), records.to_jsonl([row]), "t")
            archive.put(records.normalized_key("p", run, "runs.jsonl"), records.to_jsonl(runs), "t")
        # an uncommitted run (no runs.jsonl) is ignored
        archive.put(records.normalized_key("p", "20261001T070000Z-c", "breaker.jsonl"),
                    records.to_jsonl([dict(reading("10-01", 99.0, 999), device_key="dev-1", seen_run="x")]), "t")
        result = run_trend(archive, "p")
        (device,) = result["devices"]
        self.assertEqual((device["name"], device["readings"], device["wear_percent"]), ("Lab/Relay", 2, 45.0))
        self.assertGreater(device["wear_rate_percent_per_year"], 0)
        self.assertEqual(run_trend(archive, "p", site="Other")["devices"], [])
        self.assertIn("Lab/Relay", render(result))


if __name__ == "__main__":
    unittest.main()
