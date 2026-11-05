# SEL event archive

`sel-event-sweep` keeps SEL relay and meter event history (HIS, SER and event
reports) before it rolls off the device. It runs wherever the devices are
reachable and writes to a local folder or an S3 bucket.

## Storage: S3 or local

`selEventArchive.store` chooses where sweeps go:
- **`s3`:** needs `bucket`; optional `profile` picks the AWS profile.
- **`local`:** the same layout under `localDir`, default
  `~/Library/Application Support/sel-triage/sel-events`. No AWS is needed. This is
  the default when no bucket is configured.

The local store keeps its own sweep state (`<localDir>/state.sqlite`), so switching stores
never skips a device. Everything below applies to both; with `local`, the AWS preflight is
skipped. `--name "<site>/<label>"` sweeps one device, `--site` the devices at a site.

## Setup

1. Add a `selEventArchive` section to `config.local.json` (see
   `config.example.json`): `bucket`, `prefix`, optional `profile`.
2. Check that your AWS credentials can write to `<bucket>/<prefix>/`.
3. Run once by hand for one site, then the fleet:
   ```bash
   .venv/bin/python -m sel_triage sel-event-sweep --site "<site>"
   .venv/bin/python -m sel_triage sel-event-sweep
   ```
4. Install the daily agent (from the main checkout, so the agent's working
   directory and config path are stable):
   ```bash
   .venv/bin/python -m sel_triage sel-event-sweep install-agent --config "$PWD/config.local.json" --hour 7
   ```
   Logs: `~/Library/Logs/sel-triage/sel-event-sweep.log`.
   Remove it with `sel-event-sweep uninstall-agent`.

## What a sweep does

- **Preflight.** If the S3 bucket is not reachable with your AWS credentials,
  it exits 0 and does nothing. It never opens or manages a VPN: reaching the
  devices is up to you.
  After `staleNotifyDays` without a successful sweep, it posts a macOS
  notification on each skip.
- **Per device (Access Level 1, read-only).** It reads `HIS`, then `SER`.
  For families in `eventReportFamilies` it then fetches `EVE n` for events not
  yet archived, oldest first, up to `eventsPerRun`, and reads `HIS` again; if
  HIS changed in between, it drops those reports for this run. A failed report
  read ends report fetching for that device until the next sweep; HIS and SER
  are already saved.
- **Ordering.** Devices that have gone longest without success go first.
  Sites run in parallel, and devices at one site run one at a time. After
  `unreachableStopAfter` consecutive unreachable devices at different sites,
  it re-checks the network hook and stops only if that reports the network down
  (the CLI's hook always reports up; library callers can supply their own).
- **Upload.** Raw text goes to `<prefix>/raw/<device_key>/<run_id>/`. Rows go
  to `<prefix>/normalized/<run_id>/*.jsonl`, with `runs.jsonl` written last
  as the commit marker. Local state
  (`~/Library/Application Support/sel-triage/sel-events.sqlite`) is updated
  only after that.

## SER rows

SER is parsed for every family (`parsers.common.parse_ser_table`; the 700G keeps its own
parser), built from live captures of the 351/351A/351S, 651R-2, 651RA, 735, 751/751A
and 851. Each row is `device_ts`, `element` and `state`.

Message rows that carry no state are kept as the message text with state `Event`. In the
parsed records they also get an `event` category:
- **Power:** `power_loss`, `power_restored`, `powered_up`, `restarted`, `sleep`.
- **Configuration:** `settings_changed`, `time_changed`.
- **Status:** `enabled`, `disabled`, `breaker_open`, `breaker_closed`, `control_local`,
  `control_remote`.
- **Other:** `archive_cleared`, `group_change`, `other`.

Examples are "Power loss", "Relay Settings Changed", "Going to sleep" and "Time changed by
ASCII +07226.0s". They are the cheapest evidence of outages, setting edits and clock
changes on a device.

## Breaker wear (`breaker.jsonl`, `sel-breaker-trend`)

On families with a breaker monitor command (351 family, 700G, 751; the 651, 735 and 851
have none) the sweep reads `BRE` last, after SER and the event reports. It saves `bre.txt`
and writes one row per device per run to `breaker.jsonl` (additive, like
`event_reports.jsonl`):
- **Wear:** `breaker_wear_percent` (the worst phase) and `wear_percent` per phase.
- **Counts:** `operation_count`, `relay_trip_count`, `external_trip_count`.
- **State:** `last_reset`, `monitor_enabled`.
- **Everything else** from the family's parser under `details`: accumulated interrupted
  kA, electrical and mechanical operating times, and the minimum DC voltage at the last
  operation.

`sel-event-reparse` re-reads archived `bre.txt` when `BREAKER_PARSER_VERSION` is bumped.

`sel-breaker-trend [--name|--site] [--min-days 7] [--horizon-days 365] [--render]` reads
those rows (offline) and reports, per breaker:
- the latest wear and operation count;
- the wear and operation rates per year since the last counter reset;
- the projected date the wear reaches the alarm threshold.

Its findings are `wear_over_threshold`, `wear_reaches_threshold_soon`,
`operations_over_threshold`, `counters_reset`, `monitor_disabled` and `insufficient_history`.
Thresholds are `diagnosticThresholds.breaker_wear_percent` and `breaker_operation_count`
(default 80 % and 5000, overridable by model, site or device). A rate needs two readings at
least `--min-days` apart, so the trend fills in as the sweep runs (the daily agent gives one
reading a day).

## Event report summaries (`event_reports.jsonl`)

Each fetched `EVE n` report is parsed by the vendored event-report package
(`integrations/devices/sel/eventreport/`, the same parser as `sel-visualize`) into one
row in `<prefix>/normalized/<run_id>/event_reports.jsonl`:

- **Identity and links:** `device_key`, `device_ts`, `s3_key` (the raw report), `sha256`,
  `report_parser_version`.
- **The event:** `event_number`, `event_time`, `time_source`, `event_type` (e.g.
  `CAG T`), `location` (null when the relay printed `$$$$$$$`), `shot`, `targets`, `fid`.
- **Currents:** `reported_currents` (A/B/C/G/Q primary amps).
- **Sampling and signals:** `nominal_frequency_hz`, `samples_per_cycle`, `sample_count`,
  `analog_channels`, `digital_signal_count`, `digital_transition_count`, `warnings`.

A report that does not parse is still a row (`report_parse = "parse_failed"` with
`report_error`), and it never stops the sweep. The file is additive: a consumer that reads
only `runs`, `ser`, `history` and `reports` ignores it.

`sel-event-reparse` also summarizes archived reports with no summary at the current
`REPORT_PARSER_VERSION` (`sel_archive/records.py`), so a parser improvement or older
archived runs are backfilled. Bump that version when the summary changes. To render one
report for a person: download its `s3_key` and run `sel-visualize` on it.

## Reading the results

- `ser_gap` / `his_gap` true on a run row: records rolled off between sweeps.
  Sweep that device more often.
- `ser_parse` / `his_parse = no_parser`: raw text is archived but no rows yet.
  Add a parser (`add-sel-model-support`), bump the family in
  `sel_archive/records.py:PARSER_VERSIONS`, then run
  `sel-event-reparse --family <family>`.
- `clock_offset_s`: relay-local clock minus UTC (includes the site's UTC
  offset). `device_ts` is never converted.

The SEL-751A HIS layout without `REF`/`LOCAT` is parsed from sel751 parser
version 3 (earlier versions stored no 751A history rows). After deploying it,
run `sel-event-reparse --family sel751` to fill rows for raw text already archived.

## Adding event reports for another family

`EVE n` numbering is verified only on the 651 and 700G families. To enable
another family, read `HIS` and `EVE <n>` by hand on one device. If the
report's trigger time matches HIS entry `n`, add the family to
`eventReportFamilies`.
