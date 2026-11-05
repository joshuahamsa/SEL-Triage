# sel-triage

Read-only triage tools for SEL protective relays, meters and RTACs. SEL's own software
(ACSELERATOR QuickSet) runs only on Windows; `sel-triage` covers the read-side jobs from a
Mac terminal: identify a device, take a status snapshot, pull event history and reports, capture complete settings, check and diff those settings, pack them
into QuickSet `.rdb` databases, and turn event reports into interactive offline waveform
reports.

> **Not affiliated with Schweitzer Engineering Laboratories, Inc.** SEL, ACSELERATOR and
> QuickSet are trademarks of their owner. This project only talks to devices through their
> documented ASCII and web interfaces.

## Safety first

`sel-triage` is **read-only by construction**:

- Device sessions stop at **Access Level 1**. The clients have no API that sends free text:
  every command comes from a fixed allowlist of read commands, with byte and time limits.
  `2AC`, `SET`, `OPEN`, `CLOSE`, `RESET`, `CLEAR`, `TEST`, `TRIGGER` and any file write or
  delete are rejected, and the public-safety tests (`tests/test_*public_safety*.py`) fail the
  build if one could ever be sent.
- A failed login is **never retried**, so a wrong password cannot lock out a port.
- Passwords come from the **macOS Keychain** only. They are never read from the config,
  the command line or the environment, never printed, and redacted from saved evidence.
- `sel-triage` never opens, prompts for or manages a VPN. SEL Telnet is plaintext; use it
  only on a trusted plant network or VPN that you connect yourself.
- RTAC tools send only `GET` requests to an allowlist (REST API) or read-only report pages
  (web interface), then log out. Every RTAC login appears in the RTAC's own SOE.

Read [docs/sel-live-verification.md](docs/sel-live-verification.md) before pointing any
command at a device for the first time.

## Supported devices

| Model family | Identity, status, meter | HIS / SER | Event reports (EVE/CEV) | Breaker | Settings capture |
|---|---|---|---|---|---|
| SEL-351 / 351A / 351S | yes | yes | no | yes | `FILE READ` |
| SEL-651 / 651RA / 651R-2 | yes | yes | yes | — | `FILE READ` |
| SEL-700G / 700GT | yes | yes | yes (fixtures; pending live validation) | yes | `FILE READ`, plus `SHO` in snapshots |
| SEL-735 meter | yes | yes | no | — | `FILE SHOW` |
| SEL-751 / 751A | yes | yes | no | yes | `FILE READ` |
| SEL-851 | yes | yes | no | — | `FILE READ` |

SEL-3505 RTAC: the web snapshot reads SOE, alarms, diagnostics and connected IEDs; the REST
API snapshot reads identity, status, alarms, IED connections and, optionally, tags.

Known limitations:

- SEL-700G/700GT normalized field labels come from synthetic fixtures and are pending live
  validation; treat them as best-effort.
- SEL-751/751A event collection returns HIS and SER only (no EVE/CEV recipe yet).
- The live verification gate covers event-report collection on the SEL-651 only
  (651/651RA/651R-2). The SEL-700G event path is implemented and tested against fixtures,
  and is pending live validation.
- The event visualizer runs offline on retrieved files; snapshots and event collection never
  invoke it.
- Unsupported models and capabilities fail conservatively, and a configured model hint
  never overrides the model the device reports in `ID`.

## Install

Python 3.11 or newer. The core has no third-party dependencies. The live commands read
passwords from the macOS Keychain, so they run on macOS; the offline commands (visualizer,
settings checks and diffs, `.rdb` tools) run anywhere Python does.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .              # core
.venv/bin/pip install -e ".[rdb]"       # + .rdb packing and reading (olefile)
.venv/bin/pip install -e ".[s3]"        # + S3 event archive (boto3)
```

Run it as `sel-triage <command>` or `.venv/bin/python -m sel_triage <command>`.

## Configure

1. Copy `config.example.json` to `config.local.json` (git-ignored) and replace the example
   devices with yours. Device names are `<site>/<label>`; `--site` filters match the part
   before the slash. Never put a password in the file.
2. Store each Access Level 1 password in the Keychain under the service `sel-triage`, with the
   device's `credentialRef` as the account. Use the interactive form so the password never
   appears in your shell history:

   ```bash
   security add-generic-password -U -s sel-triage -a <credential-ref> -w
   ```

   RTAC logins use the Keychain service `rtac/<site>`, with the username as the account.
3. Optional: thresholds for the diagnostics (`diagnosticThresholds`, with `byModel`, `bySite`
   and `byDevice` overrides), settings checks (`selSettingsChecks`), capture folders
   (`selSettings`) and the event archive (`selEventArchive`). `config.example.json` shows
   every key.

Commands read `config.local.json` when it exists, else `config.json`; `--config` overrides.

## Commands

Every command prints a JSON result (`tool`, `ran_at`, `ok`, …, `errors`); `--render` prints a
readable summary instead.

**Live, read-only (contacts a device)**

| Command | What it does |
|---|---|
| `sel-snapshot --name <device>` | identity, status, targets, meter and breaker data, with diagnostics; `--include-events` adds event collection, `--include-settings` adds `SHO` (SEL-700G) |
| `sel-collect-events --name <device>` | newest event reports (`--event-count`, at most 10) or one (`--event-number`), plus HIS and SER |
| `sel-settings-capture --name/--site/--all` | complete settings by `FILE READ` (`FILE SHOW` on the SEL-735), saved by device and time |
| `sel-event-sweep` | archive HIS, SER and new event reports for every configured device to a local folder or S3; `install-agent` schedules it daily on macOS |
| `rtac-snapshot --name <rtac>` | RTAC web interface: SOE, alarms, diagnostics, connected IEDs |
| `rtac-api-snapshot --name <rtac>` | RTAC REST API: identity, status, alarms, IED connections, optional tags |

**Offline (no device contact)**

| Command | What it does |
|---|---|
| `sel-visualize <files or folders> --output-dir DIR` | interactive HTML waveforms, digital states and phasors from `.eve` / `.cev` files, plus CSV and JSON |
| `sel-inventory <captures>` | one row per device: model, firmware, capture age |
| `sel-settings check \| rules \| diff \| index` | rule checks on saved settings, the rule list, diffs between captures, and a SQLite index for queries across devices |
| `sel-rdb pack \| pack-all \| read` | build QuickSet `.rdb` databases from captures, or read one back |
| `sel-breaker-trend` | breaker wear and operation rates over time from archived readings |
| `sel-event-reparse` | re-parse archived HIS and SER with the current parsers |

Run `sel-triage <command> --help` for every option.

## Documentation

- [docs/sel-live-verification.md](docs/sel-live-verification.md): the manual gate before
  using a new device or model live
- [docs/sel-settings-capture.md](docs/sel-settings-capture.md): settings capture, the
  SQLite index and `.rdb` packing
- [docs/sel-event-archive.md](docs/sel-event-archive.md): the event archive and breaker trends
- [sel_triage/integrations/devices/sel/reference/README.md](sel_triage/integrations/devices/sel/reference/README.md):
  the per-model command reference

## Evidence and data handling

Live commands save what they read as evidence in private user data, in an owner-only
directory (`~/Library/Application Support/sel-triage/evidence` on macOS); `--evidence-root`
overrides it, and a repository-local `evidence/` folder is git-ignored. Results reference
evidence by relative path, size, media type and SHA-256 digest. Text evidence is redacted
before it is hashed and written.

Test fixtures are synthetic or anonymized: site names, device names, serial numbers and IP
addresses are replaced, and every address uses the documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24). `tests/test_repo_public_data.py` enforces this across the
repository. To guard your own names too, list them one per line in `.denylist.local`
(git-ignored) and the test fails if any appears in a tracked file.

## Tests

```bash
.venv/bin/pip install -e ".[rdb]"
.venv/bin/python -m pytest -q          # or: python -m unittest discover -s tests
```

The suite uses fakes and fixtures only; it never contacts a device or reads the real
Keychain. A passing run is not evidence of compatibility with a live device.

## License

MIT. See [LICENSE](LICENSE).
