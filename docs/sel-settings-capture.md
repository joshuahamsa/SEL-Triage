# SEL settings capture (live, read-only)

`sel-settings-capture` reads a relay's or meter's **complete** settings, as
ACSELERATOR QuickSet's "Read" does, and saves them where the offline tools
(`sel-inventory`, `sel-settings check|diff`) read them. It is a port of SEL-Audit's
`cli_read_settings.py` / `cli_audit_rdb.py` capture.

`SHO` (what `sel-snapshot` shows) is only a summary: a relay hides every setting of a
disabled function, so `SHO` yields roughly a fifth of the settings database.
`FILE READ` copies the stored streams byte for byte.

## Usage

```bash
.venv/bin/python -m sel_triage sel-settings-capture --name "<site>/<label>" --render
.venv/bin/python -m sel_triage sel-settings-capture --site "<site>" --render
.venv/bin/python -m sel_triage sel-settings-capture --all --max-age-days 30 --render
.venv/bin/python -m sel_triage sel-settings check "<captures folder>" --render
```

| Option | Meaning |
|---|---|
| `--name` / `--site` / `--all` | one configured SEL device, every SEL device whose site contains the text, or all of them |
| `--out DIR` | captures folder; default `selSettings.capturesDir`, else `~/Library/Application Support/sel-triage/sel-settings`. SEL-Audit's `Reads` folder works too |
| `--max-age-days N` | skip a device whose newest capture is `ok` and newer than N days (SEL-Audit's `--reuse-captures`) |
| `--max-sites-parallel N` | sites read at once (default 4); devices within a site run one at a time |
| `--pause S` | seconds between transfers (default 0.3) |
| `--block-timeout S` | per-block XMODEM timeout (default 10) |

Config (`config.local.json`): `selSettings.capturesDir`, `maxSitesParallel`,
`unreachableStopAfter` (default 3), `readTimeoutSeconds` (default 60).

## What it sends

Per device, over the device's Telnet / terminal-server port:

1. `ACC` + the Access Level 1 password from the Keychain (`credentialRef`), then `ID`.
   This is the same `SelClient` login as `sel-snapshot`, including the terminal-server
   wake. One login per device per run, never retried.
2. `FILE READ CFG.TXT`, which gives the class list `[CLASSES]`.
3. `FILE READ set_<class>.txt` for every class, then `FILE READ SET_HMI.TXT` (relays
   only; it is not listed in `CFG.TXT`). A bare return follows each `FILE READ`: when a
   device never starts a transfer, the receiver's `C` invitations stay typed on its
   command line and would otherwise prefix the next command (seen live as `CHLP`).
4. `HELP` last, on the 700G, 751/751A and 851 only (the 351, 651 and 735 manuals list no
   help command). It is the firmware's advertised Access Level 1 list; the 751 notes that
   privileged commands are left out, so the manual reference below is the complete list.

Nothing else is sent:
- The command policy accepts only `CFG.TXT` and `SET_<class>.TXT` as file names.
- The XMODEM side sends only `C`, `ACK` and `NAK`.

Access Level 1 cannot change settings, and `FILE READ` only copies *from* the device.
`tests/test_sel_settings_capture_public_safety.py` and `tests/test_sel_commands.py`
enforce both.

**SEL-735 meters** use `FILE SHOW <file>` instead. The 735 accepts `FILE READ`, but
its XMODEM sender aborts within tens of milliseconds when the receiver's `C` has not
arrived, which a VPN round trip cannot meet. `FILE SHOW` prints the same file as
framed text. The choice follows the model the device reports at login.

**Telnet vs raw ports.** A Telnet endpoint escapes `0xFF` data bytes as `IAC IAC`
during the binary transfer; a raw terminal-server port does not. The transport
undoes the escaping only when the endpoint negotiated Telnet options. This replaces
SEL-Audit's `--telnet-binary auto`.

## Output

```
<captures>/<site>/<host>_<port>/<YYYYMMDDTHHMMSSZ>/
    ID.txt  CFG.TXT  set_<class>.txt ...  SET_HMI.TXT  HELP.txt
    transcript.txt   # login + ID exchange, password redacted
    manifest.json    # method, model, FID, classes, SHA-256 and size per file, skipped streams
    ERROR.txt        # instead of the streams when the capture failed (error type and category)
```

This is SEL-Audit's `Reads` layout, so `discover_devices` treats both the same.
- A stream that will not transfer is skipped and listed in `manifest.json` and the
  result, as SEL-Audit did.
- A missing `CFG.TXT` fails the capture.

## SQLite index (fleet queries)

The capture folders are the source of truth. `sel-settings index` derives a SQLite
database from them, and every `sel-settings-capture` run updates it afterwards
(`--no-index` skips this).
- **Default location:** `selSettings.indexPath`, else
  `~/Library/Application Support/sel-triage/sel-settings.sqlite`.
- **Incremental:** unchanged runs are skipped, changed runs are re-read, and runs whose
  folder is gone are dropped. `--rebuild` re-reads everything.
- **Several roots, one database:** index SEL-Audit's `Reads` into the same database and
  each device's history spans both.
- **Device names:** devices are named from the inventory (`devices.json` and config) by
  address. A schema change resets the database (it is derived); re-index each folder
  afterwards.

```bash
.venv/bin/python -m sel_triage sel-settings index                       # the captures folder
.venv/bin/python -m sel_triage sel-settings index <SEL-Audit>/Reads     # add the SEL-Audit corpus
sqlite3 ~/Library/Application\ Support/sel-triage/sel-settings.sqlite
```

| Table / view | Rows |
|---|---|
| `captures` | one per capture run: `device` (the inventory name when the capture's `<host>_<port>` matches a configured SEL device, else the folder key), `device_site`, `device_key` (the folder's `<site>/<host>_<port>`, kept for provenance), `captured_at`, `status` (`ok`, `identity_only`, `failed`), `method`, `model`, `fid`, `firmware_revision`, `firmware_date`, `part_number`, `serial_number`, `device_id`, `error`, `setting_count`, `root`, `path` |
| `settings` | one per setting: `capture_id`, `class` (`1`, `G`, `L1`, `P1`, ...), `key`, `value`. Password-like values are redacted as in the offline tools |
| `latest_captures` | newest `ok` capture per `device`; a newer failed run never hides it, and captures filed under different site spellings (SEL-Audit vs the inventory) form one history |
| `latest_settings` | the settings of `latest_captures` |

| `device_commands` / `latest_commands` | the device's `HELP` list (`help_status` on `captures`: `ok`, `rejected`, `empty`) |
| `manual_commands` | the SEL manual command summaries packaged in `sel_triage/integrations/devices/sel/reference/` (newest manual per model): `model`, `verb`, `command` (with argument forms), `min_access_level`, `access_levels`, `kind` (`read`, `write`, `session`, `other`), `description` |
| `manual_firmware` | each manual's firmware revision history: `revision`, `fid`, `date`, `command_changes` |
| `device_command_reference` | each device's latest capture joined to its model's manual commands |
| `device_firmware_reference` | each device's firmware vs the manual: `manual_latest_revision`, `fid_in_manual` (0 = firmware newer than the manual on file) |

The reference covers SEL-351/351A/351S, 651R/651R-2/651RA, 700G, 735, 751/751A and 851
(see its README for manuals, dates and caveats; the 351/351S editions are old).
`tests/test_sel_reference.py` checks that every command sel-triage can send is a read
in every manual. Note that Access Level 1 is not purely read-only: `MET RD/RE/RM/RP`,
`HIS C/R` and `SER C` reset stored data at Level 1; sel-triage never sends them.

Example queries:

```sql
-- firmware spread by model
SELECT model, firmware_revision, COUNT(*) FROM latest_captures GROUP BY 1, 2 ORDER BY 1, 3 DESC;
-- every relay's group-1 CT ratio
SELECT device, value FROM latest_settings WHERE class = '1' AND key = 'CTR' ORDER BY device_key;
-- devices with SNTP off
SELECT device FROM latest_settings WHERE key IN ('ESNTP', 'Time.SNTPEnable') AND value IN ('OFF', 'N');
-- devices whose firmware is newer than the manual on file
SELECT device, fid, manual_latest_revision FROM device_firmware_reference WHERE NOT fid_in_manual;
-- every Level 1 write command a given device's manual lists
SELECT DISTINCT command, description FROM device_command_reference
WHERE device = '<site>/<label>' AND kind = 'write' AND min_access_level = '1';
-- what changed on a device between its last two captures: sel-settings diff <device folder>
```

## .rdb relay databases (`sel-rdb`)

These are local files only and need the `[rdb]` extra (`olefile`) to read an existing `.rdb`.
The code is ported from SEL-Audit's `rdb_pack`/`ole_writer` and the Lowes `extract.py`.

```bash
.venv/bin/python -m sel_triage sel-rdb pack "<captures>/<site>/<host>_<port>/<stamp>" [--template X.rdb]
.venv/bin/python -m sel_triage sel-rdb pack-all [--templates DIR] [--out DIR]
.venv/bin/python -m sel_triage sel-rdb read X.rdb [--as-capture DIR] [--extract DIR] [--settings]
```

- **`pack`, subset mode:** packs exactly what the relay returned. It opens in QuickSet,
  but only with the settings that apply to that unit.
- **`--template`:** overlays the captured values onto a full-schema QuickSet export of the
  same firmware ID, giving a QuickSet-shaped database.
- **`pack-all`:** does this for the newest good capture of every device, into
  `<out>/<site>/<label>.rdb` (default `~/Library/Application Support/sel-triage/sel-rdb`).
  The label is the inventory name. `<FID>.rdb` files in `--templates` are used where the
  firmware ID matches.
- **`read`:** lists relays, firmware IDs, classes and setting counts. `--as-capture` writes
  a relay as a capture folder, so `sel-settings diff <that folder> <a live capture>` shows
  what differs between a QuickSet database and the relay.

## Sweep behaviour

- **Preflight.** If the network hook reports the device network down, nothing is
  contacted and the result says `network_unreachable`. It never opens or manages a
  VPN; the CLI assumes the devices are reachable.
- **Stopping.** When consecutive unreachable devices span `unreachableStopAfter`
  sites, it re-checks the network hook and stops if it reports the network down
  (`stopped_early`). This is the same guard as `sel-event-sweep`.
- **Duplicates.** A device listed twice in the inventory at one address gets one login;
  the duplicates are reported (`duplicate_endpoints`).
- **Exit status.** 0 when every attempted device captured, 2 otherwise. `failures`
  lists each device with its error category and capture folder.

## Not ported (on purpose)

- `SHO` to INI conversion is superseded by `FILE READ`.
- The Streamlit GUI, `probe_meter.py` and `upload_rdbs.py` (writes to an external
  system) are left out.
- The `relayConnectionsV2.csv` inventory is replaced by the `devices` list in the
  config (or a `devices.json` next to it).
- The `--password` flag is gone; the password comes from the Keychain.

## Live validation (2026-10-12)

Two devices behind one terminal server, one login each:

| Device | Path | Result |
|---|---|---|
| SEL-751 relay | `FILE READ` (XMODEM) | 20 settings streams + `CFG.TXT`; every stream **byte-identical** (SHA-256) to SEL-Audit's 2026-05-19 capture of the same relay; `sel-settings diff` 0 changes; `SET_HMI.TXT` not offered (SEL-Audit got none either) |
| SEL-735 meter | `FILE SHOW` | first capture of this meter: 12 classes, 1199 settings, 0 unparsed lines |

`sel-settings check` on the two captures flagged a site-level phase-rotation mismatch
(relay `ACB`, meter `ABC`), free-running clocks (SNTP off) on both, and different UTC
offsets: the kind of finding the capture exists to feed.
