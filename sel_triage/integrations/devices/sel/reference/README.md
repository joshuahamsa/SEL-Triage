# SEL ASCII command reference (per model, per firmware)

`commands/<MODEL>.json` lists, for each supported model, the ASCII commands from the
command summary in that model's SEL instruction manual and the firmware revision history
(revision, FID, date). Load it with
`sel_triage.integrations.devices.sel.reference.load_reference()`; `sel-settings index` puts it
in the settings index (`manual_commands`, `manual_firmware`, `device_command_reference`).

## What is and is not included

Each command row keeps the facts needed to reason about safety: the command token, the
minimum and allowed access levels, the prompt, a `kind` (`read`, `write`, `session`,
`other`) and the manual page it came from. Firmware rows keep the revision, FID, date and the
number of change notes on that page.

The manuals' own wording is **not** included: command descriptions and firmware change
notes are left out because SEL instruction manuals are copyrighted and distributed only
through an SEL account. The manuals themselves are never redistributed.

To build a full local reference with descriptions from your own manual copies, use the
extraction scripts in `scripts/sel_manuals/`:

```bash
python -I scripts/sel_manuals/extract.py <folder of manual PDFs> <output folder>
python -I scripts/sel_manuals/verify.py <folder of manual PDFs> <output folder>
```

`extract.py` needs PyMuPDF. Its `MANUALS` table lists each manual's file name, date code and
page ranges; `verify.py` checks every extracted row against the cited page. Keep the output
of a local build out of source control.

## Schema

```json
{
  "model": "SEL-751",
  "manual_date": "2025-02-14",
  "command_table": "SEL-751 Relay Command Summary (end of manual, English column)",
  "access_level_hierarchy": ["0", "1", "2", "C"],
  "commands": [
    {"command": "ID", "min_access_level": "0", "access_levels": ["0", "1", "2"],
     "prompt": null, "kind": "read", "page": 1171}
  ],
  "firmware": [
    {"revision": "R402", "fid": "SEL-751-R402-V0-Z102100-D20241231", "date": "2024-12-31",
     "manual_date_code": "20241231", "page": 762, "command_changes": [], "n_change_bullets": 24}
  ]
}
```

`kind` comes from rules in the extractor (the command keyword and the description verb), not
from the manual. The live clients never use this file to decide what to send: the command
allowlists in `sel_triage.integrations.devices.sel.commands` are fixed in code and covered by
the public-safety tests.
