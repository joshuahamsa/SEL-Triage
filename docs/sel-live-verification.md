# Manual SEL live verification gate

This procedure is intentionally manual. Automated verification must use fakes,
fixtures, and example configuration only; it must not contact a relay or read
the real Keychain. A successful unit test run is not evidence of live model or
field compatibility.

## Safety boundary

Proceed only with written authorization for one supported test target and a
trusted VPN connected to the intended device network. Confirm the target name,
host, port, maintenance window, and owner before running anything. SEL Telnet
is plaintext and provides neither encryption nor server authentication; the
trusted VPN is a required compensating boundary, not an optional convenience.

This gate is read-only and Access Level 1 only. Do not enter Access Level 2, do
not use `2AC`, and do not issue control, settings, open, close, reset, clear,
test, or trigger commands. Stop if the observed identity does not match the
authorized target. The library's model hint is advisory; the `ID` response is
authoritative.

SEL-700G/700GT normalized field labels currently come from synthetic fixtures
and are pending live validation. SEL-751/751A is identity-only. Event
collection is supported for the SEL-651 family only. Do not broaden a test
because a lower-level command recipe happens to exist.

## 1. Prepare a private config and Keychain item

Copy `config.example.json` outside source control, replace its example network
values, and keep only the Access Level 1 credential reference in JSON. Never
put the secret in the file, an environment variable, a CLI option, or a shell
argument.

Create or update the Keychain item with this exact interactive form:

```bash
security add-generic-password -U -s sel-triage -a <credential-ref> -w
```

The final `-w` has no following value, so `security` prompts for the secret and
the secret is not placed in shell history or process arguments. Do not run this
documentation command literally: replace `<credential-ref>` with the exact
reference in the selected device entry. This project does not require a live
Keychain operation during automated verification.

Choose a new, distinctive sentinel string as the authorized test credential
when the device owner permits credential rotation. If rotation is not allowed,
treat the existing credential value as the sentinel for the final leak scan;
do not record or print it.

## 2. Confirm the gate before connecting

Record the following in the operator's approved ticket or runbook, not in this
repository:

- trusted VPN name and connected status;
- the single authorized device and expected model;
- confirmation that the credential grants Access Level 1 only;
- approved evidence and log directories with restrictive permissions;
- whether latest-one event retrieval is separately authorized.

Create a dedicated evidence root with owner-only permissions. The examples use
shell variables for non-secret paths and names only. If `--evidence-root` is
omitted, the CLI uses its owner-only `sel-triage/evidence` directory in
private user data; an explicitly approved root remains preferable for a live
verification record:

```bash
umask 077
export SEL_CONFIG=/approved/private/sel-triage.json
export SEL_EVIDENCE=/approved/private/sel-evidence
export SEL_TARGET='Authorized relay name'
mkdir -p "$SEL_EVIDENCE"
```

Do not store a password or sentinel in an environment variable.

## 3. Run one fast snapshot

Use the named target form:

```bash
python3 -m sel_triage sel-snapshot \
  --config "$SEL_CONFIG" \
  --name "$SEL_TARGET" \
  --evidence-root "$SEL_EVIDENCE"
```

For an authorized ad-hoc target, the current CLI instead requires all three
connection/credential options shown here; `--model-hint` remains optional:

```bash
python3 -m sel_triage sel-snapshot \
  --config "$SEL_CONFIG" \
  --host 192.0.2.10 \
  --port 2381 \
  --credential-ref sel/authorized-relay/access1 \
  --model-hint SEL-651R2 \
  --evidence-root "$SEL_EVIDENCE"
```

Do not add `--include-events` at this stage. Save the JSON output in the
approved log location if the runbook requires it. Confirm all of the following
before continuing:

1. The reported `identity.observed_model` and device ID match the authorized
   target. A `model_mismatch` warning requires stopping and resolving inventory.
2. Evidence paths are relative and stay beneath the selected evidence root.
3. Each text artifact and JSON output contains no credential or sentinel. A
   literal `[REDACTED]` marker may appear where text evidence was redacted.
4. Recompute each referenced SHA-256 digest with `shasum -a 256 <path>` and
   compare it to the JSON/manifest `sha256` value.
5. Review errors and unavailable capabilities conservatively. In particular,
   do not infer healthy state from a missing or unparsed field.
6. Verify clean logout: the result must contain no `logout_failed` error, the
   process must exit, and any approved session monitoring must show the Telnet
   connection closed. Logout closes the socket without sending another relay
   command.

Stop after identity when the observed family is SEL-751/751A. For
SEL-700G/700GT, compare every normalized label with the device's approved
reference because those fixture-derived labels are not yet live-validated.

## 4. Optionally retrieve the latest one event

Skip this section unless event retrieval is explicitly authorized and the
observed model is SEL-651, SEL-651RA, or SEL-651R2. The bounded latest one form
below makes both the request and the hard maximum one event and retains at most
100 newest SER rows:

```bash
python3 -m sel_triage sel-collect-events \
  --config "$SEL_CONFIG" \
  --name "$SEL_TARGET" \
  --event-count 1 \
  --event-format eve \
  --ser-limit 100 \
  --hard-event-limit 1 \
  --evidence-root "$SEL_EVIDENCE"
```

Confirm `selection.mode` is `latest`, `selection.count` and
`selection.hard_event_limit` are both `1`, the observed source identity still
matches, every artifact is referenced and hashed, and the connection closes
cleanly. Raw `.eve`, `.cev`, and `.ser` artifacts are sensitive and must remain
in the approved directory.

Do not visualize as part of collection. If a local visualization is separately
approved, run `sel-visualize` later on the explicit input files (offline, in-process):

```bash
python3 -m sel_triage sel-visualize /approved/private/event-1.eve \
  --output-dir /approved/private/reports
```

## 5. Scan for the sentinel and close the gate

Scan the evidence root and any captured stdout/stderr or operator logs. The
following helper prompts without echo and never places the sentinel in argv or
shell history. Pass only approved artifact/log roots as arguments:

```bash
python3 - "$SEL_EVIDENCE" /approved/private/sel-logs <<'PY'
import getpass
import pathlib
import sys

needle = getpass.getpass("Sentinel secret to scan for: ").encode()
matches = []
for root_name in sys.argv[1:]:
    root = pathlib.Path(root_name)
    if not root.exists():
        continue
    paths = (root.rglob("*") if root.is_dir() else (root,))
    for path in paths:
        if path.is_file() and needle in path.read_bytes():
            matches.append(str(path))
needle = None
if matches:
    print("SENTINEL FOUND in:", *matches, sep="\n")
    raise SystemExit(1)
print("Sentinel not found")
PY
```

Any match fails the gate: restrict access, preserve the affected files for the
approved incident process, and do not publish the evidence. Record the command
exit codes, observed model, reviewed hashes, logout result, and sentinel scan
result in the approved ticket. Do not commit live artifacts or logs.

## Orchestration boundary

This procedure validates only the local read-only library and CLI. Scheduling,
report generation, monitoring-platform integrations, and MCP consumers are
future work. Passing this gate does not authorize or implement those systems,
and no future consumer may bypass the fixed command policy, evidence controls,
or manual live authorization.
