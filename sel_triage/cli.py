"""Command-line entry point for sel-triage."""
import argparse
import json
import sys
from pathlib import Path

from . import render as render_mod
from .core.errors import TriageError


class _UsageError(Exception):
    """An intentionally detail-free argument error."""



class _SelValidationError(ValueError):
    """A safe, stage-specific SEL invocation validation error."""

    def __init__(self, message, category):
        super().__init__(message)
        self.category = category



class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _UsageError(message)



def _default_config():
    """Prefer a git-ignored config.local.json (real device details) over config.json."""

    return "config.local.json" if Path("config.local.json").is_file() else "config.json"


def _shared(parser, evidence=False):
    parser.add_argument("--config", default=None, help="default: config.local.json if present, else config.json")
    parser.add_argument("--render", action="store_true")
    if evidence:
        from .core.evidence import default_evidence_root

        parser.add_argument(
            "--evidence-root",
            default=str(default_evidence_root()),
            help=(
                "owner-only evidence directory in private user data "
                "(default: %(default)s)"
            ),
        )



def _sel_target(parser):
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--name")
    selection.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--model-hint")
    parser.add_argument("--credential-ref")



def _event_options(parser):
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--event-count",
        type=int,
        help="number of newest events, bounded by an absolute ceiling of 10",
    )
    selection.add_argument(
        "--event-number", type=int, help="one explicit event number"
    )
    parser.add_argument(
        "--event-format",
        choices=("eve", "cev", "cev_raw"),
        default=None,
        help="event format (default: eve)",
    )
    parser.add_argument(
        "--ser-limit",
        type=int,
        default=None,
        help="maximum retained SER rows (default: 500)",
    )
    parser.add_argument(
        "--hard-event-limit",
        type=int,
        default=None,
        help="caller limit that may lower, never raise, the absolute ceiling of 10",
    )



def _build_parser():
    parser = _Parser(prog="sel-triage")
    commands = parser.add_subparsers(dest="tool", required=True)

    snapshot = commands.add_parser(
        "sel-snapshot",
        help="collect a bounded read-only SEL snapshot",
        description=(
            "Collect a bounded read-only Access Level 1 snapshot over plaintext "
            "Telnet. Use only on a trusted plant or VPN network."
        ),
    )
    _shared(snapshot, evidence=True)
    _sel_target(snapshot)
    snapshot.add_argument(
        "--include-events",
        action="store_true",
        help=(
            "selector options require --include-events; also collect bounded "
            "SEL-651/700G event evidence and SER"
        ),
    )
    snapshot.add_argument(
        "--include-settings",
        action="store_true",
        help="also read the relay settings with SHO (SEL-700G)",
    )
    _event_options(snapshot)

    events = commands.add_parser(
        "sel-collect-events",
        help="collect bounded SEL event evidence",
        description=(
            "Collect bounded read-only SEL-651/700G event evidence over plaintext Telnet "
            "on a trusted plant or VPN network."
        ),
    )
    _shared(events, evidence=True)
    _sel_target(events)
    _event_options(events)

    event_sweep = commands.add_parser(
        "sel-event-sweep",
        help="archive SEL HIS/SER/event reports to S3 (opportunistic; never prompts)",
    )
    event_sweep.add_argument(
        "action", nargs="?", default="run", choices=("run", "install-agent", "uninstall-agent")
    )
    _shared(event_sweep)
    event_sweep.add_argument("--site", default=None)
    event_sweep.add_argument("--name", default=None, help="one configured SEL device (exact name)")
    event_sweep.add_argument("--max-sites-parallel", type=int, default=None)
    event_sweep.add_argument("--hour", type=int, default=7)

    sel_rdb = commands.add_parser("sel-rdb", help="offline: SEL .rdb databases from settings captures, and reading them")
    sel_rdb_commands = sel_rdb.add_subparsers(dest="sel_rdb_command", required=True)
    rdb_pack = sel_rdb_commands.add_parser("pack", help="one capture folder -> .rdb (subset, or --template)")
    _shared(rdb_pack)
    rdb_pack.add_argument("capture", help="capture run folder (<site>/<host>_<port>/<stamp>)")
    rdb_pack.add_argument("--out", default=None, help="output .rdb (default: next to the capture)")
    rdb_pack.add_argument("--template", default=None, help="full-schema QuickSet .rdb of the same FID")
    rdb_pack.add_argument("--device-name", default=None, help="label inside the .rdb (default: the device folder)")
    rdb_pack_all = sel_rdb_commands.add_parser("pack-all", help="newest good capture of every device -> .rdb files")
    _shared(rdb_pack_all)
    rdb_pack_all.add_argument("root", nargs="?", default=None, help="captures folder (default: selSettings.capturesDir)")
    rdb_pack_all.add_argument("--out", default=None, help="output folder (default: <app data>/sel-rdb)")
    rdb_pack_all.add_argument("--templates", default=None, help="folder of <FID>.rdb templates")
    rdb_read = sel_rdb_commands.add_parser("read", help="relays, classes and settings in a .rdb")
    _shared(rdb_read)
    rdb_read.add_argument("rdb")
    rdb_read.add_argument("--extract", default=None, help="dump every raw stream into this folder")
    rdb_read.add_argument("--as-capture", default=None, help="write a relay as a capture folder (for sel-settings)")
    rdb_read.add_argument("--device", default=None, help="relay inside the .rdb (when it holds several)")
    rdb_read.add_argument("--settings", action="store_true", help="include every parsed setting")

    breaker_trend = commands.add_parser(
        "sel-breaker-trend",
        help="offline: breaker wear and operations over time from archived BRE readings (sel-event-sweep)",
    )
    _shared(breaker_trend)
    breaker_trend.add_argument("--name", default=None, help="one device (exact name)")
    breaker_trend.add_argument("--site", default=None, help="devices whose site contains this text")
    breaker_trend.add_argument("--min-days", type=float, default=7.0,
                               help="minimum span of readings for a rate (default 7)")
    breaker_trend.add_argument("--horizon-days", type=float, default=365.0,
                               help="flag wear projected to reach the threshold within this many days (default 365)")

    settings_capture = commands.add_parser(
        "sel-settings-capture",
        help="read complete SEL settings with FILE READ (FILE SHOW on the 735), read-only; never opens a VPN",
        description=(
            "Live, read-only settings capture (ported from SEL-Audit): ID, CFG.TXT and every "
            "SET_<class>.TXT stream, saved in SEL-Audit's Reads layout for sel-inventory and "
            "sel-settings. One Access Level 1 login per device, never retried."
        ),
    )
    _shared(settings_capture)
    capture_selection = settings_capture.add_mutually_exclusive_group(required=True)
    capture_selection.add_argument("--name", help="one configured SEL device")
    capture_selection.add_argument("--site", help="every SEL device whose site contains this text")
    capture_selection.add_argument("--all", action="store_true", help="every configured SEL device")
    settings_capture.add_argument(
        "--out", default=None,
        help="captures folder (default: selSettings.capturesDir, else the app's sel-settings folder; "
             "SEL-Audit's Reads folder works too)")
    settings_capture.add_argument("--max-age-days", type=float, default=None,
                                  help="skip devices with a successful capture newer than this")
    settings_capture.add_argument("--max-sites-parallel", type=int, default=None)
    settings_capture.add_argument("--pause", type=float, default=None, help="seconds between transfers (default 0.3)")
    settings_capture.add_argument("--block-timeout", type=float, default=None,
                                  help="per-block XMODEM timeout in seconds (default 10)")
    settings_capture.add_argument("--no-index", action="store_true",
                                  help="do not update the SQLite index (sel-settings index) after the run")

    event_reparse = commands.add_parser(
        "sel-event-reparse",
        help="re-parse archived SEL HIS/SER with current parsers (S3 only, no devices)",
    )
    _shared(event_reparse)
    event_reparse.add_argument("--family", default=None)
    event_reparse.add_argument("--since", default=None, help="first run_id to scan")

    rtac = commands.add_parser(
        "rtac-snapshot",
        help="collect a read-only SEL RTAC web snapshot (SOE, alarms, diagnostics, connected IEDs)",
        description=(
            "Log in to an SEL-3505 RTAC's web interface with the keychain item "
            "rtac/<site> (account = username), fetch read-only reports, and log out. "
            "Every login is recorded in the RTAC's own SOE."
        ),
    )
    _shared(rtac, evidence=True)
    rtac.add_argument("--name", required=True)

    rtac_api = commands.add_parser(
        "rtac-api-snapshot",
        help="read-only SEL RTAC REST API snapshot (identity, status, alarms, IED connections, optional tags)",
        description=(
            "Request one token from the RTAC REST API (/api/v1) with the keychain item rtac/<site> "
            "(account = username) and send only GETs to an allowlist. The account needs the 'API Login' "
            "permission; a refused token request is recorded in the RTAC's SOE and is never retried."
        ),
    )
    _shared(rtac_api, evidence=True)
    rtac_api.add_argument("--name", required=True)
    rtac_api.add_argument("--tags", action="append", default=[], metavar="FILTER",
                          help="also read logic-engine tags matching FILTER (e.g. '*g_*'); repeatable")
    rtac_api.add_argument("--alarm-history-hours", type=float, metavar="H",
                          help="also read the last H hours of history for each tag in the alarm summary")
    rtac_api.add_argument("--credential-service", metavar="SERVICE",
                          help="keychain service of a separate API account (default: the device's rtac/<site>)")

    visualize = commands.add_parser(
        "sel-visualize",
        help="offline reports (interactive HTML, CSV, JSON) for retrieved SEL EVE or CEV files",
        description=(
            "Parse SEL ASCII EVE and SEL-651R raw CEV event files and write, per file, report.html "
            "(waveforms, digital states, phasors), analog.csv, digital.csv, metadata.json and a "
            "byte-identical source copy. A folder input contributes every .eve/.cev in it. "
            "No device access."
        ),
    )
    visualize.add_argument("inputs", nargs="+")
    visualize.add_argument("--output-dir", required=True)
    visualize.add_argument("--overwrite", action="store_true",
                           help="replace an output folder that holds only generated reports")
    visualize.add_argument("--render", action="store_true")
    # Offline SEL captures (SEL-Audit Reads or the evidence store); no device access.
    sel_inventory = commands.add_parser(
        "sel-inventory", help="offline: one row per SEL device from saved captures (model, firmware, capture age)")
    _shared(sel_inventory)
    sel_inventory.add_argument("path", help="SEL-Audit Reads folder (or a site, device or run folder), or evidence")
    sel_inventory.add_argument("--csv", action="store_true", help="print the rows as CSV instead of JSON")
    sel_inventory.add_argument("--max-age-days", type=float,
                               help="flag captures older than this (default: sel_capture_max_age_days, 180)")
    sel_settings = commands.add_parser("sel-settings", help="offline: check or diff saved SEL settings captures")
    sel_settings_commands = sel_settings.add_subparsers(dest="sel_settings_command", required=True)
    sel_check = sel_settings_commands.add_parser("check", help="rule checks on each device's newest settings")
    _shared(sel_check)
    sel_check.add_argument("path", help="SEL-Audit Reads folder (or a site, device or run folder), or evidence")
    sel_check.add_argument("--group", default="1", help="settings group to check (default: 1)")
    sel_rules = sel_settings_commands.add_parser("rules", help="list the settings rules")
    _shared(sel_rules)
    sel_index = sel_settings_commands.add_parser(
        "index", help="index saved captures into SQLite (captures, settings, latest_* views) for fleet queries")
    _shared(sel_index)
    sel_index.add_argument("path", nargs="?", default=None,
                           help="captures folder (default: selSettings.capturesDir); SEL-Audit Reads works too")
    sel_index.add_argument("--db", default=None,
                           help="database (default: selSettings.indexPath, else the app's sel-settings.sqlite)")
    sel_index.add_argument("--rebuild", action="store_true", help="re-read every capture under the folder")
    sel_diff = sel_settings_commands.add_parser(
        "diff", help="diff two captures (device or run folders); one device folder diffs its last two captures")
    _shared(sel_diff)
    sel_diff.add_argument("a")
    sel_diff.add_argument("b", nargs="?")
    sel_diff.add_argument("--include-identity", action="store_true",
                          help="between peers, also show names and addresses")
    sel_diff.add_argument("--ignore", action="append", help="key regular expression to skip (repeatable)")
    return parser



def _print_result(result, human_readable):
    if human_readable:
        print(render_mod.render(result))
    else:
        print(json.dumps(result, indent=2))



def _sel_context(args):
    # Imports and run functions are deliberately resolved at invocation time.
    # This keeps CLI tests hermetic and prevents an import from initiating work.
    from .core.config import read_config
    from .core.inventory import resolve_device, with_imported_devices
    from .core.secrets import MacOSKeychainSecretProvider

    if args.name is not None and (
        not isinstance(args.name, str) or not args.name.strip()
    ):
        raise _SelValidationError("name must be nonempty", "invalid_target")
    if args.host is not None and (
        not isinstance(args.host, str) or not args.host.strip()
    ):
        raise _SelValidationError("host must be nonempty", "invalid_target")

    if args.host is not None:
        if args.port is None or args.credential_ref is None:
            raise _SelValidationError(
                "ad-hoc target requires --port and --credential-ref",
                "invalid_target",
            )
    elif any(
        value is not None
        for value in (args.port, args.model_hint, args.credential_ref)
    ):
        raise _SelValidationError(
            "named target cannot include ad-hoc target options", "invalid_target"
        )

    try:
        config = with_imported_devices(read_config(args.config), args.config)
    except (OSError, ValueError) as exc:
        raise _SelValidationError(str(exc), "config") from None
    try:
        target = resolve_device(
            config,
            name=args.name,
            host=args.host,
            port=args.port,
            model_hint=args.model_hint,
            credential_ref=args.credential_ref,
        )
    except ValueError as exc:
        category = "invalid_target"
        if args.name is not None and not str(exc).startswith("device not found"):
            category = "config"
        raise _SelValidationError(str(exc), category) from None
    if target.kind.lower() != "sel":
        raise _SelValidationError(
            "selected device is not an SEL target", "invalid_target"
        )

    service = _keychain_service(config)
    try:
        provider = MacOSKeychainSecretProvider(service)
    except ValueError as exc:
        raise _SelValidationError(str(exc), "config") from None
    from .core.thresholds import resolve_thresholds
    from .integrations.devices.sel.diagnostics import DEFAULT_THRESHOLDS

    try:
        thresholds = resolve_thresholds(
            config, target.name, target.model_hint, _threshold_names()
        )
    except ValueError as exc:
        raise _SelValidationError(str(exc), "config") from None
    return target, provider, thresholds



def _keychain_service(config):
    providers = config.get("secretProviders", {})
    if not isinstance(providers, dict):
        raise _SelValidationError("secretProviders must be an object", "config")
    default_provider = providers.get("default", {})
    if not isinstance(default_provider, dict):
        raise _SelValidationError(
            "default secret provider must be an object", "config"
        )
    if default_provider and default_provider.get("type") != "macos-keychain":
        raise _SelValidationError("unsupported secret provider type", "config")
    return default_provider.get("service", "sel-triage")



def _threshold_names():
    from .tools.threshold_names import threshold_names

    return threshold_names()



def _rtac_target(args):
    from .core.config import read_config
    from .core.inventory import resolve_device, with_imported_devices
    from .core.thresholds import resolve_thresholds

    try:
        config = read_config(args.config) if Path(args.config).is_file() else {}
        config = with_imported_devices(config, args.config)
        target = resolve_device(config, name=args.name)
        if target.kind.lower() != "rtac":
            raise ValueError("selected device is not an RTAC")
        thresholds = resolve_thresholds(config, target.name, None, _threshold_names())
    except (OSError, ValueError) as exc:
        raise _SelValidationError(str(exc), "config") from None
    return target, thresholds



def _run_rtac_api(args, now):
    from .integrations.devices.rtac import api_workflow
    from .integrations.devices.rtac.credentials import read_keychain_login

    target, thresholds = _rtac_target(args)
    return api_workflow.run_rtac_api_snapshot(
        target,
        read_keychain_login,
        Path(args.evidence_root),
        now=now,
        thresholds=thresholds,
        tag_filters=args.tags,
        alarm_history_hours=args.alarm_history_hours,
        credential_service=args.credential_service,
    )



def _run_rtac(args, now):
    from .integrations.devices.rtac import workflow
    from .integrations.devices.rtac.credentials import read_keychain_login

    target, thresholds = _rtac_target(args)
    return workflow.run_rtac_snapshot(
        target,
        read_keychain_login,
        Path(args.evidence_root),
        now=now,
        thresholds=thresholds,
    )



NOT_TRIED_OUTCOMES = ("auth_skipped", "breaker_skipped")


def _sel_event_sweep_inputs(args):
    """Build (config, settings, deps, state_path) for a real sweep."""

    from dataclasses import replace
    from .core.config import read_config
    from .core.inventory import with_imported_devices
    from .core.secrets import MacOSKeychainSecretProvider
    from .sel_archive import agent
    from .sel_archive.settings import archive_settings
    from .sel_archive.state import default_state_path
    from .sel_archive.sweep import SweepDeps

    config = with_imported_devices(read_config(args.config), args.config)
    settings = archive_settings(config)
    if args.max_sites_parallel is not None:
        if args.max_sites_parallel <= 0:
            raise ValueError("--max-sites-parallel must be positive")
        settings = replace(settings, max_sites_parallel=args.max_sites_parallel)

    def network_up():
        # sel-triage never manages VPNs or network links; reaching the devices is the operator's job
        return True

    def aws_ok():
        if settings.store == "local":
            return True
        try:
            import boto3

            session = boto3.Session(profile_name=settings.profile) if settings.profile else boto3.Session()
            session.client("s3").head_bucket(Bucket=settings.bucket)
            return True
        except Exception:
            return False

    deps = SweepDeps(
        network_up=network_up,
        aws_ok=aws_ok,
        notify=agent.macos_notify,
        client_factory=agent.sweep_client_factory(settings.read_timeout_seconds),
        secret_provider=MacOSKeychainSecretProvider(_keychain_service(config)),
        archive=_event_archive(settings),
    )
    # a local store keeps its own sweep state, so switching stores never skips a device's reports
    state_path = settings.local_dir / "state.sqlite" if settings.store == "local" else default_state_path()
    return config, settings, deps, state_path



def _event_archive(settings):
    if settings.store == "local":
        from .sel_archive.archive import LocalArchive

        return LocalArchive(settings.local_dir)
    return _LazyS3Archive(settings.bucket, settings.profile)



class _LazyS3Archive:
    """Create the boto3 client only when a sweep actually uploads."""

    def __init__(self, bucket, profile):
        self._args = (bucket, profile)
        self._archive = None

    def _real(self):
        if self._archive is None:
            from .sel_archive.archive import S3Archive

            self._archive = S3Archive(*self._args)
        return self._archive

    def put(self, key, data, content_type):
        self._real().put(key, data, content_type)

    def get(self, key):
        return self._real().get(key)

    def list_children(self, prefix):
        return self._real().list_children(prefix)



def _run_sel_event_sweep(args):
    from .sel_archive import agent
    from .sel_archive import sweep as sweep_mod

    if args.action == "install-agent":
        repo = str(Path.cwd().resolve())
        result = agent.install_agent(sys.executable, repo, str(Path(args.config).resolve()), args.hour)
        print(json.dumps(result, indent=2))
        return 0
    if args.action == "uninstall-agent":
        print(json.dumps(agent.uninstall_agent(), indent=2))
        return 0
    config, settings, deps, state_path = _sel_event_sweep_inputs(args)
    try:
        summary = sweep_mod.run_sweep(config, settings, deps, state_path, site=args.site, name=args.name)
    except KeyboardInterrupt:
        return _error("interrupted", "stopped by user; nothing was committed", 130)
    except (TriageError, ValueError):
        raise
    except Exception as exc:
        return _error("sweep_failed", "{0}: {1}".format(type(exc).__name__, exc), 2)
    print(json.dumps(summary, indent=2))
    return 0



def _run_sel_rdb(args):
    from .core.config import read_config
    from .core.inventory import with_imported_devices
    from .integrations.devices.sel.settings.index import inventory_endpoints
    from .tools import sel_capture, sel_rdb

    if args.sel_rdb_command == "pack":
        return sel_rdb.run_pack(Path(args.capture), out=Path(args.out) if args.out else None,
                                template=Path(args.template) if args.template else None,
                                device_name=args.device_name)
    if args.sel_rdb_command == "read":
        return sel_rdb.run_read(Path(args.rdb), extract=Path(args.extract) if args.extract else None,
                                as_capture=Path(args.as_capture) if args.as_capture else None,
                                device=args.device, include_settings=args.settings)
    config = read_config(args.config) if Path(args.config).is_file() else {}
    if config:
        config = with_imported_devices(config, args.config)
    root, _db = sel_capture.configured_paths(config)
    root = Path(args.root) if args.root else root
    out = Path(args.out) if args.out else sel_capture.default_captures_root().parent / "sel-rdb"
    return sel_rdb.run_pack_all(root, out, templates=Path(args.templates) if args.templates else None,
                                endpoints=inventory_endpoints(config))



def _run_sel_breaker_trend(args):
    from .core.config import read_config
    from .core.inventory import with_imported_devices
    from .core.thresholds import resolve_thresholds
    from .sel_archive.breaker_trend import run_trend
    from .sel_archive.settings import archive_settings

    config = with_imported_devices(read_config(args.config), args.config)
    settings = archive_settings(config)
    names = _threshold_names()
    if args.min_days < 0 or args.horizon_days < 0:
        raise ValueError("--min-days and --horizon-days must be >= 0")
    return run_trend(
        _event_archive(settings), settings.prefix,
        thresholds_for=lambda name, model: resolve_thresholds(config, name, model, names),
        name=args.name, site=args.site, min_days=args.min_days, horizon_days=args.horizon_days,
    )



def _run_sel_settings_capture(args):
    from dataclasses import replace
    from .core.config import read_config
    from .core.inventory import with_imported_devices
    from .core.secrets import MacOSKeychainSecretProvider
    from .integrations.devices.sel.settings.live import CaptureOptions
    from .sel_archive import agent
    from .tools import sel_capture

    config = with_imported_devices(read_config(args.config), args.config)
    section = config.get("selSettings", {}) or {}
    default_root, index_db = sel_capture.configured_paths(config)
    root = args.out or str(default_root)
    options = CaptureOptions()
    if args.pause is not None:
        if args.pause < 0:
            raise ValueError("--pause must be >= 0")
        options = replace(options, pause_seconds=args.pause)
    if args.block_timeout is not None:
        if args.block_timeout <= 0:
            raise ValueError("--block-timeout must be positive")
        options = replace(options, block_timeout=args.block_timeout)
    parallel = args.max_sites_parallel or int(section.get("maxSitesParallel", sel_capture.DEFAULT_MAX_SITES_PARALLEL))
    if parallel <= 0:
        raise ValueError("--max-sites-parallel must be positive")
    if args.max_age_days is not None and args.max_age_days < 0:
        raise ValueError("--max-age-days must be >= 0")
    settings = sel_capture.CaptureSettings(
        root=Path(root).expanduser(),
        options=options,
        max_sites_parallel=parallel,
        unreachable_stop_after=int(section.get("unreachableStopAfter", sel_capture.DEFAULT_UNREACHABLE_STOP_AFTER)),
        max_age_days=args.max_age_days,
    )

    def network_up():
        # sel-triage never manages VPNs or network links; reaching the devices is the operator's job
        return True

    deps = sel_capture.CaptureDeps(
        network_up=network_up,
        client_factory=agent.sweep_client_factory(
            float(section.get("readTimeoutSeconds", sel_capture.DEFAULT_READ_TIMEOUT_SECONDS))
        ),
        secret_provider=MacOSKeychainSecretProvider(_keychain_service(config)),
    )
    items = sel_capture.select_items(config, name=args.name, site=None if args.all else args.site)
    try:
        result = sel_capture.run_capture(config, items, settings, deps)
    except KeyboardInterrupt:
        raise TriageError("stopped by user; finished captures are kept", category="interrupted", reachable=None)
    if not args.no_index and settings.root.is_dir():
        from .integrations.devices.sel.settings.index import build_index, inventory_endpoints

        try:
            result["index"] = build_index(settings.root, index_db, endpoints=inventory_endpoints(config))
        except (OSError, ValueError) as exc:
            result.setdefault("warnings", []).append("index_not_updated: {0}".format(exc))
    return result



def _run_sel_event_reparse(args):
    from .core.config import read_config
    from .sel_archive.reparse import reparse
    from .sel_archive.settings import archive_settings

    settings = archive_settings(read_config(args.config))
    result = reparse(
        _event_archive(settings),
        settings.prefix,
        family=args.family,
        since=args.since,
    )
    print(json.dumps(result, indent=2))
    return 0



def _selector(args):
    from .tools.sel_collect_events import EventSelector

    event_format = "eve" if args.event_format is None else args.event_format
    if args.event_number is not None:
        return EventSelector.number(args.event_number, event_format=event_format)
    count = 1 if args.event_count is None else args.event_count
    return EventSelector.latest(count=count, event_format=event_format)



def _validated_event_request(args):
    from .integrations.devices.sel.workflows import ABSOLUTE_EVENT_LIMIT

    try:
        selector = _selector(args)
    except ValueError as exc:
        raise _SelValidationError(str(exc), "invalid_event_request") from None
    args.ser_limit = 500 if args.ser_limit is None else args.ser_limit
    args.hard_event_limit = (
        ABSOLUTE_EVENT_LIMIT
        if args.hard_event_limit is None
        else args.hard_event_limit
    )
    if args.ser_limit < 1:
        raise _SelValidationError(
            "SER limit must be a positive integer", "invalid_event_request"
        )
    if args.hard_event_limit < 1:
        raise _SelValidationError(
            "hard event limit must be a positive integer", "invalid_event_request"
        )
    if args.hard_event_limit > ABSOLUTE_EVENT_LIMIT:
        raise _SelValidationError(
            "hard event limit exceeds the absolute maximum of {0}".format(
                ABSOLUTE_EVENT_LIMIT
            ),
            "invalid_event_request",
        )
    if selector.count > args.hard_event_limit:
        raise _SelValidationError(
            "requested event count exceeds the configured hard maximum of {0}".format(
                args.hard_event_limit
            ),
            "invalid_event_request",
        )
    return selector



def _collect(target, provider, args, now, selector):
    from .tools import sel_collect_events

    return sel_collect_events.run(
        target,
        selector=selector,
        ser_limit=args.ser_limit,
        hard_event_limit=args.hard_event_limit,
        secret_provider=provider,
        evidence_root=Path(args.evidence_root),
        now=now,
    )



def _run_sel(args, now):
    if args.tool == "sel-visualize":
        from .tools import sel_visualize

        try:
            return sel_visualize.run(args.inputs, args.output_dir, overwrite=args.overwrite)
        except ValueError as exc:
            raise _SelValidationError(
                str(exc), "invalid_visualizer_request"
            ) from None

    selector = None
    explicit_event_options = any(
        value is not None
        for value in (
            args.event_count,
            args.event_number,
            args.event_format,
            args.ser_limit,
            args.hard_event_limit,
        )
    )
    if (
        args.tool == "sel-snapshot"
        and not args.include_events
        and explicit_event_options
    ):
        raise _SelValidationError(
            "event selector options require --include-events",
            "invalid_event_request",
        )
    if args.tool == "sel-collect-events" or args.include_events:
        selector = _validated_event_request(args)

    target, provider, thresholds = _sel_context(args)
    if args.tool == "sel-collect-events":
        return _collect(target, provider, args, now, selector)

    from .tools import sel_snapshot

    result = sel_snapshot.run(
        [target],
        provider,
        Path(args.evidence_root),
        now=now,
        thresholds=thresholds,
        include_settings=args.include_settings,
    )
    if args.include_events:
        result = dict(result)
        try:
            event_collection = _collect(
                target, provider, args, now, selector
            )
        except Exception as exc:
            from .integrations.devices.sel.workflows import event_failure_result

            event_collection = event_failure_result(
                target,
                result.get("ran_at", "unknown"),
                exc,
            )
        result["event_collection"] = event_collection
        if event_collection.get("ok") is not True:
            result["ok"] = False
            result["partial"] = bool(
                result.get("partial") is True
                or any(
                    isinstance(item, dict)
                    and (item.get("ok") is True or item.get("partial") is True)
                    for item in result.get("targets", [])
                )
            )
            result["errors"] = list(result.get("errors", []))
            for error in event_collection.get("errors", []):
                if isinstance(error, dict):
                    item = dict(error)
                    item.setdefault("scope", "event_collection")
                    result["errors"].append(item)
    return result



def _run_sel_offline(args, now):
    from .core.config import read_config
    from .tools import sel_settings

    config = read_config(args.config) if Path(args.config).is_file() else {}
    names = _threshold_names()
    if args.tool == "sel-inventory":
        result = sel_settings.run_inventory(args, config, names, now)
        if args.csv:
            from .integrations.devices.sel.settings.inventory import inventory_csv

            sys.stdout.write(inventory_csv(result))
            return 0
    elif args.sel_settings_command == "check":
        result = sel_settings.run_check(args, config, names, now)
    elif args.sel_settings_command == "rules":
        result = sel_settings.run_rules(now)
    elif args.sel_settings_command == "index":
        from .core.inventory import with_imported_devices

        if Path(args.config).is_file():
            config = with_imported_devices(config, args.config)
        result = sel_settings.run_index(args, config, now)
    else:
        result = sel_settings.run_diff(args, now)
    _print_result(result, args.render)
    return 0



def _error(category, message, exit_code):
    print("error[{0}]: {1}".format(category, message), file=sys.stderr)
    return exit_code



def main(argv=None, now=None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError:
        return _error("usage", "invalid command arguments", 2)
    except SystemExit as exc:
        return int(exc.code or 0)
    if getattr(args, "config", "") is None:
        args.config = _default_config()

    try:
        if args.tool == "rtac-snapshot":
            _print_result(_run_rtac(args, now), args.render)
            return 0
        if args.tool == "rtac-api-snapshot":
            _print_result(_run_rtac_api(args, now), args.render)
            return 0
        if args.tool in ("sel-inventory", "sel-settings"):
            return _run_sel_offline(args, now)
        if args.tool == "sel-event-sweep":
            return _run_sel_event_sweep(args)
        if args.tool == "sel-event-reparse":
            return _run_sel_event_reparse(args)
        if args.tool == "sel-rdb":
            _print_result(_run_sel_rdb(args), args.render)
            return 0
        if args.tool == "sel-breaker-trend":
            _print_result(_run_sel_breaker_trend(args), args.render)
            return 0
        if args.tool == "sel-settings-capture":
            result = _run_sel_settings_capture(args)
            _print_result(result, args.render)
            return 0 if result.get("ok") else 2
        result = _run_sel(args, now)
        _print_result(result, args.render)
        return 0
    except TriageError as exc:
        return _error(exc.category, str(exc), 2)
    except _SelValidationError as exc:
        return _error(exc.category, str(exc), 2)
    except ValueError as exc:
        category = "invalid_request" if args.tool.startswith("sel-") else "config"
        return _error(category, str(exc), 2)
    except Exception:
        return _error("unexpected", "command failed", 1)



__all__ = ["main"]
