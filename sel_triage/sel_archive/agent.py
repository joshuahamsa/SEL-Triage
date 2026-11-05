"""Install the daily launchd agent that runs sel-event-sweep; macOS notifications."""

import json
import os
from pathlib import Path
import plistlib
from typing import Callable, Dict, List, Optional

from ..core.inventory import DeviceTarget
from ..core.process import run_bounded_process

LABEL = "com.sel-triage.sel-event-sweep"


def default_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / (LABEL + ".plist")


def default_log_path() -> Path:
    return Path.home() / "Library" / "Logs" / "sel-triage" / "sel-event-sweep.log"


def _launchctl(args: List[str]) -> int:
    result = run_bounded_process(["/bin/launchctl"] + list(args), 30, 65536)
    return -1 if result.returncode is None else result.returncode


def build_plist(python: str, working_dir: str, config_path: str, hour: int, log_path: str) -> bytes:
    return plistlib.dumps(
        {
            "Label": LABEL,
            "ProgramArguments": [python, "-m", "sel_triage", "sel-event-sweep", "--config", config_path],
            "WorkingDirectory": working_dir,
            "StartCalendarInterval": {"Hour": hour, "Minute": 0},
            "StandardOutPath": log_path,
            "StandardErrorPath": log_path,
            "RunAtLoad": False,
        }
    )


def install_agent(
    python: str,
    working_dir: str,
    config_path: str,
    hour: int,
    *,
    path: Optional[Path] = None,
    log_path: Optional[str] = None,
    launchctl: Optional[Callable[[List[str]], int]] = None,
) -> Dict:
    if isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23:
        raise ValueError("hour must be 0-23")
    if not os.path.isabs(config_path) or not os.path.isabs(working_dir):
        raise ValueError("the agent needs absolute config and working directory paths")
    launchctl = launchctl or _launchctl
    path = Path(path) if path is not None else default_plist_path()
    log = log_path or str(default_log_path())
    Path(log).parent.mkdir(parents=True, exist_ok=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_plist(python, working_dir, config_path, hour, log))
    os.chmod(str(path), 0o644)
    domain = "gui/{0}".format(os.getuid())
    launchctl(["bootout", domain, str(path)])  # not loaded yet is fine
    if launchctl(["bootstrap", domain, str(path)]) != 0:
        raise RuntimeError("launchctl bootstrap failed for " + str(path))
    return {"installed": True, "plist": str(path), "hour": hour, "log": log}


def uninstall_agent(*, path: Optional[Path] = None, launchctl: Optional[Callable[[List[str]], int]] = None) -> Dict:
    launchctl = launchctl or _launchctl
    path = Path(path) if path is not None else default_plist_path()
    launchctl(["bootout", "gui/{0}".format(os.getuid()), str(path)])
    existed = path.is_file()
    if existed:
        path.unlink()
    return {"installed": False, "plist": str(path), "removed": existed}


def macos_notify(message: str) -> None:
    script = "display notification {0} with title \"sel-triage\"".format(json.dumps(message))
    run_bounded_process(["/usr/bin/osascript", "-e", script], 10, 4096)


def sweep_client_factory(read_timeout_seconds: float) -> Callable[[DeviceTarget], object]:
    from ..integrations.devices.sel.client import SelClient
    from ..transports.telnet import TelnetTransport

    def factory(target: DeviceTarget):
        return SelClient(
            TelnetTransport(
                target.host,
                target.port,
                connect_timeout=target.timeout_seconds,
                read_timeout=read_timeout_seconds,
            ),
            command_seconds=read_timeout_seconds,
        )

    return factory
