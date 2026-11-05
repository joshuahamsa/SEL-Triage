"""Per-site RTAC web logins from the macOS Keychain.

Each site's login is one generic-password item: service ``rtac/<site>``,
account = the RTAC username, password = the RTAC password. Usernames differ
per site, so there is no default; a missing item means no login is tried.
"""

import re
import shlex
import subprocess
from typing import Callable, Tuple

from sel_triage.core.errors import TriageError

_SECURITY = "/usr/bin/security"
_ACCOUNT = re.compile(r'"acct"<blob>="([^"]*)"')
_TIMEOUT_SECONDS = 5.0


def read_keychain_login(service: str, runner: Callable = subprocess.run) -> Tuple[str, str]:
    """Return (username, password) for ``service`` or raise credentials_missing."""

    missing = TriageError(
        "no saved RTAC login for {0}; add one with: security add-generic-password -s {1} -a <username> -w".format(
            service, shlex.quote(service)
        ),
        category="credentials_missing",
        reachable=None,
    )
    try:
        attributes = runner([_SECURITY, "find-generic-password", "-s", service],
                            capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise missing from None
    match = _ACCOUNT.search(attributes.stdout or "") if attributes.returncode == 0 else None
    if match is None or not match.group(1):
        raise missing
    try:
        secret = runner([_SECURITY, "find-generic-password", "-s", service, "-w"],
                        capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise missing from None
    password = (secret.stdout or "").rstrip("\n") if secret.returncode == 0 else ""
    if not password:
        raise missing
    return match.group(1), password


__all__ = ["read_keychain_login"]
