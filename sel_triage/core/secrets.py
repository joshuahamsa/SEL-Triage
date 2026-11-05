"""Secret providers used by device integrations."""

import re
import subprocess
from typing import Callable, Optional, Protocol

from .errors import TriageError
from .process import run_bounded_process

SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
_KEYCHAIN_TIMEOUT_SECONDS = 2.0
_MAX_KEYCHAIN_OUTPUT_BYTES = 16 * 1024


def _without_command_line_ending(value: str) -> str:
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\r") or value.endswith("\n"):
        return value[:-1]
    return value


_MODIFIED = re.compile(r'"mdat"<timedate>=\S+\s+"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})')


def keychain_modified_at(service: str, runner: Callable = subprocess.run) -> Optional[str]:
    """When a login-keychain item was last written (UTC), without reading its value."""

    try:
        result = runner(["/usr/bin/security", "find-generic-password", "-s", service],
                        capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _MODIFIED.search(result.stdout or "") if result.returncode == 0 else None
    if match is None:
        return None
    y, mo, d, h, mi, s = match.groups()
    return "{0}-{1}-{2}T{3}:{4}:{5}Z".format(y, mo, d, h, mi, s)


class SecretProvider(Protocol):
    """Resolve a credential reference without exposing it to callers."""

    def get(self, credential_ref: str) -> str:
        """Return the secret associated with ``credential_ref``."""


class MacOSKeychainSecretProvider:
    """Read a service/account pair from the macOS login or System keychain."""

    def __init__(
        self,
        service: str,
        runner: Callable = None,
        popen_factory: Callable = subprocess.Popen,
    ) -> None:
        if not isinstance(service, str) or not service.strip():
            raise ValueError("service must be nonempty")
        self.service = service
        # ``runner`` is retained as a compatibility seam for tests. Production
        # callers take the Popen-based bounded path when it is left as None.
        self.runner = runner
        self.popen_factory = popen_factory

    @staticmethod
    def _raise_timeout() -> None:
        raise TriageError(
            "keychain credential lookup timed out",
            category="secret_timeout",
        )

    @staticmethod
    def _raise_output_too_large() -> None:
        raise TriageError(
            "keychain credential lookup produced too much output",
            category="secret_output_too_large",
        )

    def _run_injected(self, command):
        timed_out = False
        try:
            result = self.runner(
                command,
                capture_output=True,
                text=True,
                timeout=_KEYCHAIN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as timeout_error:
            # TimeoutExpired retains captured output on the exception object.
            # Clear every alias before leaving the handler, then raise outside
            # it so the static TriageError has no sensitive exception context.
            timeout_error.output = None
            timeout_error.stdout = None
            timeout_error.stderr = None
            timed_out = True
        if timed_out:
            self._raise_timeout()

        output_too_large = False
        for output in (result.stdout, result.stderr):
            if output is None:
                continue
            size = (
                len(output)
                if isinstance(output, bytes)
                else len(output.encode("utf-8"))
            )
            if size > _MAX_KEYCHAIN_OUTPUT_BYTES:
                output_too_large = True
                break
        output = None
        if output_too_large:
            result = None
            self._raise_output_too_large()
        return result.returncode, result.stdout

    def _run_default(self, command):
        result = run_bounded_process(
            command,
            timeout_seconds=_KEYCHAIN_TIMEOUT_SECONDS,
            max_output_bytes=_MAX_KEYCHAIN_OUTPUT_BYTES,
            popen_factory=self.popen_factory,
        )
        output_too_large = result.output_too_large
        timed_out = result.timed_out
        if output_too_large or timed_out:
            result = None
        if output_too_large:
            self._raise_output_too_large()
        if timed_out:
            self._raise_timeout()
        return result.returncode, result.stdout.decode("utf-8")

    def get(self, credential_ref: str) -> str:
        if not isinstance(credential_ref, str) or not credential_ref.strip():
            raise ValueError("credential reference must be nonempty")

        for extra in ([], [SYSTEM_KEYCHAIN]):
            stdout = None
            command = [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                self.service,
                "-a",
                credential_ref,
                "-w",
            ] + extra
            try:
                if self.runner is None:
                    returncode, stdout = self._run_default(command)
                else:
                    returncode, stdout = self._run_injected(command)
            except OSError:
                break
            try:
                secret = (
                    _without_command_line_ending(stdout)
                    if returncode == 0
                    else ""
                )
            finally:
                stdout = None
            if secret:
                return secret

        raise TriageError(
            "keychain credential not found: {0}".format(credential_ref),
            category="secret_not_found",
        )
