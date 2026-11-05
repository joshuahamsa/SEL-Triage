"""Bounded Access Level 1 session client for read-only SEL triage."""

from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Mapping, Optional

from sel_triage.core.errors import TriageError
from sel_triage.core.redaction import SecretFingerprintRedactor
from sel_triage.transports.telnet import TelnetTransport

from .commands import COMMANDS_BY_FAMILY, SelCommand
from .settings.xmodem import XmodemError, receive_file


_IDENTIFIER_RE = re.compile(
    r'"?([A-Za-z][A-Za-z0-9_]*)=([^"\r\n,]+)"?(?:\s*,\s*"[0-9A-Fa-f]+")?'
)
_MODEL_RE = re.compile(
    r"\bSEL-(700GT?|751A?|651(?:RA|R-?2)?)\b", re.IGNORECASE
)
_GENERAL_MODEL_RE = re.compile(
    r"\b(SEL-[0-9]{3,4}[A-Z]{0,3})\b", re.IGNORECASE
)
# Keep dispatch isolated from the exported dictionaries.  Those dictionaries
# are useful for policy inspection, but replacing an entry must never turn
# caller-controlled data into executable wire text.
_COMMAND_POLICY = MappingProxyType(
    {
        family: MappingProxyType(dict(commands))
        for family, commands in COMMANDS_BY_FAMILY.items()
    }
)


@dataclass(frozen=True)
class SelIdentity:
    """Identity fields observed from the relay's read-only ``ID`` response."""

    observed_model: str
    device_id: Optional[str]
    firmware_id: str
    identifiers: Mapping[str, str]
    raw_text: str

    @property
    def model(self) -> str:
        """Compatibility alias for the authoritative observed model."""

        return self.observed_model


# After clearing the command line, prompts are drained until the device is quiet this long.
DRAIN_QUIET_SECONDS = 1.0
DRAIN_MAX_PROMPTS = 4

# Seconds to wait for an unprompted "=" before sending one bare return.
WAKE_AFTER_SECONDS = 2.0
MAX_COMMAND_SECONDS = 300.0


class SelClient:
    """Drive the fixed ``NEW -> CONNECTED -> ACCESS1 -> CLOSED`` session."""

    def __init__(
        self, transport: TelnetTransport, command_seconds: Optional[float] = None
    ) -> None:
        # command_seconds raises (never past the transport's own read timeout)
        # the per-command deadline for slow links, e.g. a full SER at 9600 baud.
        if command_seconds is not None and (
            isinstance(command_seconds, bool)
            or not isinstance(command_seconds, (int, float))
            or not 0 < command_seconds <= MAX_COMMAND_SECONDS
        ):
            raise ValueError(
                "command_seconds must be in (0, {0}]".format(MAX_COMMAND_SECONDS)
            )
        self._command_seconds = command_seconds
        self._transport = transport
        self._state = "NEW"
        self._family = "generic"
        self._identity: Optional[SelIdentity] = None

    def __repr__(self) -> str:
        return "SelClient(state={0!r}, family={1!r})".format(
            self._state, self._family
        )

    @property
    def state(self) -> str:
        return self._state

    @property
    def family(self) -> str:
        return self._family

    @property
    def identity(self) -> Optional[SelIdentity]:
        return self._identity

    @property
    def transcript(self) -> bytes:
        """Bytes received so far (bounded by the transport); callers redact before storing."""

        return bytes(getattr(self._transport, "transcript", b""))

    def login(self, password: str) -> SelIdentity:
        """Enter Access Level 1 and identify the connected device."""

        redactor: Optional[SecretFingerprintRedactor] = None
        try:
            if (
                not isinstance(password, str)
                or "\r" in password
                or "\n" in password
            ):
                raise TriageError(
                    "SEL credential must contain exactly one line",
                    category="invalid_secret",
                    reachable=None,
                )
            if self._state != "NEW":
                raise TriageError(
                    "SEL login requires a NEW session",
                    category="session_state",
                    reachable=None,
                )
            redactor = SecretFingerprintRedactor(password)

            try:
                self._transport.connect()
                self._state = "CONNECTED"
                self._read_initial_prompt()
                self._transport.write_line("ACC")

                password_prompt = self._transport.read_until((b"Password:",))
                if password_prompt.matched != b"Password:":
                    raise TriageError(
                        "SEL password prompt was not received",
                        category="authentication_failed",
                        reachable=True,
                    )

                self._transport.write_line(password)
                password = None
                access_result = self._transport.read_until(
                    (b"=>", b"Password:", b"="),
                    line_prompts=(b"=>", b"="),
                )
                if access_result.matched != b"=>":
                    raise TriageError(
                        "SEL Access Level 1 authentication failed",
                        category="authentication_failed",
                        reachable=True,
                    )

                self._state = "ACCESS1"
                raw_identity = redactor.redact(self.run("identity"))
                identity = _normalize_identity(raw_identity)
                self._identity = identity
                self._family = _family_for(identity.observed_model)
                return identity
            except Exception:
                self._close()
                raise
        finally:
            # Tracebacks retain frame locals after an error.  Clear the only
            # secret-bearing local before this frame can be retained.
            password = None
            redactor = None

    def _read_initial_prompt(self) -> None:
        """Wait for the first "=" prompt, sending one bare return if it is quiet.

        Relays reached through a serial terminal server (banner "TERMINAL
        SERVER") print nothing until a carriage return arrives. A return at a
        direct relay's "=" prompt only redisplays the prompt.
        """

        session_timeout = self._transport.read_timeout
        self._transport.read_timeout = min(WAKE_AFTER_SECONDS, session_timeout)
        try:
            self._transport.read_until((b"=",), line_prompts=(b"=",))
            return
        except TriageError as error:
            if error.category != "transport_timeout":
                raise
        finally:
            self._transport.read_timeout = session_timeout
        self._transport.write_line("")
        self._transport.read_until((b"=",), line_prompts=(b"=",))

    def run(self, capability: str, argument: object = None) -> str:
        """Run one allowlisted capability; callers cannot supply wire text."""

        # Text responses drop SEL STX/ETX message framing; run_bytes keeps raw
        # bytes because binary event data can contain those values.
        return (
            self.run_bytes(capability, argument)
            .decode("utf-8", errors="replace")
            .replace("\x02", "")
            .replace("\x03", "")
        )

    def run_bytes(self, capability: str, argument: object = None) -> bytes:
        """Run one allowlisted recipe while preserving binary response bytes."""

        command = self._command_for(capability)
        wire_text = command.render(argument)
        if self._state != "ACCESS1":
            raise TriageError(
                "SEL capability requires an ACCESS1 session",
                category="session_state",
                reachable=None,
            )

        try:
            self._transport.write_line(wire_text)
            original_timeout = getattr(self._transport, "read_timeout", None)
            if (
                not isinstance(original_timeout, bool)
                and isinstance(original_timeout, (int, float))
            ):
                allowed = command.max_seconds
                if self._command_seconds is not None:
                    allowed = max(allowed, float(self._command_seconds))
                self._transport.read_timeout = min(float(original_timeout), allowed)
            try:
                result = self._transport.read_until(
                    (command.terminal_prompt,),
                    max_bytes=command.max_bytes,
                    line_prompts=(command.terminal_prompt,),
                )
            finally:
                if (
                    not isinstance(original_timeout, bool)
                    and isinstance(original_timeout, (int, float))
                ):
                    self._transport.read_timeout = original_timeout
            return result.data
        except Exception:
            self._close()
            raise

    def read_file(
        self,
        filename: str,
        *,
        start_retries: int = 15,
        start_timeout: float = 3.0,
        block_timeout: float = 10.0,
        settle_seconds: float = 8.0,
    ) -> bytes:
        """Copy one settings file from the device with ``FILE READ`` (XMODEM/YMODEM).

        The device is the sender; this drives the receiver side (``C``/``ACK``/``NAK``
        only). A failed transfer raises ``file_transfer_failed`` after waiting for the
        prompt, leaving the session usable for the next file; any other error closes it.
        Telnet IAC escaping is undone only on an endpoint that negotiated Telnet.
        """

        command = self._command_for("file_read")
        wire_text = command.render(filename)
        if self._state != "ACCESS1":
            raise TriageError(
                "SEL capability requires an ACCESS1 session",
                category="session_state",
                reachable=None,
            )
        try:
            self._transport.write_line(wire_text)
            try:
                _name, data = receive_file(
                    self._transport.read_raw,
                    self._transport.write_control,
                    start_retries=start_retries,
                    start_timeout=start_timeout,
                    block_timeout=block_timeout,
                )
            except XmodemError as error:
                # The receiver's 'C' invitations went to a device that never started
                # sending, so they sit typed on its command line ("CCCC"). A bare return
                # discards them (an unknown command at Access Level 1) before the next one.
                self._flush_line(settle_seconds)
                raise TriageError(
                    "FILE READ {0} failed: {1}".format(filename, error),
                    category="file_transfer_failed",
                    reachable=True,
                ) from None
            self._settle(settle_seconds)
            # A 'C' sent before the transfer began may also be left on the line.
            self._flush_line(settle_seconds)
            return data
        except TriageError as error:
            if error.category != "file_transfer_failed":
                self._close()
            raise
        except Exception:
            self._close()
            raise

    def _flush_line(self, seconds: float) -> None:
        """Send one bare return, wait for its prompt, then drain any later prompts.

        A device can answer leftover characters and the return with more than one prompt
        (seen live: an SEL-851 answered "C" with "Enter at least three letters..." after
        the flush's own prompt). An unread prompt would end the *next* command's read
        early and shift every response by one, so prompts are read until the device has
        been quiet for ``DRAIN_QUIET_SECONDS``.
        """

        self._transport.write_line("")
        self._settle(seconds)
        for _ in range(DRAIN_MAX_PROMPTS):
            if not self._settle(DRAIN_QUIET_SECONDS):
                break

    def _settle(self, seconds: float) -> bool:
        """Wait for one ``=>`` prompt; a quiet device is not an error. True if a prompt came."""

        original_timeout = self._transport.read_timeout
        self._transport.read_timeout = min(float(original_timeout), seconds)
        try:
            self._transport.read_until((b"=>",), line_prompts=(b"=>",))
            return True
        except TriageError as error:
            if error.category != "transport_timeout":
                raise
            return False
        finally:
            self._transport.read_timeout = original_timeout

    def logout(self) -> None:
        """End the session without issuing any additional relay command."""

        self._close()

    def _command_for(self, capability: str) -> SelCommand:
        commands = _COMMAND_POLICY[self._family]
        try:
            return commands[capability]
        except (KeyError, TypeError):
            raise TriageError(
                "command_unavailable: unsupported capability for SEL family "
                "{0}".format(self._family),
                category="command_unavailable",
                reachable=None,
            ) from None

    def _close(self) -> None:
        if self._state == "CLOSED":
            return
        self._transport.close()
        self._state = "CLOSED"


def _normalize_identity(raw_text: str) -> SelIdentity:
    identifiers = {
        match.group(1).upper(): match.group(2).strip()
        for match in _IDENTIFIER_RE.finditer(raw_text)
    }
    firmware_id = identifiers.get("FID", "")
    model_match = _MODEL_RE.search(firmware_id)
    if model_match is not None:
        observed_model = "SEL-{0}".format(
            model_match.group(1).upper().replace("R-2", "R2")
        )
    else:
        general_match = _GENERAL_MODEL_RE.search(firmware_id)
        if general_match is None:
            raise TriageError(
                "SEL identity response did not contain a recognized model",
                category="invalid_identity",
                reachable=True,
            )
        observed_model = general_match.group(1).upper()
    return SelIdentity(
        observed_model=observed_model,
        device_id=identifiers.get("DEVID"),
        firmware_id=firmware_id,
        identifiers=MappingProxyType(identifiers),
        raw_text=raw_text,
    )


def _family_for(observed_model: str) -> str:
    model = observed_model.upper()
    if model in ("SEL-700G", "SEL-700GT"):
        return "sel700g"
    if model in ("SEL-751", "SEL-751A"):
        return "sel751"
    if model == "SEL-735":
        return "sel735"
    if model in ("SEL-351", "SEL-351A", "SEL-351S"):
        return "sel351"
    if model == "SEL-851":
        return "sel851"
    if model in ("SEL-651", "SEL-651RA", "SEL-651R2"):
        return "sel651"
    return "generic"


__all__ = ["SelClient", "SelIdentity"]
