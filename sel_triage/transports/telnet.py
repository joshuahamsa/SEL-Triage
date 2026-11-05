"""A small, bounded Telnet transport for read-only device sessions."""

from dataclasses import dataclass
import socket
import time
from typing import Callable, Optional, Tuple

from sel_triage.core.errors import TriageError


_IAC = 255
_WILL = 251
_WONT = 252
_DO = 253
_DONT = 254
_READ_SIZE = 4096
ABSOLUTE_MAX_SESSION_BYTES = 16 * 1024 * 1024
ABSOLUTE_MAX_TRANSCRIPT_BYTES = 1024 * 1024
ABSOLUTE_MAX_PROMPT_SETTLE_SECONDS = 1.0
DEFAULT_MAX_TRANSCRIPT_BYTES = 256 * 1024
DEFAULT_PROMPT_SETTLE_SECONDS = 0.1


# SEL devices (seen behind serial terminal servers) wrap each message in
# STX (0x02) ... ETX (0x03). Prompt matching treats them like line breaks;
# payload bytes are left untouched because binary event data can contain them.
_STX = 0x02
_ETX = 0x03
# XMODEM receiver handshake: 'C' (CRC mode), ACK, NAK, CAN. write_control sends only these.
_CONTROL_BYTES = frozenset((0x43, 0x06, 0x15, 0x18))


@dataclass(frozen=True)
class TelnetRead:
    """Decoded Telnet payload ending at a requested prompt."""

    data: bytes
    matched: bytes
    elapsed_seconds: float


class TelnetTransport:
    """Perform deadline- and size-bounded reads over a Telnet socket."""

    def __init__(
        self,
        host: str,
        port: int,
        connect_timeout: float = 5.0,
        read_timeout: float = 5.0,
        max_response_bytes: int = 1024 * 1024,
        max_session_bytes: int = ABSOLUTE_MAX_SESSION_BYTES,
        max_transcript_bytes: int = DEFAULT_MAX_TRANSCRIPT_BYTES,
        prompt_settle_seconds: float = DEFAULT_PROMPT_SETTLE_SECONDS,
        socket_factory: Callable[..., socket.socket] = socket.create_connection,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if connect_timeout <= 0:
            raise ValueError("connect_timeout must be positive")
        if read_timeout <= 0:
            raise ValueError("read_timeout must be positive")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if (
            isinstance(max_session_bytes, bool)
            or not isinstance(max_session_bytes, int)
            or max_session_bytes <= 0
            or max_session_bytes > ABSOLUTE_MAX_SESSION_BYTES
        ):
            raise ValueError(
                "max_session_bytes must be between 1 and {0}".format(
                    ABSOLUTE_MAX_SESSION_BYTES
                )
            )
        if (
            isinstance(max_transcript_bytes, bool)
            or not isinstance(max_transcript_bytes, int)
            or max_transcript_bytes <= 0
            or max_transcript_bytes > ABSOLUTE_MAX_TRANSCRIPT_BYTES
        ):
            raise ValueError(
                "max_transcript_bytes must be between 1 and {0}".format(
                    ABSOLUTE_MAX_TRANSCRIPT_BYTES
                )
            )
        if (
            isinstance(prompt_settle_seconds, bool)
            or not isinstance(prompt_settle_seconds, (int, float))
            or not 0 < prompt_settle_seconds <= ABSOLUTE_MAX_PROMPT_SETTLE_SECONDS
        ):
            raise ValueError(
                "prompt_settle_seconds must be greater than 0 and no greater "
                "than {0}".format(ABSOLUTE_MAX_PROMPT_SETTLE_SECONDS)
            )

        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_response_bytes = max_response_bytes
        self.max_session_bytes = max_session_bytes
        self.max_transcript_bytes = max_transcript_bytes
        self.prompt_settle_seconds = prompt_settle_seconds
        self._socket_factory = socket_factory
        self._clock = clock
        self._socket: Optional[socket.socket] = None
        self._transcript = bytearray()
        self._payload_buffer = bytearray()
        self._telnet_state = "data"
        self._telnet_command: Optional[int] = None
        self._telnet_negotiated = False
        self._session_bytes = 0

    @property
    def transcript(self) -> bytes:
        """Return received wire bytes for caller-controlled redaction/storage."""

        return bytes(self._transcript)

    def connect(self) -> None:
        """Open the configured TCP connection and apply the read timeout."""

        if self._socket is not None:
            return
        connected: Optional[socket.socket] = None
        try:
            connected = self._socket_factory(
                (self.host, self.port), self.connect_timeout
            )
            connected.settimeout(self.read_timeout)
        except OSError as exc:
            if connected is not None:
                try:
                    connected.close()
                except OSError:
                    pass
            raise TriageError(
                "unable to establish Telnet connection",
                category="route_or_tcp",
                reachable=False,
            ) from exc

        self._socket = connected
        self._transcript.clear()
        self._payload_buffer.clear()
        self._telnet_state = "data"
        self._telnet_command = None
        self._telnet_negotiated = False
        self._session_bytes = 0

    def write_line(self, text: str) -> None:
        """Encode text as UTF-8 and send one CRLF-terminated Telnet line."""

        connected: Optional[socket.socket] = None
        payload: Optional[bytes] = None
        try:
            if (
                not isinstance(text, str)
                or "\r" in text
                or "\n" in text
            ):
                raise TriageError(
                    "Telnet lines must not contain CR or LF",
                    category="invalid_line",
                    reachable=self._socket is not None,
                )
            connected = self._require_socket()
            payload = text.encode("utf-8") + b"\r\n"
            connected.sendall(payload)
        except OSError as exc:
            raise TriageError(
                "Telnet write failed",
                category="route_or_tcp",
                reachable=True,
            ) from exc
        finally:
            # Exceptions retain frame locals.  Clear both forms of the line and
            # the socket alias so a credential cannot survive in a traceback.
            text = None
            payload = None
            connected = None

    def read_until(
        self,
        prompts: Tuple[bytes, ...],
        max_bytes: Optional[int] = None,
        line_prompts: Tuple[bytes, ...] = (),
    ) -> TelnetRead:
        """Read until a prompt, bounded by the call and transport limits."""

        if not prompts or any(
            not isinstance(prompt, bytes) or not prompt for prompt in prompts
        ):
            raise ValueError("prompts must contain nonempty bytes")
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if any(prompt not in prompts for prompt in line_prompts):
            raise ValueError("line_prompts must be a subset of prompts")

        response_limit = self.max_response_bytes
        if max_bytes is not None:
            response_limit = min(response_limit, max_bytes)

        connected = self._require_socket()
        started = self._clock()
        deadline = started + self.read_timeout
        received_bytes = len(self._payload_buffer)

        while True:
            match = self._find_prompt_match(
                prompts, response_limit, line_prompts
            )
            tentative = match is not None and match[3]
            if match is not None and not tentative:
                # A successful receive can return after its requested timeout
                # because of scheduler delay.  Do not let bytes from that late
                # receive finalize a prompt beyond the absolute call deadline.
                self._remaining_seconds(deadline)
                return self._complete_prompt_read(
                    connected,
                    match,
                    response_limit,
                    started,
                )

            if received_bytes > response_limit:
                raise self._read_error(
                    "Telnet response exceeded the byte limit",
                    "response_too_large",
                )
            remaining_seconds = self._remaining_seconds(deadline)
            remaining_session_bytes = self.max_session_bytes - self._session_bytes
            if remaining_session_bytes < 0 or (
                remaining_session_bytes == 0 and not tentative
            ):
                raise self._read_error(
                    "Telnet session exceeded the byte limit",
                    "session_too_large",
                )

            receive_timeout = remaining_seconds
            deadline_limited_settle = False
            if tentative:
                receive_timeout = min(
                    self.prompt_settle_seconds,
                    remaining_seconds,
                )
                deadline_limited_settle = (
                    remaining_seconds <= self.prompt_settle_seconds
                )

            try:
                connected.settimeout(receive_timeout)
                chunk = connected.recv(
                    min(
                        _READ_SIZE,
                        response_limit - received_bytes + 1,
                        remaining_session_bytes + 1,
                    )
                )
            except (socket.timeout, TimeoutError) as exc:
                if tentative and not deadline_limited_settle:
                    self._remaining_seconds(deadline)
                    return self._complete_prompt_read(
                        connected,
                        match,
                        response_limit,
                        started,
                    )
                raise self._read_error(
                    "Telnet read deadline expired", "transport_timeout"
                ) from exc
            except OSError as exc:
                raise self._read_error(
                    "Telnet connection failed while reading", "route_or_tcp"
                ) from exc

            if not chunk:
                if tentative:
                    self._remaining_seconds(deadline)
                    return self._complete_prompt_read(
                        connected,
                        match,
                        response_limit,
                        started,
                    )
                raise self._read_error(
                    "Telnet connection closed before a prompt", "transport_eof"
                )

            self._session_bytes += len(chunk)
            self._append_transcript(chunk)
            if self._session_bytes > self.max_session_bytes:
                raise self._read_error(
                    "Telnet session exceeded the byte limit",
                    "session_too_large",
                )
            received_bytes += len(chunk)
            if received_bytes > response_limit:
                raise self._read_error(
                    "Telnet response exceeded the byte limit",
                    "response_too_large",
                )
            self._payload_buffer.extend(self._decode_telnet(chunk, deadline))

    @property
    def telnet_negotiated(self) -> bool:
        """True once the peer sent a Telnet option command (a real Telnet endpoint).

        A Telnet endpoint escapes 0xFF data bytes as IAC IAC in a binary transfer; a raw
        terminal-server port does not, so read_raw de-escapes only after negotiation."""

        return self._telnet_negotiated

    def read_raw(self, timeout: float) -> bytes:
        """Return the payload bytes that arrive within *timeout* seconds (b"" if none).

        For receiver-driven binary transfers (XMODEM ``FILE READ``): bytes left over from
        the last prompt read come first; bounded by the session byte limit and recorded
        in the transcript like any other read."""

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError("timeout must be positive")
        if self._payload_buffer:
            data = bytes(self._payload_buffer)
            self._payload_buffer.clear()
            return data
        connected = self._require_socket()
        remaining_session_bytes = self.max_session_bytes - self._session_bytes
        if remaining_session_bytes <= 0:
            raise self._read_error(
                "Telnet session exceeded the byte limit", "session_too_large"
            )
        try:
            connected.settimeout(timeout)
            try:
                chunk = connected.recv(min(_READ_SIZE, remaining_session_bytes + 1))
            finally:
                connected.settimeout(self.read_timeout)
        except (socket.timeout, TimeoutError):
            return b""
        except OSError as exc:
            raise self._read_error(
                "Telnet connection failed while reading", "route_or_tcp"
            ) from exc
        if not chunk:
            raise self._read_error(
                "Telnet connection closed during a transfer", "transport_eof"
            )
        self._session_bytes += len(chunk)
        self._append_transcript(chunk)
        if self._session_bytes > self.max_session_bytes:
            raise self._read_error(
                "Telnet session exceeded the byte limit", "session_too_large"
            )
        if self._telnet_negotiated:
            return self._decode_telnet(chunk, self._clock() + timeout)
        return chunk

    def write_control(self, data: bytes) -> None:
        """Send one XMODEM receiver control byte (C, ACK, NAK or CAN) and nothing else."""

        if not isinstance(data, bytes) or len(data) != 1 or data[0] not in _CONTROL_BYTES:
            raise TriageError(
                "only XMODEM receiver control bytes may be sent",
                category="invalid_line",
                reachable=self._socket is not None,
            )
        connected = self._require_socket()
        try:
            connected.sendall(data)
        except OSError as exc:
            raise TriageError(
                "Telnet write failed",
                category="route_or_tcp",
                reachable=True,
            ) from exc

    def close(self) -> None:
        """Close the socket once; subsequent calls are no-ops."""

        connected = self._socket
        self._socket = None
        if connected is not None:
            try:
                connected.close()
            except OSError:
                pass

    def _require_socket(self) -> socket.socket:
        if self._socket is None:
            raise TriageError(
                "Telnet transport is not connected",
                category="route_or_tcp",
                reachable=False,
            )
        return self._socket

    def _read_error(self, message: str, category: str) -> TriageError:
        return TriageError(message, category=category, reachable=True)

    def _remaining_seconds(self, deadline: float) -> float:
        remaining_seconds = deadline - self._clock()
        if remaining_seconds <= 0:
            raise self._read_error(
                "Telnet read deadline expired", "transport_timeout"
            )
        return remaining_seconds

    def _find_prompt_match(
        self,
        prompts: Tuple[bytes, ...],
        max_bytes: int,
        line_prompts: Tuple[bytes, ...],
    ) -> Optional[Tuple[int, int, bytes, bool]]:
        first = None
        framed = frozenset(line_prompts)
        for order, prompt in enumerate(prompts):
            found = self._find_prompt(prompt, prompt in framed)
            if found is None:
                continue
            position, tentative = found
            candidate = (position, order, prompt, tentative)
            if first is None or candidate[:2] < first[:2]:
                first = candidate

        if first is None:
            return None

        position, _, matched, _ = first
        end = position + len(matched)
        if end > max_bytes:
            raise self._read_error(
                "Telnet response exceeded the byte limit",
                "response_too_large",
            )
        return first

    def _consume_prompt_match(
        self,
        match: Tuple[int, int, bytes, bool],
        max_bytes: int,
    ) -> Tuple[bytes, bytes]:
        position, _, matched, _ = match
        end = position + len(matched)
        if end > max_bytes:
            raise self._read_error(
                "Telnet response exceeded the byte limit",
                "response_too_large",
            )
        data = bytes(self._payload_buffer[:end])
        del self._payload_buffer[:end]
        return data, matched

    def _complete_prompt_read(
        self,
        connected: socket.socket,
        match: Tuple[int, int, bytes, bool],
        max_bytes: int,
        started: float,
    ) -> TelnetRead:
        """Restore session timeout state and return a completed prompt read."""

        try:
            connected.settimeout(self.read_timeout)
        except OSError as exc:
            raise self._read_error(
                "Telnet connection failed while restoring timeout",
                "route_or_tcp",
            ) from exc
        data, matched = self._consume_prompt_match(match, max_bytes)
        return TelnetRead(
            data=data,
            matched=matched,
            elapsed_seconds=self._clock() - started,
        )

    def _find_prompt(
        self, prompt: bytes, line_framed: bool
    ) -> Optional[Tuple[int, bool]]:
        position = self._payload_buffer.find(prompt)
        if not line_framed:
            if position < 0:
                return None
            return position, False

        buffer = self._payload_buffer
        while position >= 0:
            end = position + len(prompt)
            starts_line = position == 0 or buffer[position - 1] in (10, 13, _STX)
            after = end
            while after < len(buffer) and buffer[after] == _ETX:
                after += 1
            if starts_line and after == len(buffer):
                return position, True
            if starts_line and (after > end or buffer[end] in (10, 13)):
                return position, False
            position = buffer.find(prompt, position + 1)
        return None

    def _append_transcript(self, chunk: bytes) -> None:
        self._transcript.extend(chunk)
        excess = len(self._transcript) - self.max_transcript_bytes
        if excess > 0:
            del self._transcript[:excess]

    def _decode_telnet(self, chunk: bytes, deadline: float) -> bytes:
        payload = bytearray()
        for value in chunk:
            if self._telnet_state == "data":
                if value == _IAC:
                    self._telnet_state = "iac"
                else:
                    payload.append(value)
                continue

            if self._telnet_state == "iac":
                if value == _IAC:
                    payload.append(_IAC)
                    self._telnet_state = "data"
                elif value in (_WILL, _WONT, _DO, _DONT):
                    self._telnet_negotiated = True
                    self._telnet_command = value
                    self._telnet_state = "option"
                else:
                    self._telnet_state = "data"
                continue

            self._refuse_option(self._telnet_command, value, deadline)
            self._telnet_command = None
            self._telnet_state = "data"

        return bytes(payload)

    def _refuse_option(
        self, command: Optional[int], option: int, deadline: float
    ) -> None:
        if command == _WILL:
            response = bytes((_IAC, _DONT, option))
        elif command == _DO:
            response = bytes((_IAC, _WONT, option))
        else:
            return

        connected = self._require_socket()
        try:
            connected.settimeout(self._remaining_seconds(deadline))
            connected.sendall(response)
        except (socket.timeout, TimeoutError) as exc:
            raise self._read_error(
                "Telnet read deadline expired", "transport_timeout"
            ) from exc
        except OSError as exc:
            raise TriageError(
                "Telnet negotiation failed",
                category="route_or_tcp",
                reachable=True,
            ) from exc
