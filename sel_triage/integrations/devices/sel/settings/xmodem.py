"""XMODEM / YMODEM *receive* support for SEL relay ``FILE READ`` transfers.

Ported unchanged from SEL-Audit ``relay_tools/xmodem.py`` (field-proven on the
fleet's relays); only the receive side exists, so nothing here can write a file
to a device.

When a SEL relay is given ``FILE READ <name>`` it sends the file using the
XMODEM protocol (ACSELERATOR QuickSet uses the YMODEM-batch variant). The relay
is the *sender*; the connecting program is the *receiver* and must drive the
transfer -- request CRC mode with ``C``, acknowledge every block with ``ACK``,
and acknowledge end-of-transmission. A plain terminal capture never sends those
control bytes, so the relay just prints "Ready to send file" and stalls. That
is why ``FILE READ`` "never transfers" from a raw telnet session.

This module implements only the *receive* side. It auto-detects XMODEM vs
YMODEM from the first block's sequence number:

* **XMODEM** -- first data block is sequence 1. No length is transmitted, so
  the final block is padded with ``SUB`` (0x1A) bytes, which are trimmed off.
* **YMODEM** -- block 0 is a header carrying ``filename`` and exact byte
  ``size``; the file is then trimmed to that exact length.

The transfer is expressed against two callbacks so it can be unit-tested with a
scripted transport:

* ``read(timeout) -> bytes`` -- return bytes received within ``timeout`` (may
  be empty).
* ``write(data)`` -- send control/handshake bytes to the relay.
"""

from __future__ import annotations

import time
from collections.abc import Callable

# XMODEM/YMODEM control bytes.
SOH = 0x01  # start of a 128-byte block
STX = 0x02  # start of a 1024-byte block (XMODEM-1K / YMODEM)
EOT = 0x04  # end of transmission
ACK = 0x06  # block accepted
NAK = 0x15  # block rejected, resend
CAN = 0x18  # cancel transfer
CRC_C = 0x43  # ASCII 'C' -- receiver requests CRC mode
SUB = 0x1A  # padding byte for the final XMODEM block

ReadFn = Callable[[float], bytes]
WriteFn = Callable[[bytes], None]
LogFn = Callable[[str], None]


class XmodemError(Exception):
    """Raised when an XMODEM/YMODEM receive cannot be completed."""


def _crc16_xmodem(data: bytes) -> int:
    """Compute the CRC-16/XMODEM checksum (poly 0x1021, init 0x0000)."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


class _ByteStream:
    """Adapts a timeout-based ``read`` callback into exact-length reads."""

    def __init__(self, read: ReadFn) -> None:
        self._read = read
        self._buf = bytearray()

    def _fill(self, timeout: float) -> bool:
        """Pull one more chunk into the buffer. Returns False on timeout."""
        chunk = self._read(timeout)
        if chunk:
            self._buf.extend(chunk)
            return True
        return False

    def read_exact(self, count: int, timeout: float) -> bytes:
        """Return exactly ``count`` bytes, or raise on timeout."""
        deadline = time.monotonic() + timeout
        while len(self._buf) < count:
            if not self._fill(max(0.05, deadline - time.monotonic())):
                if time.monotonic() >= deadline:
                    raise XmodemError(f"timed out waiting for {count} bytes")
        out = bytes(self._buf[:count])
        del self._buf[:count]
        return out

    def peek(self, count: int, timeout: float) -> bytes:
        """Return up to ``count`` buffered bytes without consuming them."""
        deadline = time.monotonic() + timeout
        while len(self._buf) < count:
            if not self._fill(max(0.05, deadline - time.monotonic())):
                if time.monotonic() >= deadline:
                    break
        return bytes(self._buf[:count])

    def read_frame_start(self, timeout: float) -> int | None:
        """Return the next genuine frame-start byte (SOH/STX/EOT/CAN).

        Leading noise -- the relay's command echo and "Ready to send file"
        banner -- is discarded. A candidate SOH/STX is accepted only when the
        next two bytes form a valid block sequence pair (``~seq == 0xFF-seq``).
        That check rejects the STX (0x02) bytes the relay uses to frame
        ordinary command output, which would otherwise be mistaken for a
        1024-byte block header. Returns ``None`` on timeout.
        """
        deadline = time.monotonic() + timeout
        while True:
            if not self._buf:
                if not self._fill(max(0.05, deadline - time.monotonic())):
                    if time.monotonic() >= deadline:
                        return None
                continue
            byte = self._buf[0]
            if byte in (EOT, CAN):
                del self._buf[0]
                return byte
            if byte in (SOH, STX):
                ahead = self.peek(3, max(0.05, deadline - time.monotonic()))
                if len(ahead) == 3 and ahead[2] == (0xFF - ahead[1]) & 0xFF:
                    del self._buf[0]  # leave the seq pair for _read_block
                    return byte
            del self._buf[0]  # noise, or an STX/SOH that is not a real block


def _parse_ymodem_header(payload: bytes) -> tuple[str, int | None]:
    """Parse a YMODEM block-0 header into ``(filename, size)``.

    The header is ``filename\\0size <modtime ...>\\0`` followed by NUL padding.
    An all-NUL header (empty filename) marks the end of a YMODEM batch.
    """
    if not payload or payload[0] == 0:
        return "", None
    name_part, _, rest = payload.partition(b"\x00")
    filename = name_part.decode("ascii", errors="replace")
    size: int | None = None
    meta = rest.split(b"\x00", 1)[0].strip()
    if meta:
        first = meta.split()[0]
        try:
            size = int(first)
        except ValueError:
            size = None
    return filename, size


def _read_block(
    stream: _ByteStream,
    block_size: int,
    timeout: float,
    log: LogFn | None = None,
) -> tuple[int, bytes] | None:
    """Read and validate one SOH/STX block.

    Returns ``(seq, payload)`` if the block is intact, or ``None`` if it is
    corrupt or incomplete -- in which case the caller should NAK for a resend.
    """
    try:
        header = stream.read_exact(2, timeout)
        payload = stream.read_exact(block_size, timeout)
        crc_bytes = stream.read_exact(2, timeout)
    except XmodemError:
        if log:
            log("  block incomplete (timed out mid-block)")
        return None
    seq, seq_complement = header[0], header[1]
    if _crc16_xmodem(payload) != (crc_bytes[0] << 8 | crc_bytes[1]):
        if log:
            log(f"  block {seq}: CRC mismatch")
        return None
    if seq_complement != (0xFF - seq):
        if log:
            log(f"  block {seq}: bad sequence complement 0x{seq_complement:02X}")
        return None
    return seq, payload


def _consume_ymodem_batch_end(
    stream: _ByteStream, write: WriteFn, timeout: float, log: LogFn
) -> None:
    """Acknowledge the YMODEM end-of-batch null header.

    After a file's EOT, a YMODEM sender expects one more ``C`` and then sends a
    final all-zero header block to close the batch. Consuming and ACKing it
    here leaves the connection clean for the next command -- otherwise the
    stale block is mistaken for the *next* file's (empty) header.
    """
    write(bytes([CRC_C]))
    tail = stream.read_frame_start(timeout=min(timeout, 3.0))
    if tail in (SOH, STX):
        _read_block(stream, 128 if tail == SOH else 1024, timeout)
        write(bytes([ACK]))
        log("  YMODEM batch closed")


def _await_transfer_start(
    stream: _ByteStream, write: WriteFn, retries: int, timeout: float, log: LogFn
) -> int:
    """Send ``C`` until the relay emits its first framing byte.

    Returns that framing byte, or raises :class:`XmodemError` if the relay
    never begins sending.
    """
    for attempt in range(1, retries + 1):
        write(bytes([CRC_C]))
        start = stream.read_frame_start(timeout=timeout)
        if start is not None:
            return start
        log(f"  waiting for relay to start transfer ({attempt}/{retries})")
    raise XmodemError("relay never started the transfer (no XMODEM frame)")


def receive_file(
    read: ReadFn,
    write: WriteFn,
    *,
    log: LogFn | None = None,
    start_retries: int = 15,
    start_timeout: float = 3.0,
    block_timeout: float = 10.0,
) -> tuple[str | None, bytes]:
    """Receive one file from a SEL relay over XMODEM or YMODEM.

    Args:
        read: Callback returning bytes available within a timeout.
        write: Callback that sends handshake bytes to the relay.
        log: Optional sink for human-readable progress lines.
        start_retries: How many times to send ``C`` while waiting for the
            relay to begin sending.
        start_timeout: Seconds to wait per ``C`` attempt before retrying.
        block_timeout: Per-block read timeout once the transfer is underway.

    Returns:
        ``(filename, data)``. ``filename`` is populated only for YMODEM
        transfers; ``data`` is the exact file content.

    Raises:
        XmodemError: If the transfer cannot be completed.
    """

    def _log(msg: str) -> None:
        if log is not None:
            log(msg)

    stream = _ByteStream(read)
    start = _await_transfer_start(stream, write, start_retries, start_timeout, _log)

    data = bytearray()
    filename: str | None = None
    filesize: int | None = None
    is_ymodem = False
    expected_seq = 1  # first *data* block is always sequence 1

    while start != EOT:
        if start == CAN:
            raise XmodemError("transfer cancelled by the relay (CAN)")
        if start not in (SOH, STX):  # pragma: no cover -- frame starts only
            raise XmodemError(f"unexpected framing byte 0x{start:02X}")

        block = _read_block(stream, 128 if start == SOH else 1024, block_timeout, _log)
        if block is None:
            write(bytes([NAK]))
        elif block[0] == 0 and not data and not is_ymodem:
            # YMODEM batch header block carries the name and exact size.
            is_ymodem = True
            filename, filesize = _parse_ymodem_header(block[1])
            _log(f"  YMODEM header: name={filename!r} size={filesize}")
            write(bytes([ACK]))
            if not filename:
                return filename, b""  # empty header -- end of batch
            write(bytes([CRC_C]))  # request the data phase
        elif block[0] == (expected_seq & 0xFF):
            data.extend(block[1])
            write(bytes([ACK]))
            expected_seq += 1
        elif block[0] == ((expected_seq - 1) & 0xFF):
            write(bytes([ACK]))  # sender missed our ACK and resent -- re-ACK
        else:
            raise XmodemError(
                f"block sequence error: got {block[0]}, "
                f"expected {expected_seq & 0xFF}"
            )

        next_start = stream.read_frame_start(timeout=block_timeout)
        if next_start is None:
            raise XmodemError("transfer stalled mid-stream")
        start = next_start

    write(bytes([ACK]))  # acknowledge EOT
    _log("  EOT received, transfer complete")

    # A YMODEM sender closes the batch with one more (empty) header block.
    # Consume it so the connection is clean for the next command.
    if is_ymodem:
        _consume_ymodem_batch_end(stream, write, block_timeout, _log)

    # Trim padding: YMODEM gives an exact length; XMODEM pads with SUB.
    if is_ymodem and filesize is not None:
        return filename, bytes(data[:filesize])
    return filename, bytes(data).rstrip(bytes([SUB]))
