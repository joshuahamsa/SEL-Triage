"""Unit tests for :mod:`sel_triage.integrations.devices.sel.settings.xmodem` (ported from SEL-Audit).

The XMODEM/YMODEM receiver is exercised against :class:`FakeRelay`, a scripted
in-memory sender that responds to the receiver's ``C``/``ACK``/``NAK`` exactly
as a real SEL relay would. Run from the repository root with::

    python -m unittest discover -s tests
"""

import unittest

from sel_triage.integrations.devices.sel.settings.xmodem import (
    ACK,
    CRC_C,
    EOT,
    NAK,
    SOH,
    STX,
    SUB,
    XmodemError,
    _crc16_xmodem,
    _parse_ymodem_header,
    receive_file,
)


def _make_block(seq: int, payload: bytes, block_size: int, *, pad: int = SUB) -> bytes:
    """Build one CRC-mode XMODEM/YMODEM frame for ``payload``."""
    body = payload + bytes([pad]) * (block_size - len(payload))
    start = SOH if block_size == 128 else STX
    crc = _crc16_xmodem(body)
    return bytes([start, seq & 0xFF, 0xFF - (seq & 0xFF)]) + body + bytes([crc >> 8, crc & 0xFF])


def _xmodem_frames(data: bytes, block_size: int = 128) -> list[bytes]:
    """Split ``data`` into XMODEM data frames followed by an EOT frame."""
    frames = []
    for i in range(0, max(len(data), 1), block_size):
        seq = i // block_size + 1
        frames.append(_make_block(seq, data[i : i + block_size], block_size))
    frames.append(bytes([EOT]))
    return frames


def _ymodem_frames(name: str, data: bytes, block_size: int = 1024) -> list[bytes]:
    """Build a full YMODEM batch: header, data frames, EOT, end-of-batch header."""
    header = name.encode("ascii") + b"\x00" + str(len(data)).encode("ascii") + b"\x00"
    frames = [_make_block(0, header, 128, pad=0x00)]
    for i in range(0, len(data), block_size):
        frames.append(_make_block(i // block_size + 1, data[i : i + block_size], block_size))
    frames.append(bytes([EOT]))
    frames.append(_make_block(0, b"", 128, pad=0x00))  # end-of-batch null header
    return frames


class FakeRelay:
    """Scripted XMODEM/YMODEM sender driven by the receiver's control bytes."""

    def __init__(self, frames: list[bytes], *, ymodem: bool = False,
                 corrupt_once: set[int] | None = None, preamble: bytes = b"") -> None:
        self.frames = frames
        self.ymodem = ymodem
        self.corrupt_once = corrupt_once or set()
        self.preamble = preamble
        self._corrupted: set[int] = set()
        self._idx = 0
        self._started = False
        self._expect_c = False
        self._out = bytearray()

    def _emit(self) -> None:
        """Queue the next frame for delivery to the receiver."""
        if self._idx >= len(self.frames):
            return
        frame = self.frames[self._idx]
        if self._idx in self.corrupt_once and self._idx not in self._corrupted:
            self._corrupted.add(self._idx)
            frame = frame[:-1] + bytes([frame[-1] ^ 0xFF])  # break the CRC
        self._out.extend(frame)
        self._idx += 1
        # After a YMODEM header block the receiver replies ACK then C.
        if self.ymodem and self._idx == 1:
            self._expect_c = True

    def write(self, data: bytes) -> None:
        """Consume control bytes the receiver sends back."""
        for byte in data:
            if self._expect_c:
                if byte == CRC_C:
                    self._expect_c = False
                    self._emit()
                continue
            if not self._started:
                if byte in (CRC_C, NAK):
                    self._started = True
                    self._out.extend(self.preamble)  # relay echo / banner noise
                    self._emit()
                continue
            if byte == ACK:
                self._emit()
            elif byte == NAK and self._idx > 0:
                self._idx -= 1  # resend the frame that was rejected
                self._emit()

    def read(self, _timeout: float) -> bytes:
        """Return queued bytes for the receiver (timeout is irrelevant here)."""
        chunk = bytes(self._out)
        self._out.clear()
        return chunk


class Crc16Tests(unittest.TestCase):
    """The CRC-16/XMODEM implementation."""

    def test_known_check_value(self):
        """CRC-16/XMODEM of ``b"123456789"`` is the standard 0x31C3."""
        self.assertEqual(_crc16_xmodem(b"123456789"), 0x31C3)


class YmodemHeaderTests(unittest.TestCase):
    """Parsing of the YMODEM block-0 header."""

    def test_filename_and_size_are_extracted(self):
        """``name\\0size\\0`` yields the file name and exact byte size."""
        name, size = _parse_ymodem_header(b"set_1.txt\x008294\x00\x00\x00")
        self.assertEqual((name, size), ("set_1.txt", 8294))

    def test_empty_header_marks_end_of_batch(self):
        """An all-NUL header reports no file."""
        self.assertEqual(_parse_ymodem_header(b"\x00" * 128), ("", None))


class XmodemReceiveTests(unittest.TestCase):
    """Receiving plain XMODEM transfers."""

    def test_single_block_padding_is_trimmed(self):
        """A short final block padded with SUB is restored to exact content."""
        payload = b'RID,"SEL-751"\x1c\r\n'
        relay = FakeRelay(_xmodem_frames(payload))
        _name, data = receive_file(relay.read, relay.write, block_timeout=2.0)
        self.assertEqual(data, payload)

    def test_multi_block_transfer_is_reassembled(self):
        """Data spanning several 128-byte blocks is concatenated in order."""
        payload = bytes(range(256)) * 3  # 768 bytes -> 6 blocks
        # Avoid trailing SUB bytes being trimmed as padding.
        payload = payload.rstrip(bytes([SUB])) or payload
        relay = FakeRelay(_xmodem_frames(payload))
        _name, data = receive_file(relay.read, relay.write, block_timeout=2.0)
        self.assertEqual(data, payload)

    def test_bad_crc_triggers_nak_and_resend(self):
        """A corrupt block is NAK'd and the relay's resend is accepted."""
        payload = b"hello relay settings"
        relay = FakeRelay(_xmodem_frames(payload), corrupt_once={0})
        _name, data = receive_file(relay.read, relay.write, block_timeout=2.0)
        self.assertEqual(data, payload)

    def test_relay_command_framing_stx_is_not_mistaken_for_a_block(self):
        """A stray STX in the relay's command framing is skipped, not parsed.

        SEL relays wrap command output in STX (0x02) / ETX (0x03). STX is also
        the XMODEM 1024-byte block marker, so the receiver must validate the
        sequence pair before committing to a block.
        """
        payload = b"real settings payload"
        preamble = b"\x02\r\nReady to send file\x03\r\n"
        relay = FakeRelay(_xmodem_frames(payload), preamble=preamble)
        _name, data = receive_file(relay.read, relay.write, block_timeout=2.0)
        self.assertEqual(data, payload)

    def test_transfer_that_never_starts_raises(self):
        """If the relay sends nothing, the receiver gives up cleanly."""
        silent = FakeRelay([])  # never started, emits nothing
        with self.assertRaises(XmodemError):
            receive_file(
                silent.read, silent.write, start_retries=2, start_timeout=0.2
            )


class YmodemReceiveTests(unittest.TestCase):
    """Receiving YMODEM transfers (the variant QuickSet uses)."""

    def test_header_size_trims_the_file_exactly(self):
        """A 1024-block YMODEM transfer is trimmed to the header's byte size."""
        payload = b"X" * 1500  # spans two 1024-byte blocks
        relay = FakeRelay(_ymodem_frames("set_G.txt", payload), ymodem=True)
        name, data = receive_file(relay.read, relay.write, block_timeout=2.0)
        self.assertEqual(name, "set_G.txt")
        self.assertEqual(data, payload)
        self.assertEqual(len(data), 1500)

    def test_end_of_batch_header_is_consumed(self):
        """The YMODEM end-of-batch header is drained, leaving a clean stream.

        Without this the stale header is mistaken for the next file's (empty)
        header -- the off-by-one seen in the first live test.
        """
        relay = FakeRelay(_ymodem_frames("set_R.txt", b"settings"), ymodem=True)
        receive_file(relay.read, relay.write, block_timeout=2.0)
        self.assertEqual(relay._idx, len(relay.frames))  # every frame sent
        self.assertEqual(bytes(relay._out), b"")  # nothing left buffered


if __name__ == "__main__":
    unittest.main()
