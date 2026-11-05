"""SelClient FILE READ (XMODEM/YMODEM receive) and FILE SHOW, against scripted transports."""

import unittest

from sel_triage.core.errors import TriageError
from sel_triage.integrations.devices.sel.client import SelClient
from sel_triage.integrations.devices.sel.settings.xmodem import (
    ACK,
    CRC_C,
    EOT,
    SOH,
    SUB,
    _crc16_xmodem,
)
from tests.test_sel_client import ScriptedTransport, successful_reads, telnet_read

QUIET = TriageError("Telnet read deadline expired", category="transport_timeout", reachable=True)


def _block(seq, payload, size=128):
    body = payload + bytes([SUB]) * (size - len(payload))
    crc = _crc16_xmodem(body)
    return bytes([SOH, seq & 0xFF, 0xFF - (seq & 0xFF)]) + body + bytes([crc >> 8, crc & 0xFF])


class RawTransport(ScriptedTransport):
    """Adds the binary side: scripted raw chunks and recorded control bytes."""

    def __init__(self, reads, raw_chunks):
        super().__init__(reads)
        self.raw_chunks = list(raw_chunks)
        self.controls = []

    def read_raw(self, timeout):
        return self.raw_chunks.pop(0) if self.raw_chunks else b""

    def write_control(self, data):
        self.controls.append(data)


def _logged_in(raw_chunks, after=(), identity=None):
    transport = RawTransport(successful_reads(identity) + list(after), raw_chunks)
    client = SelClient(transport)
    client.login("synthetic-password")
    return client, transport


class TestFileRead(unittest.TestCase):
    def test_xmodem_file_read_returns_exact_content(self):
        content = b"[CLASSES]\r\n1,\"Group 1\"\r\n"
        client, transport = _logged_in(
            [b"FILE READ CFG.TXT\r\nReady to send file\r\n", _block(1, content), bytes([EOT])],
            after=[telnet_read(b"\x02\r\n=>\x03", b"=>"), telnet_read(b"\r\n=>", b"=>"), QUIET],
        )

        data = client.read_file("CFG.TXT")

        self.assertEqual(data, content)
        # a bare return clears any 'C' left on the command line before the next command
        self.assertEqual(transport.writes[-2:], ["FILE READ CFG.TXT", ""])
        self.assertEqual(transport.reads, [])
        self.assertEqual(transport.controls, [bytes([CRC_C]), bytes([ACK]), bytes([ACK])])
        self.assertEqual(client.state, "ACCESS1")

    def test_failed_transfer_keeps_the_session_for_the_next_file(self):
        client, transport = _logged_in(
            [],
            after=[telnet_read(b"Invalid File Name\r\n=>", b"=>"), QUIET],
        )

        with self.assertRaises(TriageError) as raised:
            client.read_file("SET_HMI.TXT", start_retries=2, start_timeout=0.01)

        self.assertEqual(raised.exception.category, "file_transfer_failed")
        self.assertEqual(client.state, "ACCESS1")
        self.assertEqual(transport.writes[-2:], ["FILE READ SET_HMI.TXT", ""])
        self.assertEqual(transport.close_calls, 0)
        self.assertEqual(transport.controls, [bytes([CRC_C])] * 2)

    def test_late_prompts_are_drained_so_the_next_command_reads_its_own_reply(self):
        # an 851 answered the leftover "C" with its own message and prompt after the flush prompt
        client, transport = _logged_in(
            [],
            after=[telnet_read(b"=>", b"=>"),
                   telnet_read(b'Enter at least three letters of command name.\r\n=>', b"=>"),
                   QUIET,
                   telnet_read(b"HELP\r\nMET  - Display metering data.\r\n=>", b"=>")],
        )
        with self.assertRaises(TriageError):
            client.read_file("SET_HMI.TXT", start_retries=1, start_timeout=0.01)
        self.assertIn(b"Display metering data", client.run_bytes("help"))

    def test_transport_failure_closes_the_session(self):
        client, transport = _logged_in([])
        transport.read_raw = lambda timeout: (_ for _ in ()).throw(
            TriageError("closed", category="transport_eof", reachable=True)
        )

        with self.assertRaises(TriageError) as raised:
            client.read_file("CFG.TXT")

        self.assertEqual(raised.exception.category, "transport_eof")
        self.assertEqual(client.state, "CLOSED")

    def test_invalid_file_names_are_rejected_without_writing(self):
        client, transport = _logged_in([])
        writes = list(transport.writes)
        for bad in ("CFG.TXT\r\nSET", "../CFG.TXT", "SET_1.TXT;SET", "", "PASSWORD.TXT", None, 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    client.read_file(bad)
                with self.assertRaises(ValueError):
                    client.run_bytes("file_show", bad)
        self.assertEqual(transport.writes, writes)
        self.assertEqual(transport.controls, [])

    def test_file_read_requires_access1(self):
        transport = RawTransport([], [])
        client = SelClient(transport)
        with self.assertRaises(TriageError) as raised:
            client.read_file("CFG.TXT")
        self.assertEqual(raised.exception.category, "session_state")
        self.assertEqual(transport.writes, [])


class TestFileShow(unittest.TestCase):
    def test_file_show_is_allowlisted_for_the_735(self):
        identity = (
            b'ID\r\n"FID=SEL-735-R300-V1-Z012003-D20230101","0A0B"\r\n'
            b'"DEVID=LAB-METER-01","C3D4"\r\n=>'
        )
        payload = b"FILE SHOW CFG.TXT\r\n\x02\r\n[CLASSES]\r\n1,\"Group 1\"\r\n\x03\x02\r\n=>\x03"
        client, transport = _logged_in([], after=[telnet_read(payload, b"=>")], identity=identity)

        self.assertEqual(client.family, "sel735")
        self.assertEqual(client.run_bytes("file_show", "CFG.TXT"), payload)
        self.assertEqual(transport.writes[-1], "FILE SHOW CFG.TXT")


if __name__ == "__main__":
    unittest.main()
