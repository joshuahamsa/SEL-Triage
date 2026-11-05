from pathlib import Path
import socket
import unittest
from unittest import mock

from sel_triage.core.errors import TriageError
from sel_triage.integrations.devices.sel import client as sel_client_module
from sel_triage.integrations.devices.sel.client import SelClient
from sel_triage.transports.telnet import TelnetRead, TelnetTransport


FIXTURES = Path(__file__).parent / "fixtures" / "sel"


class ScriptedTransport:
    def __init__(self, reads):
        self.reads = list(reads)
        self.writes = []
        self.connect_calls = 0
        self.close_calls = 0
        self.read_limits = []
        self.read_timeouts = []
        self.read_timeout = 120
        self.returned_reads = []
        self.transcript = b"".join(
            item.data for item in self.reads if isinstance(item, TelnetRead)
        )

    def connect(self):
        self.connect_calls += 1

    def write_line(self, text):
        self.writes.append(text)

    def read_until(self, prompts, max_bytes=None, line_prompts=()):
        self.read_limits.append(max_bytes)
        self.read_timeouts.append(self.read_timeout)
        if not self.reads:
            raise AssertionError("unexpected read")
        item = self.reads.pop(0)
        if isinstance(item, BaseException):
            raise item
        if item.matched not in prompts:
            raise AssertionError(
                "scripted prompt {0!r} was not requested in {1!r}".format(
                    item.matched, prompts
                )
            )
        if max_bytes is not None and len(item.data) > max_bytes:
            raise TriageError(
                "Telnet response exceeded the byte limit",
                category="response_too_large",
                reachable=True,
            )
        self.returned_reads.append(item)
        return item

    def close(self):
        self.close_calls += 1


class PasswordWriteFailureSocket:
    def __init__(self):
        self.chunks = [
            b"SEL SYNTHETIC\r\n=",
            socket.timeout("quiet prompt settle"),
            b"Password:",
        ]
        self.sent = []
        self.send_calls = 0
        self.closed = False

    def recv(self, size):
        value = self.chunks.pop(0) if self.chunks else b""
        if isinstance(value, BaseException):
            raise value
        if len(value) > size:
            self.chunks.insert(0, value[size:])
            return value[:size]
        return value

    def sendall(self, data):
        self.send_calls += 1
        if self.send_calls == 2:
            raise OSError("synthetic write failure")
        self.sent.append(data)

    def settimeout(self, value):
        pass

    def close(self):
        self.closed = True


def telnet_read(data, matched):
    return TelnetRead(data=data, matched=matched, elapsed_seconds=0.01)


def successful_reads(identity=None):
    if identity is None:
        identity = (
            b'ID\r\n"FID=SEL-700GT-R100-V0-Z001001-D20260101","A1B2"\r\n'
            b'"DEVID=LAB-RELAY-01","C3D4"\r\n=>'
        )
    return [
        telnet_read(b"SEL SYNTHETIC\r\n=", b"="),
        telnet_read(b"Password:", b"Password:"),
        telnet_read(b"=>", b"=>"),
        telnet_read(identity, b"=>"),
    ]


def contains_secret(value, secret, seen=None):
    if seen is None:
        seen = set()
    if id(value) in seen:
        return False
    seen.add(id(value))
    if isinstance(value, bytes):
        return secret.encode() in value
    if isinstance(value, str):
        return secret in value
    if isinstance(value, dict):
        return any(
            contains_secret(item, secret, seen)
            for pair in value.items()
            for item in pair
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_secret(item, secret, seen) for item in value)
    return secret in repr(value)


def sel_triage_traceback_locals(error):
    frame_locals = []
    seen_errors = set()
    while error is not None and id(error) not in seen_errors:
        seen_errors.add(id(error))
        traceback = error.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            module_name = frame.f_globals.get("__name__", "")
            if module_name == "sel_triage" or module_name.startswith(
                "sel_triage."
            ):
                frame_locals.append(dict(frame.f_locals))
            traceback = traceback.tb_next
        error = error.__cause__ or error.__context__
    return frame_locals


class TestSelClient(unittest.TestCase):
    def test_multiline_password_is_rejected_before_connect_without_traceback_leak(self):
        for suffix in ("\r2AC", "\n2AC", "\r\n2AC"):
            with self.subTest(suffix=repr(suffix)):
                secret = "UNIQUE-LINE-SECRET-9812ca" + suffix
                transport = ScriptedTransport(successful_reads())
                client = SelClient(transport)

                try:
                    client.login(secret)
                except TriageError as error:
                    self.assertEqual(error.category, "invalid_secret")
                    self.assertFalse(contains_secret(error.as_dict(), secret))
                    for local_values in sel_triage_traceback_locals(error):
                        self.assertFalse(contains_secret(local_values, secret))
                else:
                    self.fail("TriageError not raised")

                self.assertEqual(transport.connect_calls, 0)
                self.assertEqual(transport.writes, [])
                self.assertEqual(client.state, "NEW")

    def test_unknown_model_status_is_unavailable_without_transport_write(self):
        # Unknown models use the generic family, which only allows ID and HELP.
        identity = (
            b'ID\r\n"FID=SEL-2440-R100-V0-Z001001-D20240101","089F"\r\n'
            b'"DEVID=LAB-RELAY-01","C3D4"\r\n=>'
        )
        transport = ScriptedTransport(successful_reads(identity))
        client = SelClient(transport)
        client.login("synthetic-password")
        writes_before = list(transport.writes)

        with self.assertRaisesRegex(TriageError, "command_unavailable") as raised:
            client.run("status")

        self.assertEqual(raised.exception.category, "command_unavailable")
        self.assertEqual(transport.writes, writes_before)

    def test_651_uncaptured_target_command_is_unavailable_without_writes(self):
        identity = (
            b'ID\r\n"FID=SEL-651R-2-R411-V1-Z011003-D20211018","0953"\r\n'
            b'"DEVID=LAB-RECLOSER-01","C3D4"\r\n=>'
        )
        transport = ScriptedTransport(successful_reads(identity))
        client = SelClient(transport)
        client.login("synthetic-password")
        writes_before = list(transport.writes)

        for capability in ("target",):
            with self.subTest(capability=capability):
                with self.assertRaisesRegex(
                    TriageError, "command_unavailable"
                ) as raised:
                    client.run(capability)
                self.assertEqual(raised.exception.category, "command_unavailable")
                self.assertEqual(transport.writes, writes_before)

    def test_700g_event_and_settings_recipes_are_library_owned(self):
        for capability, argument, wire in (
            ("ser", None, "SER"),
            ("eve", 1, "EVE 1"),
            ("cev", 3, "CEV 3"),
            ("settings_global", None, "SHO G"),
            ("settings_group", None, "SHO"),
            ("settings_logic", None, "SHO L"),
            ("settings_report", None, "SHO R"),
        ):
            with self.subTest(capability=capability):
                payload = "{0}\r\nsynthetic\r\n=>".format(wire).encode()
                transport = ScriptedTransport(
                    successful_reads() + [telnet_read(payload, b"=>")]
                )
                client = SelClient(transport)
                client.login("synthetic-password")

                self.assertEqual(client.run_bytes(capability, argument), payload)
                self.assertEqual(transport.writes[-1], wire)

    def test_700g_settings_recipes_reject_arguments(self):
        transport = ScriptedTransport(successful_reads())
        client = SelClient(transport)
        client.login("synthetic-password")
        writes_before = list(transport.writes)

        for argument in (1, "1", "G; SET"):
            with self.subTest(argument=argument):
                with self.assertRaises(ValueError):
                    client.run_bytes("settings_group", argument)
                self.assertEqual(transport.writes, writes_before)

    def test_651_event_recipe_accepts_only_a_positive_integer_argument(self):
        identity = (
            b'ID\r\n"FID=SEL-651R-2-R411-V1-Z011003-D20211018","0953"\r\n'
            b'"DEVID=LAB-RECLOSER-01","C3D4"\r\n=>'
        )
        payload = b"EVE 1\r\nEvent Number = 10260\r\n=>"
        transport = ScriptedTransport(
            successful_reads(identity) + [telnet_read(payload, b"=>")]
        )
        client = SelClient(transport)
        client.login("synthetic-password")

        result = client.run_bytes("eve", 1)

        self.assertEqual(result, payload)
        self.assertEqual(transport.writes[-1], "EVE 1")
        command = client._command_for("eve")
        self.assertEqual(transport.read_limits[-1], command.max_bytes)
        self.assertEqual(transport.read_timeouts[-1], command.max_seconds)
        self.assertEqual(transport.read_timeout, 120)

        writes_before = list(transport.writes)
        class FormattedInteger(int):
            def __format__(self, format_spec):
                return "1\r\nSET 1"

        for invalid in (None, True, 0, -1, "1", "1; SET 1", FormattedInteger(1)):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    client.run_bytes("eve", invalid)
                self.assertEqual(transport.writes, writes_before)

    def test_command_seconds_can_raise_the_per_command_deadline(self):
        transport = ScriptedTransport(
            successful_reads() + [telnet_read(b"SER\r\n=>", b"=>")]
        )
        client = SelClient(transport, command_seconds=150)
        client.login("synthetic-password")

        client.run_bytes("ser")

        self.assertEqual(transport.read_timeouts[-1], 120)  # still capped by the transport
        transport.read_timeout = 200
        transport.reads.append(telnet_read(b"SER\r\n=>", b"=>"))
        client.run_bytes("ser")
        self.assertEqual(transport.read_timeouts[-1], 150)

    def test_command_seconds_is_bounded(self):
        for bad in (0, -1, 301, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    SelClient(ScriptedTransport([]), command_seconds=bad)

    def test_651_raw_cev_recipe_is_library_owned(self):
        identity = (
            b'ID\r\n"FID=SEL-651R-2-R411-V1-Z011003-D20211018","0953"\r\n'
            b'"DEVID=LAB-RECLOSER-01","C3D4"\r\n=>'
        )
        payload = b"CEV R 2\r\n\x02binary\r\n=>"
        transport = ScriptedTransport(
            successful_reads(identity) + [telnet_read(payload, b"=>")]
        )
        client = SelClient(transport)
        client.login("synthetic-password")

        self.assertEqual(client.run_bytes("cev_raw", 2), payload)
        self.assertEqual(transport.writes[-1], "CEV R 2")

    def test_sanitized_login_fixture_contains_no_secret_or_live_address(self):
        fixture = (FIXTURES / "700gt-login.txt").read_text()

        self.assertIn("SEL-700GT", fixture)
        self.assertIn("LAB-RELAY-01", fixture)
        self.assertNotIn("203.0.113.", fixture)
        self.assertNotRegex(fixture, r"(?im)^password:[^\r\n]*\S")

    def test_login_reaches_access1_and_normalizes_identity(self):
        transport = ScriptedTransport(successful_reads())
        client = SelClient(transport)

        identity = client.login("synthetic-password")

        self.assertEqual(transport.connect_calls, 1)
        self.assertEqual(
            transport.writes,
            ["ACC", "synthetic-password", "ID"],
        )
        self.assertEqual(client.state, "ACCESS1")
        self.assertEqual(client.family, "sel700g")
        self.assertEqual(identity.observed_model, "SEL-700GT")
        self.assertEqual(identity.model, "SEL-700GT")
        self.assertEqual(identity.device_id, "LAB-RELAY-01")
        self.assertTrue(identity.firmware_id.startswith("SEL-700GT-"))
        self.assertEqual(identity.identifiers["DEVID"], "LAB-RELAY-01")

    def test_login_wakes_terminal_server_with_bare_return(self):
        # A serial terminal server shows a banner but no relay prompt until a
        # carriage return is sent.
        quiet = TriageError("Telnet read deadline expired", category="transport_timeout", reachable=True)
        transport = ScriptedTransport([quiet] + successful_reads())
        client = SelClient(transport)

        identity = client.login("synthetic-password")

        self.assertEqual(transport.writes, ["", "ACC", "synthetic-password", "ID"])
        self.assertEqual(identity.observed_model, "SEL-700GT")
        self.assertEqual(transport.read_timeouts[0], sel_client_module.WAKE_AFTER_SECONDS)
        self.assertEqual(transport.read_timeouts[1], 120)
        self.assertEqual(transport.read_timeout, 120)

    def test_text_output_drops_sel_stx_etx_framing(self):
        framed = (
            b'\x03\x02ID\r\n"FID=SEL-700G-R302-V1-Z008004-D20240329","08F1"\r\n'
            b'"DEVID=SEL-700GT","045C"\r\n\x02=>'
        )
        transport = ScriptedTransport(successful_reads(framed))
        client = SelClient(transport)

        identity = client.login("synthetic-password")

        self.assertEqual(identity.observed_model, "SEL-700G")
        self.assertEqual(identity.device_id, "SEL-700GT")
        self.assertNotIn("\x02", identity.raw_text)
        self.assertNotIn("\x03", identity.raw_text)

    def test_login_does_not_wake_when_prompt_arrives(self):
        transport = ScriptedTransport(successful_reads())
        SelClient(transport).login("synthetic-password")
        self.assertNotIn("", transport.writes)
        self.assertEqual(transport.read_timeout, 120)

    def test_login_still_times_out_if_wake_gets_no_prompt(self):
        quiet = TriageError("Telnet read deadline expired", category="transport_timeout", reachable=True)
        transport = ScriptedTransport([quiet, quiet])
        with self.assertRaises(TriageError) as ctx:
            SelClient(transport).login("synthetic-password")
        self.assertEqual(ctx.exception.category, "transport_timeout")
        self.assertEqual(transport.writes, [""])

    def test_identity_source_is_redacted_before_normalization_and_storage(self):
        secret = "identity-secret-fingerprint-sentinel"
        identity_source = (
            b'ID\r\n"FID=SEL-700GT-R100-V0-Z001001-D20260101","A1B2"\r\n'
            b'"DEVID=LAB-RELAY-01","C3D4"\r\nNOTE='
            + secret.encode("utf-8")
            + b"\r\n=>"
        )
        transport = ScriptedTransport(successful_reads(identity_source))
        client = SelClient(transport)
        normalized_inputs = []
        normalize = sel_client_module._normalize_identity

        def capture(raw_text):
            normalized_inputs.append(raw_text)
            return normalize(raw_text)

        with mock.patch.object(
            sel_client_module, "_normalize_identity", side_effect=capture
        ):
            identity = client.login(secret)

        self.assertEqual(len(normalized_inputs), 1)
        self.assertNotIn(secret, normalized_inputs[0])
        self.assertIn("[REDACTED]", normalized_inputs[0])
        self.assertNotIn(secret, identity.raw_text)
        self.assertNotIn(secret, client.identity.raw_text)

    def test_client_rejects_unknown_capability_without_writing(self):
        transport = ScriptedTransport([])
        client = SelClient(transport)

        with self.assertRaisesRegex(TriageError, "unsupported capability"):
            client.run("raw:SET 1")

        self.assertEqual(transport.writes, [])

    def test_known_capability_requires_access1_without_writing(self):
        transport = ScriptedTransport([])
        client = SelClient(transport)

        with self.assertRaisesRegex(TriageError, "ACCESS1"):
            client.run("identity")

        self.assertEqual(transport.writes, [])

    def test_run_dispatches_only_family_allowlisted_wire_text(self):
        transport = ScriptedTransport(
            successful_reads()
            + [telnet_read(b"MET\r\nIA=1.0\r\n=>", b"=>")]
        )
        client = SelClient(transport)
        client.login("synthetic-password")

        response = client.run("meter")

        self.assertEqual(transport.writes[-1], "MET")
        self.assertEqual(response, "MET\r\nIA=1.0\r\n=>")

    def test_private_dispatch_outer_and_family_mappings_are_immutable(self):
        with self.assertRaises(TypeError):
            sel_client_module._COMMAND_POLICY["generic"] = {}
        with self.assertRaises(TypeError):
            sel_client_module._COMMAND_POLICY["generic"]["identity"] = None

    def test_run_prompt_failure_closes_transport(self):
        transport = ScriptedTransport(successful_reads())
        client = SelClient(transport)
        client.login("synthetic-password")
        transport.reads.append(
            TriageError(
                "Telnet read deadline expired",
                category="transport_timeout",
                reachable=True,
            )
        )

        with self.assertRaises(TriageError) as raised:
            client.run("meter")

        self.assertEqual(raised.exception.category, "transport_timeout")
        self.assertEqual(client.state, "CLOSED")
        self.assertEqual(transport.close_calls, 1)

    def test_command_response_is_limited_by_policy(self):
        transport = ScriptedTransport(successful_reads())
        client = SelClient(transport)
        client.login("synthetic-password")
        command = client._command_for("identity")
        transport.reads.append(
            telnet_read(b"x" * (command.max_bytes + 1) + b"=>", b"=>")
        )

        with self.assertRaisesRegex(TriageError, "byte limit") as raised:
            client.run("identity")

        self.assertEqual(raised.exception.category, "response_too_large")
        self.assertEqual(client.state, "CLOSED")
        self.assertEqual(transport.read_limits[-1], command.max_bytes)
        self.assertEqual(len(transport.returned_reads), 4)

    def test_failed_auth_closes_and_does_not_leak_password(self):
        secret = "UNIQUE-SEL-SECRET-7f928a"  # gitleaks:allow (test sentinel, not a credential)
        transport = ScriptedTransport(
            [
                telnet_read(b"SEL SYNTHETIC\r\n=", b"="),
                telnet_read(b"Password:", b"Password:"),
                telnet_read(b"Invalid Access\r\nPassword:", b"Password:"),
            ]
        )
        client = SelClient(transport)

        try:
            client.login(secret)
        except TriageError as error:
            error_dictionary = error.as_dict()
            self.assertFalse(contains_secret(error_dictionary, secret))
            traceback = error.__traceback__
            client_frames = []
            while traceback is not None:
                frame = traceback.tb_frame
                if frame.f_globals.get("__name__") == sel_client_module.__name__:
                    client_frames.append(dict(frame.f_locals))
                traceback = traceback.tb_next
            self.assertTrue(client_frames)
            for frame_locals in client_frames:
                self.assertFalse(contains_secret(frame_locals, secret))
            self.assertEqual(error.category, "authentication_failed")
        else:
            self.fail("TriageError not raised")

        self.assertNotIn(secret.encode(), transport.transcript)
        self.assertNotIn(secret, repr(client))
        self.assertNotIn(secret, repr(client.__dict__))
        self.assertEqual(client.state, "CLOSED")
        self.assertEqual(transport.close_calls, 1)

    def test_password_write_failure_clears_all_production_traceback_locals(self):
        secret = "UNIQUE-WRITE-SECRET-9812ca"
        sock = PasswordWriteFailureSocket()
        transport = TelnetTransport(
            "192.0.2.10",
            23,
            socket_factory=lambda *args, **kwargs: sock,
        )
        client = SelClient(transport)

        try:
            client.login(secret)
        except TriageError as error:
            frame_locals = sel_triage_traceback_locals(error)
            self.assertTrue(frame_locals)
            for local_values in frame_locals:
                self.assertFalse(contains_secret(local_values, secret))
            self.assertFalse(contains_secret(error.as_dict(), secret))
            self.assertEqual(str(error), "Telnet write failed")
            self.assertEqual(error.category, "route_or_tcp")
        else:
            self.fail("TriageError not raised")

        self.assertEqual(client.state, "CLOSED")
        self.assertNotIn(secret.encode(), transport.transcript)
        self.assertNotIn(secret, repr(client))
        self.assertTrue(sock.closed)

    def test_prompt_failure_closes_transport(self):
        quiet = TriageError(
            "Telnet read deadline expired",
            category="transport_timeout",
            reachable=True,
        )
        # Initial wait, then the wait after the bare-return wake.
        transport = ScriptedTransport([quiet, quiet])
        client = SelClient(transport)

        with self.assertRaises(TriageError) as raised:
            client.login("synthetic-password")

        self.assertEqual(raised.exception.category, "transport_timeout")
        self.assertEqual(client.state, "CLOSED")
        self.assertEqual(transport.close_calls, 1)

    def test_unrecognized_identity_fails_closed(self):
        transport = ScriptedTransport(
            successful_reads(b'ID\r\n"DEVID=LAB-RELAY-01","C3D4"\r\n=>')
        )
        client = SelClient(transport)

        with self.assertRaisesRegex(TriageError, "identity") as raised:
            client.login("synthetic-password")

        self.assertEqual(raised.exception.category, "invalid_identity")
        self.assertEqual(client.state, "CLOSED")
        self.assertEqual(transport.close_calls, 1)

    def test_valid_unknown_sel_model_reaches_generic_identity_without_probing(self):
        identity = (
            b'ID\r\n"FID=SEL-487E-R100-V0-Z001001-D20260101","A1B2"\r\n'
            b'"DEVID=LAB-RELAY-UNKNOWN","C3D4"\r\n=>'
        )
        transport = ScriptedTransport(successful_reads(identity))
        client = SelClient(transport)

        observed = client.login("synthetic-password")

        self.assertEqual(observed.observed_model, "SEL-487E")
        self.assertEqual(client.family, "generic")
        self.assertEqual(
            transport.writes,
            ["ACC", "synthetic-password", "ID"],
        )

    def test_logout_closes_without_sending_another_command(self):
        transport = ScriptedTransport(successful_reads())
        client = SelClient(transport)
        client.login("synthetic-password")
        writes_before_logout = list(transport.writes)

        client.logout()
        client.logout()

        self.assertEqual(client.state, "CLOSED")
        self.assertEqual(transport.writes, writes_before_logout)
        self.assertEqual(transport.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
