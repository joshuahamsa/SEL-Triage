"""RTAC REST API: GET-only allowlist, token handling, pagination, parsers, findings, workflow, CLI.

Responses are synthetic and follow the R146 OpenAPI schemas; no live RTAC has
answered the API yet.
"""

import base64
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock
import urllib.parse

from sel_triage.core.errors import TriageError
from sel_triage.core.inventory import DeviceTarget
from sel_triage.integrations.devices.rtac import api_parsers
from sel_triage.integrations.devices.rtac.api import ENDPOINTS, PAGE_LIMIT, RtacApiClient
from sel_triage.integrations.devices.rtac.api_workflow import run_rtac_api_snapshot
from sel_triage.integrations.devices.rtac.diagnostics import diagnose_rtac_api


TOKEN = "eyJsynthetic.token.value"
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
TARGET = DeviceTarget(name="Lab Site/RTAC", kind="rtac", host="192.0.2.1", port=4443,
                      model_hint=None, credential_ref="rtac/Lab Site", timeout_seconds=30)

ID = {
    "BIOSVersion": "1.0", "SerialNumber": "0000000000", "RemoteOutOfBandManagement": "Disabled",
    "FID": {"Raw": "SEL-3505-3-R146-V0-Z000000-D20250101", "Product": "SEL-3505-3", "Type": "R",
            "Version": {"Major": 146.0, "Minor": 0.0}, "BuildId": "V0", "Date": "2025-01-01"},
    "Firmware": {"Hash": {"SHA256": "00"}}, "Hardware": {"SystemVersion": "1"},
    "LicensedFeatures": [{"Id": "1", "Name": "Logic Engine", "Category": "Base", "Description": "d", "Expired": False}],
}
STATUS = {
    "Online": True, "Enabled": True, "BootTime": "2026-09-01T00:00:00Z", "UpTime": "P42D",
    "Time": {"Value": "2026-10-13T12:00:30Z", "Source": "SNTP", "Accuracy": "1ms"},
    "Project": {"Name": "LAB_PROJECT", "State": "Running", "LastModifiedTimestamp": "2026-08-01T00:00:00Z"},
    "Hardware": {"SelfTests": {"RAM": "Pass", "Flash": {"Primary": "Pass", "Secondary": "Pass"},
                               "NetworkInterfaces": {"Eth_01": "Pass"}},
                 "Temperatures": {"Mainboard": 41.5}, "RTCBatteryVoltage": 3.1},
    "Memory": {"UsedBytes": 250, "AvailableBytes": 750},
    "UsersLoggedIn": [{"Name": "someone", "IsLocal": True}],
}


def alarm(tag, state="Alarmed", ack="Unacknowledged", ts="2026-10-13T08:00:00Z"):
    return {"TagName": tag, "AlarmState": state, "AcknowledgementState": ack, "Timestamp": ts, "Priority": "High",
            "Category": "Comms", "Message": tag + " message", "EventType": state, "EventTotal": 1}


CONNECTIONS = [
    {"Name": "METER_1", "Status": "Online", "Manufacturer": "SEL", "Model": "SEL-735", "Service": "DNP3",
     "Egress": [{"Physical": "Network", "IPAddress": "192.0.2.20", "Port": 20000, "Interfaces": ["Eth_01"]}],
     "MessageCount": {"Status": {"Successes": 900, "Failures": 100}, "Total": {"Sent": 1000, "Received": 900}}},
    {"Name": "RELAY_1", "Status": "Offline", "Manufacturer": "SEL", "Model": "SEL-751", "Service": "Modbus",
     "Egress": [{"Physical": "Serial", "Interface": "COM_03"}]},
    {"Name": "INV_1", "Status": "Online", "Model": "X",
     "MessageCount": {"Status": {"Successes": 1000, "Failures": 1}, "Total": {"Sent": 1001, "Received": 1000}}},
]


class FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self._headers = headers or {}

    def read(self, amount=None):
        return self._body if amount is None else self._body[:amount]

    def getheaders(self):
        return list(self._headers.items())


class FakeServer:
    """Answers /api/v1 GETs from a route table; records every request."""

    def __init__(self, routes=None, token_status=200, fail_connect=False):
        self.routes = dict(routes or {})
        self.token_status = token_status
        self.fail_connect = fail_connect
        self.requests = []

    def factory(self):
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, server):
        self.server = server

    def request(self, method, path, body=None, headers=None):
        if self.server.fail_connect:
            raise OSError("no route")
        self.server.requests.append((method, path, body, dict(headers or {})))
        self.path = path

    def getresponse(self):
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path[len("/api/v1/"):]
        if route == "auth/token":
            if self.server.token_status != 200:
                return FakeResponse(self.server.token_status, {"title": "Unauthorized", "status": 401})
            return FakeResponse(200, {"AccessToken": TOKEN, "TokenType": "Bearer", "ExpiresIn": 3600,
                                      "Scope": "api"})
        answer = self.server.routes.get(route, (404, {"title": "Not Found"}))
        if callable(answer):
            return answer(urllib.parse.parse_qs(parsed.query))
        status, body = answer[:2]
        return FakeResponse(status, body, answer[2] if len(answer) > 2 else None)

    def close(self):
        pass


def full_routes(alarms=None, history=None):
    alarms = alarms if alarms is not None else [alarm("SystemTags.Comms_Fail"), alarm("Old", state="Normalized")]
    return {
        "id": (200, ID),
        "status": (200, STATUS),
        "fingerprint": (200, "AB:CD"),
        "projects/active/connections": (200, CONNECTIONS),
        "projects/active/system-settings": (200, {"StationName": "LAB", "NominalFrequency": 60}),
        "projects": (200, [{"Name": "LAB_PROJECT"}]),
        "logic-engine/symbol-groups": (200, []),
        "alarms": (200, alarms, {"Pagination-Total": str(len(alarms))}),
        "alarms/SystemTags.Comms_Fail/history": (200, history or [
            {"TagName": "SystemTags.Comms_Fail", "EventType": "Alarmed", "AlarmState": "Alarmed",
             "Timestamp": "2026-10-13T08:00:00Z", "Priority": "High", "Message": "m"}]),
        "alarms/Old/history": (200, []),
        "logic-engine/symbols": (200, [{"Name": "g_curtail_pct", "Type": "REAL", "Task": "Main"},
                                       {"Name": "gr_status", "Type": "BOOL", "Task": "Main"}]),
        "logic-engine/symbols/g_curtail_pct": (200, 87.5),
        "logic-engine/symbols/gr_status": (403, {"title": "Forbidden"}),
    }


class ClientTests(unittest.TestCase):
    def make(self, **kwargs):
        self.server = FakeServer(**kwargs)
        return RtacApiClient("192.0.2.1", 4443, connection_factory=self.server.factory)

    def test_token_request_uses_basic_auth_then_bearer(self):
        client = self.make(routes={"id": (200, ID)})
        meta = client.login("labuser", "secret-pw")
        self.assertNotIn("AccessToken", meta)
        self.assertEqual(meta["ExpiresIn"], 3600)
        method, path, body, headers = self.server.requests[0]
        self.assertEqual((method, path, body), ("GET", "/api/v1/auth/token", None))
        self.assertEqual(headers["Authorization"], "Basic " + base64.b64encode(b"labuser:secret-pw").decode())
        self.assertEqual(client.get("id")["SerialNumber"], "0000000000")
        self.assertEqual(self.server.requests[1][3]["Authorization"], "Bearer " + TOKEN)
        self.assertEqual(client.redactions, (TOKEN,))
        client.logout()
        self.assertEqual(client.redactions, ())

    def test_every_request_is_a_get(self):
        client = self.make(routes=full_routes())
        client.login("u", "p")
        for name in ("id", "status", "fingerprint", "connections"):
            client.get(name)
        client.get_all("alarms")
        self.assertEqual({r[0] for r in self.server.requests}, {"GET"})
        self.assertTrue(all(r[2] is None for r in self.server.requests))

    def test_allowlist_has_no_write_or_secret_routes(self):
        paths = " ".join(ENDPOINTS.values()).lower()
        for word in ("command", "password", "vault", "user", "role", "security", "firmware", "auth", "ldap",
                     "certificate", "scd", "configuration"):
            self.assertNotIn(word, paths)
        self.assertNotIn("projects/active", [p for p in ENDPOINTS.values()])
        client = self.make()
        client.login("u", "p")
        for name in ("logic_engine_commands", "password_vault", "users", "active_project"):
            with self.assertRaises(ValueError):
                client.get(name)

    def test_the_client_module_contains_no_other_http_method(self):
        source = (Path(__file__).parent.parent / "sel_triage/integrations/devices/rtac/api.py").read_text()
        code = re.sub(r'"""[\s\S]*?"""', "", source)
        self.assertIsNone(re.search(r"\b(POST|PUT|PATCH|DELETE)\b", code))

    def test_path_values_are_quoted_as_one_segment(self):
        client = self.make(routes={"logic-engine/symbols/a%2Fb%20c": (200, 1)})
        client.login("u", "p")
        self.assertEqual(client.get("symbol", symbol="a/b c"), 1)
        self.assertEqual(self.server.requests[-1][1], "/api/v1/logic-engine/symbols/a%2Fb%20c")

    def test_refused_token_is_authentication_failed_once(self):
        client = self.make(token_status=401)
        with self.assertRaises(TriageError) as ctx:
            client.login("u", "wrong")
        self.assertEqual(ctx.exception.category, "authentication_failed")
        self.assertIn("API Login", str(ctx.exception))
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(client.redactions, ())

    def test_status_codes_map_to_categories(self):
        client = self.make(routes={"id": (403, {}), "status": (404, {}), "fingerprint": (401, {}),
                                   "ports": (500, {})})
        client.login("u", "p")
        for name, category in (("id", "permission_denied"), ("status", "not_found"),
                               ("fingerprint", "token_rejected"), ("ports", "rtac_http_error")):
            with self.assertRaises(TriageError) as ctx:
                client.get(name)
            self.assertEqual(ctx.exception.category, category)

    def test_get_before_login_is_refused_without_a_request(self):
        client = self.make()
        with self.assertRaises(TriageError) as ctx:
            client.get("id")
        self.assertEqual(ctx.exception.category, "session_state")
        self.assertEqual(self.server.requests, [])

    def test_unreachable_is_route_or_tcp(self):
        client = self.make(fail_connect=True)
        with self.assertRaises(TriageError) as ctx:
            client.login("u", "p")
        self.assertEqual((ctx.exception.category, ctx.exception.reachable), ("route_or_tcp", False))

    def test_pagination_follows_offsets_until_total(self):
        rows = [alarm("T{0:03d}".format(i)) for i in range(PAGE_LIMIT + 50)]

        def page(query):
            offset, limit = int(query["offset"][0]), int(query["limit"][0])
            return FakeResponse(200, rows[offset:offset + limit], {"Pagination-Total": str(len(rows))})

        client = self.make(routes={"alarms": page})
        client.login("u", "p")
        result = client.get_all("alarms", {"filter": "AlarmState==Alarmed"})
        self.assertEqual((len(result["items"]), result["total"], result["truncated"]), (250, 250, False))
        queries = [urllib.parse.parse_qs(urllib.parse.urlsplit(r[1]).query) for r in self.server.requests[1:]]
        self.assertEqual([q["offset"][0] for q in queries], ["0", "200"])
        self.assertEqual(queries[0]["filter"], ["AlarmState==Alarmed"])

    def test_pagination_stops_at_the_page_cap(self):
        def page(query):
            return FakeResponse(200, [alarm("T")] * PAGE_LIMIT, {"Pagination-Total": "100000"})

        client = self.make(routes={"alarms": page})
        client.login("u", "p")
        result = client.get_all("alarms", max_pages=3)
        self.assertEqual((len(result["items"]), result["truncated"]), (3 * PAGE_LIMIT, True))


class ParserTests(unittest.TestCase):
    def test_identity(self):
        identity = api_parsers.parse_id(ID)
        self.assertEqual(identity["observed_model"], "SEL-3505-3")
        self.assertEqual(identity["firmware_version"], "146.0")
        self.assertEqual(identity["fid"], ID["FID"]["Raw"])
        self.assertEqual(identity["serial_number"], "0000000000")
        self.assertEqual(identity["licensed_features"], [{"Name": "Logic Engine", "Category": "Base",
                                                          "Expired": False}])

    def test_status_flattens_self_tests_and_usage(self):
        status = api_parsers.parse_status(STATUS)
        self.assertEqual(status["self_test"], "OK")
        self.assertEqual(status["project_state"], "Running")
        self.assertEqual(status["memory_used_percent"], 25.0)
        self.assertEqual(status["users_logged_in"], 1)
        self.assertNotIn("someone", json.dumps(status))
        failing = dict(STATUS, Hardware={"SelfTests": {"RAM": "Pass", "Flash": {"Secondary": "Fail"}}})
        self.assertEqual(api_parsers.parse_status(failing)["self_tests_failed"], ["Flash.Secondary"])

    def test_alarms_and_connections(self):
        alarms = api_parsers.parse_alarms([alarm("B", ts="2026-10-13T09:00:00Z"), alarm("A", state="Normalized")])
        self.assertEqual([a["tag"] for a in alarms], ["A", "B"])
        self.assertEqual([a["tag"] for a in api_parsers.active_alarms(alarms)], ["B"])
        rows = api_parsers.parse_connections(CONNECTIONS)
        self.assertEqual(rows[0]["egress"], "192.0.2.20:20000")
        self.assertEqual(rows[0]["failure_ratio"], 0.1)
        self.assertEqual(rows[1]["egress"], "COM_03")
        self.assertNotIn("failure_ratio", rows[1])

    def test_unexpected_shapes_do_not_raise(self):
        self.assertEqual(api_parsers.parse_id("x"), {})
        self.assertEqual(api_parsers.parse_status(None), {})
        self.assertEqual(api_parsers.parse_connections({"a": 1}), [])
        self.assertEqual(api_parsers.parse_alarms([None, {"Message": "no tag"}]), [])


class DiagnosticTests(unittest.TestCase):
    def codes(self, status=None, alarms=None, connections=None, thresholds=None):
        return {d["code"]: d for d in diagnose_rtac_api(status, alarms, connections, NOW, thresholds)}

    def test_healthy_status_has_no_findings(self):
        self.assertEqual(self.codes(api_parsers.parse_status(STATUS), [], []), {})

    def test_status_findings(self):
        bad = api_parsers.parse_status(dict(STATUS, Time={"Value": "2026-10-13T11:40:00Z", "Source": "Internal"},
                                            Hardware={"SelfTests": {"RAM": "Fail"}}))
        codes = self.codes(bad)
        self.assertEqual(codes["rtac_self_test_failed"]["evidence"]["failed"], ["RAM"])
        self.assertEqual(codes["rtac_clock_unsynchronized"]["evidence"]["drift_seconds"], 1200)
        self.assertNotIn("rtac_clock_unsynchronized", self.codes(bad, thresholds={"rtac_clock_drift_seconds": 1500}))
        offline = api_parsers.parse_status(dict(STATUS, Online=False))
        self.assertIn("rtac_not_online", self.codes(offline))
        test_mode = api_parsers.parse_status(dict(STATUS, Project={"Name": "P", "State": "Test"}))
        self.assertIn("rtac_project_not_running", self.codes(test_mode))

    def test_alarm_and_connection_findings(self):
        alarms = api_parsers.parse_alarms([alarm("A"), alarm("B", ack="Acknowledged"), alarm("C", state="Normalized")])
        codes = self.codes(None, alarms, api_parsers.parse_connections(CONNECTIONS))
        self.assertEqual(codes["rtac_active_alarms"]["evidence"]["count"], 2)
        self.assertEqual(codes["rtac_active_alarms"]["evidence"]["unacknowledged"], 1)
        self.assertEqual([c["name"] for c in codes["rtac_ied_offline"]["evidence"]["connections"]], ["RELAY_1"])
        failing = codes["rtac_ied_message_failures"]["evidence"]["connections"]
        self.assertEqual([c["name"] for c in failing], ["METER_1"])
        self.assertNotIn("rtac_ied_message_failures",
                         self.codes(None, [], api_parsers.parse_connections(CONNECTIONS),
                                    {"rtac_connection_failure_ratio": 0.2}))


def reader(service):
    reader.services.append(service)
    return "labuser", "secret-pw"


class WorkflowTests(unittest.TestCase):
    def run_snapshot(self, server, **kwargs):
        reader.services = []
        with tempfile.TemporaryDirectory() as directory:
            client = RtacApiClient("192.0.2.1", 4443, connection_factory=server.factory)
            result = run_rtac_api_snapshot(TARGET, reader, Path(directory), lambda target: client, NOW, None, **kwargs)
            stored = {p.name: p.read_text() for p in Path(directory).rglob("*") if p.is_file()}
        return result, stored

    def test_full_snapshot(self):
        server = FakeServer(routes=full_routes())
        result, stored = self.run_snapshot(server, tag_filters=["*g_*"], alarm_history_hours=24)
        self.assertEqual(result["tool"], "rtac-api-snapshot")
        target = result["targets"][0]
        self.assertEqual(target["identity"]["observed_model"], "SEL-3505-3")
        self.assertEqual(target["identity"]["fingerprint"], "AB:CD")
        self.assertEqual(target["snapshot"]["status"]["project"], "LAB_PROJECT")
        self.assertEqual([a["tag"] for a in target["snapshot"]["alarms"]["active"]], ["SystemTags.Comms_Fail"])
        self.assertEqual(target["snapshot"]["alarm_history"]["tags"], 2)
        self.assertEqual(target["snapshot"]["tags"]["values"], [{"name": "g_curtail_pct", "type": "REAL",
                                                                 "value": 87.5}])
        codes = {d["code"] for d in target["diagnostics"]}
        self.assertEqual(codes, {"rtac_active_alarms", "rtac_ied_offline", "rtac_ied_message_failures"})
        self.assertTrue(target["ok"], target["errors"])
        self.assertEqual({r[0] for r in server.requests}, {"GET"})
        history = [urllib.parse.parse_qs(urllib.parse.urlsplit(r[1]).query) for r in server.requests
                   if "/history" in r[1]]
        self.assertEqual(history[0]["filter"], ["Timestamp=ge=2026-10-12T12:00:00Z"])
        csv_text = next(v for k, v in stored.items() if k.endswith(".csv"))
        self.assertIn("g_curtail_pct,REAL,ok,87.5", csv_text)
        self.assertIn("gr_status,BOOL,permission_denied,", csv_text)
        everything = "".join(stored.values())
        self.assertNotIn(TOKEN, everything)
        self.assertNotIn("secret-pw", everything)
        self.assertEqual(reader.services, ["rtac/Lab Site"])

    def test_refused_token_stops_with_one_request_and_no_retry(self):
        server = FakeServer(routes=full_routes(), token_status=401)
        result, _ = self.run_snapshot(server)
        target = result["targets"][0]
        self.assertEqual([e["category"] for e in target["errors"]], ["authentication_failed"])
        self.assertTrue(target["reachable"])
        self.assertFalse(target["ok"])
        self.assertEqual(len(server.requests), 1)

    def test_missing_permission_on_one_area_is_partial(self):
        routes = full_routes()
        routes["projects/active/connections"] = (403, {"title": "Forbidden"})
        routes["alarms"] = (403, {"title": "Forbidden"})
        result, _ = self.run_snapshot(FakeServer(routes=routes), alarm_history_hours=24)
        target = result["targets"][0]
        self.assertEqual(sorted((e["capability"], e["category"]) for e in target["errors"]),
                         [("alarms", "permission_denied"), ("connections", "permission_denied")])
        self.assertTrue(target["partial"])
        self.assertIn("status", target["snapshot"])
        self.assertNotIn("alarm_history", target["snapshot"])

    def test_credential_service_override(self):
        self.run_snapshot(FakeServer(routes=full_routes()), credential_service="rtac-api/Lab Site")
        self.assertEqual(reader.services, ["rtac-api/Lab Site"])

    def test_connection_lost_mid_snapshot_stops(self):
        server = FakeServer(routes=full_routes())
        calls = {"n": 0}
        original = server.factory

        def flaky():
            calls["n"] += 1
            if calls["n"] == 3:
                server.fail_connect = True
            return original()

        server.factory = flaky
        result, _ = self.run_snapshot(server)
        target = result["targets"][0]
        self.assertEqual([e["category"] for e in target["errors"]], ["route_or_tcp"])
        self.assertEqual(len(server.requests), 2)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Path(self.tmp.name) / "config.json"
        self.cfg.write_text(json.dumps({"diagnosticThresholds": {"rtac_clock_drift_seconds": 60}}))
        (Path(self.tmp.name) / "devices.json").write_text(json.dumps({"devices": [
            {"name": "Lab Site/RTAC", "site": "Lab Site", "kind": "rtac", "host": "192.0.2.1", "port": 4443,
             "credentialRef": "rtac/Lab Site"},
            {"name": "Lab Site/Relay", "site": "Lab Site", "kind": "sel", "host": "192.0.2.2", "port": 2381,
             "credentialRef": "sel/access1"},
        ]}))

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, argv):
        from sel_triage import cli
        from sel_triage.integrations.devices.rtac import api_workflow

        envelope = {"tool": "rtac-api-snapshot", "ran_at": "t", "ok": True, "errors": [], "targets": [{
            "name": "Lab Site/RTAC", "reachable": True, "identity": {"observed_model": "SEL-3505-3", "fid": "FID-X"},
            "snapshot": {"status": {"project": "LAB", "self_test": "OK"}, "alarms": {"active": [{}]},
                         "connections": [{"status": "Offline"}, {"status": "Online"}], "tags": {"read": 4}},
            "diagnostics": [{"code": "rtac_ied_offline", "severity": "warning"}], "evidence": [],
            "errors": [{"capability": "symbols", "category": "permission_denied"}]}]}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(api_workflow, "run_rtac_api_snapshot", return_value=envelope) as run, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue(), run

    def test_passes_options_and_renders(self):
        code, out, err, run = self.invoke([
            "rtac-api-snapshot", "--config", str(self.cfg), "--name", "Lab Site/RTAC", "--tags", "*g_*",
            "--tags", "*gr_*", "--alarm-history-hours", "24", "--credential-service", "rtac-api/Lab Site",
            "--render"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(run.call_args.args[0].name, "Lab Site/RTAC")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["tag_filters"], ["*g_*", "*gr_*"])
        self.assertEqual(kwargs["alarm_history_hours"], 24.0)
        self.assertEqual(kwargs["credential_service"], "rtac-api/Lab Site")
        self.assertEqual(kwargs["thresholds"], {"rtac_clock_drift_seconds": 60})
        for text in ("model=SEL-3505-3", "ieds_offline=1", "tags_read=4", "diagnostic[warning]: rtac_ied_offline",
                     "error[symbols]: permission_denied"):
            self.assertIn(text, out)

    def test_rejects_non_rtac_device(self):
        code, out, err, run = self.invoke(["rtac-api-snapshot", "--config", str(self.cfg), "--name", "Lab Site/Relay"])
        self.assertEqual(code, 2)
        self.assertIn("not an RTAC", err)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
