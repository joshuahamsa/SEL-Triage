"""RTAC web client: login flow, read-only endpoint allowlist, logout."""

from pathlib import Path
import unittest
import urllib.parse

from sel_triage.core.errors import TriageError
from sel_triage.integrations.devices.rtac.web import ENDPOINTS, RtacWebClient


F = Path(__file__).parent / "fixtures" / "rtac"
SID = "11111111-2222-3333-4444-555555555555"


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body.encode("utf-8")

    def read(self, amount=None):
        return self._body if amount is None else self._body[:amount]


class FakeConnection:
    def __init__(self, routes, fail_connect=False):
        self.routes = routes
        self.requests = []
        self.fail_connect = fail_connect
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        if self.fail_connect:
            raise OSError("no route")
        self.requests.append((method, path, body))
        self._path = path

    def getresponse(self):
        route = self._path.lstrip("/").split("?")[0]
        status, body = self.routes.get(route, (404, "not found"))
        return FakeResponse(status, body)

    def close(self):
        self.closed = True


def routes(auth_body="ok " + SID):
    return {
        "": (200, (F / "login.html").read_text()),
        "auth.sel": (200, auth_body),
        "home.sel": (200, (F / "home.html").read_text()),
        "soe.csv": (200, (F / "soe.csv").read_text()),
        "logout.sel": (200, "Logged Out"),
    }


class RtacWebClientTests(unittest.TestCase):
    def make(self, **kwargs):
        self.connection = FakeConnection(kwargs.pop("routes", routes()), **kwargs)
        return RtacWebClient("192.0.2.1", 4443, connection_factory=lambda: self.connection)

    def test_login_posts_credentials_and_token_then_opens_home(self):
        client = self.make()
        home = client.login("labuser", "secret-pw")
        self.assertIn("SEL-3505-3 Web Interface", home)
        method, path, body = self.connection.requests[1]
        self.assertEqual((method, path.split("?")[0]), ("POST", "/auth.sel"))
        form = urllib.parse.parse_qs(body)
        self.assertEqual(form["session_username"], ["labuser"])
        self.assertEqual(form["password"], ["secret-pw"])
        self.assertEqual(form["temp_auth_token"], ["synthetictoken0123456789abcdef"])
        self.assertEqual(self.connection.requests[2][0:2][0], "POST")
        self.assertEqual(client.redactions, (SID,))

    def test_fetch_passes_session_as_query_and_only_allows_listed_endpoints(self):
        client = self.make()
        client.login("labuser", "pw")
        text = client.fetch("soe")
        self.assertIn("Power_Up_Description", text)
        query = urllib.parse.parse_qs(self.connection.requests[-1][1].split("?", 1)[1])
        self.assertEqual(query["session_id"], [SID])
        self.assertEqual(query["session_username"], ["labuser"])
        with self.assertRaises(ValueError):
            client.fetch("project_upload")

    def test_allowlist_contains_no_action_endpoints(self):
        paths = " ".join(path for _, path, _ in ENDPOINTS.values()).lower()
        for word in ("upload", "delete", "ack", "factory", "account", "save", "logout"):
            self.assertNotIn(word, paths)
        self.assertEqual(set(ENDPOINTS), {"soe", "alarms", "diagnostics", "ethernet_ieds", "serial_ieds"})

    def test_failed_login_raises_authentication_failed_without_home(self):
        client = self.make(routes=routes("[ ERROR: Login Failure: Invalid Username/Password ]"))
        with self.assertRaises(TriageError) as ctx:
            client.login("labuser", "wrong")
        self.assertEqual(ctx.exception.category, "authentication_failed")
        self.assertNotIn("/home.sel", [p.split("?")[0] for _, p, _ in self.connection.requests])

    def test_unreachable_is_route_or_tcp(self):
        client = self.make(fail_connect=True)
        with self.assertRaises(TriageError) as ctx:
            client.login("labuser", "pw")
        self.assertEqual(ctx.exception.category, "route_or_tcp")
        self.assertFalse(ctx.exception.reachable)

    def test_logout_is_safe_after_login_and_without_one(self):
        client = self.make()
        client.logout()  # no session: nothing sent
        self.assertEqual(self.connection.requests, [])
        client.login("labuser", "pw")
        client.logout()
        self.assertTrue(self.connection.requests[-1][1].startswith("/logout.sel?action=logoff"))
        self.assertTrue(self.connection.closed)


if __name__ == "__main__":
    unittest.main()
