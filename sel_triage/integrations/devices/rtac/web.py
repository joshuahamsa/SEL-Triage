"""Read-only client for the SEL RTAC web interface.

Login is two steps: POST auth.sel (username, password, the login page's
temp_auth_token) returns a session UUID, then POST home.sel with it. Later
requests carry the session as query parameters; there are no cookies. Every
login is recorded in the RTAC's own SOE.

Only the endpoints in ENDPOINTS can be fetched. They are read-only reports;
pages with actions (acknowledge, delete, project upload, factory settings,
user accounts) are deliberately absent. RTAC web certificates are
self-signed and reached only over the site VPN, so TLS is not verified.
"""

import http.client
import ssl
import urllib.parse
from typing import Callable, Dict, Optional, Tuple

from sel_triage.core.errors import TriageError

from . import parsers

# name -> (method, path, extra query)
ENDPOINTS: Dict[str, Tuple[str, str, str]] = {
    "soe": ("GET", "soe.csv", ""),
    "alarms": ("GET", "alarms.csv", ""),
    "diagnostics": ("POST", "services_rpt.cev", ""),
    "ethernet_ieds": ("POST", "connected_ied_ethernet.sel", "&nameint=1&dispAll=true"),
    "serial_ieds": ("POST", "connected_ied_serial.sel", "&count=true&start=1"),
}
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_USER_AGENT = "sel-triage"


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class RtacWebClient:
    def __init__(
        self,
        host: str,
        port: int,
        timeout_seconds: float = 30.0,
        connection_factory: Optional[Callable[[], object]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self._factory = connection_factory or (
            lambda: http.client.HTTPSConnection(host, port, context=_unverified_context(), timeout=timeout_seconds)
        )
        self._connection = None
        self._session: Optional[str] = None
        self._username: Optional[str] = None

    @property
    def redactions(self) -> Tuple[str, ...]:
        """Values that must not be stored in evidence."""

        return (self._session,) if self._session else ()

    def _request(self, method: str, path: str, form: Optional[Dict[str, str]] = None) -> str:
        if self._connection is None:
            self._connection = self._factory()
        headers = {"User-Agent": _USER_AGENT, "Referer": "https://{0}:{1}/home.sel".format(self.host, self.port)}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            self._connection.request(method, "/" + path, body=body, headers=headers)
            response = self._connection.getresponse()
            data = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            reachable = self._session is not None
            raise TriageError(
                "RTAC web request failed" if reachable else "unable to reach the RTAC web interface",
                category="route_or_tcp",
                reachable=reachable,
            ) from exc
        finally:
            body = None
            form = None
        if len(data) > MAX_RESPONSE_BYTES:
            raise TriageError("RTAC response exceeded the size limit", category="response_too_large", reachable=True)
        if response.status != 200:
            raise TriageError(
                "RTAC returned HTTP {0} for {1}".format(response.status, path.split("?")[0]),
                category="rtac_http_error",
                reachable=True,
            )
        return data.decode("utf-8", errors="replace")

    def _session_query(self) -> str:
        return urllib.parse.urlencode({"session_id": self._session, "session_username": self._username})

    def login(self, username: str, password: str) -> str:
        """Log in and return the home page HTML."""

        try:
            token = parsers.login_token(self._request("GET", ""))
            if token is None:
                raise TriageError("RTAC login page not recognized", category="rtac_unrecognized", reachable=True)
            response = self._request(
                "POST",
                "auth.sel",
                {"session_username": username, "password": password, "auto_login": "false", "temp_auth_token": token},
            )
        finally:
            password = None
        session = parsers.session_id(response)
        if session is None:
            raise TriageError("RTAC login was rejected", category="authentication_failed", reachable=True)
        self._session, self._username = session, username
        return self._request("POST", "home.sel", {"session_id": session, "session_username": username})

    def fetch(self, name: str) -> str:
        try:
            method, path, extra = ENDPOINTS[name]
        except KeyError:
            raise ValueError("RTAC endpoint is not in the read-only allowlist: {0}".format(name)) from None
        if self._session is None:
            raise TriageError("RTAC fetch requires a logged-in session", category="session_state", reachable=None)
        url = "{0}?{1}{2}".format(path, self._session_query(), extra)
        form = {"session_id": self._session, "session_username": self._username} if method == "POST" else None
        return self._request(method, url, form)

    def logout(self) -> None:
        try:
            if self._session is not None:
                self._request("GET", "logout.sel?action=logoff&" + self._session_query())
        except TriageError:
            pass
        finally:
            self._session = None
            if self._connection is not None:
                try:
                    self._connection.close()
                except OSError:
                    pass
                self._connection = None


__all__ = ["ENDPOINTS", "RtacWebClient"]
