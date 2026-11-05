"""Read-only client for the SEL RTAC REST API (``/api/v1``).

Built from the OpenAPI document an SEL-3505-3 serves (R146, fetched 2026-10-09).
``GET /api/v1/auth/token`` with HTTP Basic credentials returns a bearer token
(``AccessToken``, ``TokenType``, ``ExpiresIn``, ``Scope``); every later request
carries it. The account needs the "API Login" permission plus a read permission
per area ("Logic Engine API Read" for tags, "Report Read" for alarms, "IED
Connections", "Project Read"). Without API Login the token request answers 401
exactly like a wrong password, and the RTAC logs it in its SOE as a failed
login, so a 401 is never retried.

Only GET is ever sent, and only to the paths in ENDPOINTS. Routes that change
state (``commands``, symbol writes, alarm acknowledgement, project uploads, users,
certificates, firmware) or reveal secrets (``password-vault``) are deliberately
absent, as are ``projects/active`` (it downloads the project file itself) and
the ``text/event-stream`` form of symbol reads. RTAC certificates
are self-signed and reached only over the site VPN, so TLS is not verified.
"""

import base64
import http.client
import json
import ssl
import urllib.parse
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from sel_triage.core.errors import TriageError

API_PREFIX = "/api/v1/"
# name -> path template under /api/v1/ ({placeholders} are URL-quoted path segments)
ENDPOINTS: Dict[str, str] = {
    "id": "id",
    "status": "status",
    "fingerprint": "fingerprint",
    "alarms": "alarms",
    "alarm": "alarms/{tag}",
    "alarm_history": "alarms/{tag}/history",
    "symbols": "logic-engine/symbols",
    "symbol": "logic-engine/symbols/{symbol}",
    "symbol_groups": "logic-engine/symbol-groups",
    "symbol_group": "logic-engine/symbol-groups/{group}",
    "projects": "projects",
    "connections": "projects/active/connections",
    "system_settings": "projects/active/system-settings",
    "network": "network",
    "ports": "ports",
    "serial": "serial",
}
TOKEN_PATH = "auth/token"
PAGE_LIMIT = 200  # the API's maximum page size
MAX_PAGES = 50
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_USER_AGENT = "sel-triage"


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _http_error(status: int, label: str) -> TriageError:
    if status == 401:
        return TriageError("RTAC API rejected the token for {0}".format(label), "token_rejected", reachable=True)
    if status == 403:
        return TriageError("RTAC API account lacks the permission for {0}".format(label), "permission_denied",
                           reachable=True)
    if status == 404:
        return TriageError("RTAC API has no {0}".format(label), "not_found", reachable=True)
    return TriageError("RTAC API returned HTTP {0} for {1}".format(status, label), "rtac_http_error",
                       reachable=True)


class RtacApiClient:
    def __init__(
        self,
        host: str,
        port: int,
        timeout_seconds: float = 90.0,
        connection_factory: Optional[Callable[[], object]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self._factory = connection_factory or (
            lambda: http.client.HTTPSConnection(host, port, context=_unverified_context(), timeout=timeout_seconds)
        )
        self._token: Optional[str] = None
        self._token_type = "Bearer"

    @property
    def redactions(self) -> Tuple[str, ...]:
        """Values that must not be stored in evidence."""

        return (self._token,) if self._token else ()

    def _get(self, path: str, authorization: str, label: str) -> Tuple[int, bytes, Dict[str, str]]:
        method = "GET"
        connection = self._factory()
        headers = {"Authorization": authorization, "Accept": "application/json", "User-Agent": _USER_AGENT}
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE_BYTES + 1)
            response_headers = {k.lower(): v for k, v in (response.getheaders() or [])}
        except (OSError, http.client.HTTPException) as exc:
            reachable = self._token is not None
            raise TriageError(
                "RTAC API request failed" if reachable else "unable to reach the RTAC API",
                category="route_or_tcp",
                reachable=reachable,
            ) from exc
        finally:
            authorization = None
            headers = None
            try:
                connection.close()
            except OSError:
                pass
        if len(data) > MAX_RESPONSE_BYTES:
            raise TriageError("RTAC API response for {0} exceeded the size limit".format(label),
                              category="response_too_large", reachable=True)
        return response.status, data, response_headers

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Request a bearer token once; return the token metadata without the token."""

        try:
            basic = base64.b64encode("{0}:{1}".format(username, password).encode("utf-8")).decode("ascii")
            status, data, _ = self._get(API_PREFIX + TOKEN_PATH, "Basic " + basic, "auth/token")
        finally:
            password = None
            basic = None
        if status == 401:
            raise TriageError(
                "RTAC API refused the login (wrong password, or the account lacks the 'API Login' permission); "
                "the attempt is in the RTAC SOE. Check the account's role before trying again",
                category="authentication_failed",
                reachable=True,
            )
        if status != 200:
            raise _http_error(status, "auth/token")
        try:
            token = json.loads(data.decode("utf-8"))
            access = token["AccessToken"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise TriageError("RTAC API token response not recognized", category="rtac_unrecognized",
                              reachable=True) from None
        if not isinstance(access, str) or not access:
            raise TriageError("RTAC API token response not recognized", category="rtac_unrecognized",
                              reachable=True)
        self._token = access
        self._token_type = str(token.get("TokenType") or "Bearer")
        return {k: v for k, v in token.items() if k != "AccessToken"}

    def _path(self, endpoint: str, params: Optional[Mapping[str, Any]], values: Mapping[str, str]) -> str:
        try:
            template = ENDPOINTS[endpoint]
        except KeyError:
            raise ValueError("RTAC API endpoint is not in the read-only allowlist: {0}".format(endpoint)) from None
        quoted = {k: urllib.parse.quote(str(v), safe="") for k, v in values.items()}
        path = API_PREFIX + template.format(**quoted)
        query = {k: v for k, v in (params or {}).items() if v is not None}
        return path + ("?" + urllib.parse.urlencode(query) if query else "")

    def get_response(self, endpoint: str, params: Optional[Mapping[str, Any]] = None,
                     **values: str) -> Tuple[Any, Dict[str, str], bytes]:
        """GET one allowlisted endpoint; return (parsed JSON, lowercase headers, raw body).

        ``values`` fill the endpoint's path placeholders (tag, symbol, group).
        """

        path = self._path(endpoint, params, values)
        if self._token is None:
            raise TriageError("RTAC API fetch requires a token", category="session_state", reachable=None)
        status, data, headers = self._get(path, "{0} {1}".format(self._token_type, self._token), endpoint)
        if status != 200:
            raise _http_error(status, endpoint)
        try:
            return json.loads(data.decode("utf-8")), headers, data
        except (ValueError, UnicodeDecodeError):
            raise TriageError("RTAC API returned a response that is not JSON for {0}".format(endpoint),
                              category="rtac_unrecognized", reachable=True) from None

    def get(self, endpoint: str, params: Optional[Mapping[str, Any]] = None, **values: str) -> Any:
        return self.get_response(endpoint, params, **values)[0]

    def get_all(self, endpoint: str, params: Optional[Mapping[str, Any]] = None, max_pages: int = MAX_PAGES,
                **values: str) -> Dict[str, Any]:
        """Follow offset/limit pagination; return {"items", "total", "truncated"}."""

        items: List[Any] = []
        total: Optional[int] = None
        offset = 0
        for _ in range(max_pages):
            query = dict(params or {})
            query.update(offset=offset, limit=PAGE_LIMIT)
            page, headers, _ = self.get_response(endpoint, query, **values)
            if not isinstance(page, list):
                raise TriageError("RTAC API page for {0} is not a list".format(endpoint), category="rtac_unrecognized",
                                  reachable=True)
            items.extend(page)
            try:
                total = int(headers.get("pagination-total"))
            except (TypeError, ValueError):
                total = None
            offset += len(page)
            if not page or len(page) < PAGE_LIMIT or (total is not None and offset >= total):
                return {"items": items, "total": total if total is not None else len(items), "truncated": False}
        return {"items": items, "total": total, "truncated": True}

    def logout(self) -> None:
        """Forget the token (the API has no logout; tokens expire on their own)."""

        self._token = None


__all__ = ["ENDPOINTS", "PAGE_LIMIT", "RtacApiClient"]
