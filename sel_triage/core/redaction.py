"""Source-text redaction without retaining authentication material."""

import hashlib
import hmac


class SecretFingerprintRedactor:
    """Replace an exact secret using only its length and SHA-256 fingerprint."""

    __slots__ = ("_character_length", "_digest")

    def __init__(self, secret: str) -> None:
        try:
            if not isinstance(secret, str):
                raise ValueError("redaction secret must be a string")
            self._character_length = len(secret)
            self._digest = hashlib.sha256(secret.encode("utf-8")).digest()
        finally:
            secret = None

    def redact(self, text: str) -> str:
        if not isinstance(text, str):
            raise ValueError("redaction source must be a string")
        size = self._character_length
        if size < 1 or len(text) < size:
            return text

        pieces = []
        cursor = 0
        position = 0
        last_start = len(text) - size
        while position <= last_start:
            candidate = text[position : position + size]
            digest = hashlib.sha256(candidate.encode("utf-8")).digest()
            if hmac.compare_digest(digest, self._digest):
                pieces.extend((text[cursor:position], "[REDACTED]"))
                position += size
                cursor = position
            else:
                position += 1
        if not pieces:
            return text
        pieces.append(text[cursor:])
        return "".join(pieces)



# --- settings keys -------------------------------------------------------------
#
# Device settings files (SEL FILE READ, SHO) can carry port passwords, SNMP
# communities or keys. Values under a key that looks like one of those are
# replaced before they reach any result, evidence or report.

import re as _re
from typing import Dict as _Dict, Mapping as _Mapping

REDACTED = "[REDACTED]"
_SECRET_SETTING_KEY = _re.compile(
    r"(PASS|PWD|PSWD|SECRET|TOKEN|COMMUNITY|SNMP\w*COMM|AUTHKEY|PSK)", _re.IGNORECASE
)
_SECRET_SETTING_EXACT = _re.compile(r"^PW\d*$", _re.IGNORECASE)


def is_secret_setting_key(key: str) -> bool:
    """True when a setting name looks like a password, community or key."""

    text = str(key)
    return bool(_SECRET_SETTING_KEY.search(text) or _SECRET_SETTING_EXACT.match(text))


def redact_settings(settings: _Mapping[str, str]) -> _Dict[str, str]:
    """Return a copy with secret-looking setting values replaced."""

    return {
        key: (REDACTED if is_secret_setting_key(key) else value)
        for key, value in settings.items()
    }


__all__ = ["REDACTED", "SecretFingerprintRedactor", "is_secret_setting_key", "redact_settings"]
