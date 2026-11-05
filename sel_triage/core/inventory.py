"""Device inventory resolution without secret values."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("{0} must be nonempty".format(field))
    return value


def _optional_text(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    return _required_text(value, field)


def _positive_integer(value: Any, field: str, maximum: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("{0} must be a positive integer".format(field))
    if maximum is not None and value > maximum:
        raise ValueError("{0} must be at most {1}".format(field, maximum))
    return value


@dataclass(frozen=True)
class DeviceTarget:
    """Validated connection metadata for one configured or ad-hoc device."""

    name: str
    kind: str
    host: str
    port: int
    model_hint: Optional[str]
    credential_ref: str
    timeout_seconds: int

    def __post_init__(self) -> None:
        _required_text(self.name, "name")
        _required_text(self.kind, "kind")
        _required_text(self.host, "host")
        _positive_integer(self.port, "port", maximum=65535)
        _optional_text(self.model_hint, "model hint")
        _required_text(self.credential_ref, "credential reference")
        _positive_integer(self.timeout_seconds, "timeout")


def _configured_default(config: dict, key: str, fallback: Any = None) -> Any:
    defaults = config.get("defaults")
    if isinstance(defaults, dict) and key in defaults:
        return defaults[key]
    return config.get(key, fallback)


def _timeout(config: dict, entry: Optional[dict] = None) -> Any:
    if entry is not None and "timeoutSeconds" in entry:
        return entry["timeoutSeconds"]
    return _configured_default(
        config,
        "timeoutSeconds",
        _configured_default(config, "requestTimeoutSeconds", 30),
    )


def _credential_ref(config: dict, value: Optional[str] = None) -> Any:
    if value is not None:
        return value
    return _configured_default(
        config,
        "credentialRef",
        _configured_default(config, "defaultCredentialRef"),
    )


def resolve_device(
    config: dict,
    name: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    model_hint: Optional[str] = None,
    credential_ref: Optional[str] = None,
) -> DeviceTarget:
    """Resolve a configured name or validate a self-contained ad-hoc target."""

    if not isinstance(config, dict):
        raise ValueError("config must be an object")

    named_selection = name is not None
    adhoc_selection = any(
        value is not None for value in (host, port, model_hint, credential_ref)
    )
    if named_selection == adhoc_selection:
        raise ValueError("select exactly one of a named or ad-hoc device")

    if named_selection:
        _required_text(name, "name")
        devices = config.get("devices", [])
        if not isinstance(devices, list):
            raise ValueError("config devices must be a list")
        for entry in devices:
            if isinstance(entry, dict) and entry.get("name") == name:
                return DeviceTarget(
                    name=entry.get("name"),
                    kind=entry.get("kind"),
                    host=entry.get("host"),
                    port=entry.get("port"),
                    model_hint=entry.get("modelHint"),
                    credential_ref=entry.get(
                        "credentialRef", _credential_ref(config)
                    ),
                    timeout_seconds=_timeout(config, entry),
                )
        raise ValueError("device not found: {0}".format(name))

    resolved_credential_ref = _credential_ref(config, credential_ref)
    if not isinstance(resolved_credential_ref, str) or not resolved_credential_ref.strip():
        raise ValueError("credential reference is required for an ad-hoc device")
    return DeviceTarget(
        name=host,
        kind=_configured_default(config, "kind", _configured_default(config, "defaultKind", "sel")),
        host=host,
        port=port,
        model_hint=model_hint,
        credential_ref=resolved_credential_ref,
        timeout_seconds=_timeout(config),
    )


def inventory_path(config: dict, config_path: str) -> Path:
    """Location of the imported device inventory for this config."""

    configured = config.get("deviceInventory") if isinstance(config, dict) else None
    base = Path(config_path).parent
    return base / configured if isinstance(configured, str) and configured.strip() else base / "devices.json"


def with_imported_devices(config: dict, config_path: str) -> dict:
    """Return config with imported devices appended after configured ones.

    Configured devices win on a name clash because resolution takes the first
    match. A missing inventory file leaves the config unchanged.
    """

    path = inventory_path(config, config_path)
    if not path.is_file():
        return config
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    imported = data.get("devices", []) if isinstance(data, dict) else []
    if not isinstance(imported, list):
        raise ValueError("device inventory devices must be a list")
    merged = dict(config)
    merged["devices"] = list(config.get("devices", [])) + [d for d in imported if isinstance(d, dict)]
    return merged
