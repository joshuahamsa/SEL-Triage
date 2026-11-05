"""Model-authoritative adapter selection for SEL devices."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Optional

from .base import SelAdapter
from .sel700g import Sel700GAdapter
from .sel735 import Sel735Adapter
from .sel351 import Sel351Adapter
from .sel651 import Sel651Adapter
from .sel751 import Sel751Adapter
from .sel851 import Sel851Adapter


@dataclass(frozen=True)
class AdapterSelection:
    """Selected adapter plus a non-fatal model-hint warning, if any."""

    adapter: SelAdapter
    warning: Optional[Dict[str, Any]] = None


_ADAPTERS_BY_MODEL = MappingProxyType(
    {
        "SEL-700G": Sel700GAdapter,
        "SEL-700GT": Sel700GAdapter,
        "SEL-735": Sel735Adapter,
        "SEL-351": Sel351Adapter,
        "SEL-351A": Sel351Adapter,
        "SEL-351S": Sel351Adapter,
        "SEL-651": Sel651Adapter,
        "SEL-651RA": Sel651Adapter,
        "SEL-651R2": Sel651Adapter,
        "SEL-751": Sel751Adapter,
        "SEL-751A": Sel751Adapter,
        "SEL-851": Sel851Adapter,
    }
)


def _normalize_model(model: str) -> str:
    return model.strip().upper()


def models_match(model_hint: str, observed_model: str, device_id: Optional[str] = None) -> bool:
    """True when a configured hint agrees with what the relay reports.

    A hint matches the firmware-ID model, the relay's DEVID, or any model that
    selects the same adapter family (e.g. SEL-700GT hardware reports
    FID=SEL-700G... with DEVID=SEL-700GT).
    """

    hint = _normalize_model(model_hint)
    observed = _normalize_model(observed_model)
    if hint == observed:
        return True
    if isinstance(device_id, str) and hint == _normalize_model(device_id):
        return True
    family = _ADAPTERS_BY_MODEL.get(hint)
    return family is not None and family is _ADAPTERS_BY_MODEL.get(observed)


def adapter_for(
    observed_model: str, model_hint: Optional[str] = None
) -> AdapterSelection:
    """Select by observed identity, using a hint only to report mismatch."""

    observed = _normalize_model(observed_model)
    try:
        adapter_type = _ADAPTERS_BY_MODEL[observed]
    except KeyError:
        raise ValueError("unsupported observed SEL model: {0}".format(observed))

    warning = None
    if model_hint is not None:
        hint = _normalize_model(model_hint)
        if not models_match(hint, observed):
            warning = {
                "code": "model_mismatch",
                "model_hint": hint,
                "observed_model": observed,
                "message": (
                    "Configured model hint {0} differs from observed model {1}"
                ).format(hint, observed),
            }

    return AdapterSelection(adapter=adapter_type(), warning=warning)


__all__ = ["AdapterSelection", "SelAdapter", "adapter_for", "models_match"]
