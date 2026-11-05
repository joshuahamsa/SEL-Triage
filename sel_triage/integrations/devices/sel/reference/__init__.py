"""SEL ASCII command reference per model and firmware, extracted from the instruction manuals.

``commands/<MODEL>.json`` holds each manual's command summary (command, access levels,
read/write/session kind, page) and its firmware revision history. See README.md
for the manuals used, coverage and caveats (HELP on a device omits privileged commands; the
manuals are the complete list).
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

_DIR = Path(__file__).parent / "commands"

# Observed model (FID prefix) -> reference model. Order matters: longer prefixes first.
_MODEL_MAP = (
    ("SEL-651R-2", "SEL-651R-2"),
    ("SEL-651R2", "SEL-651R-2"),
    ("SEL-651RA", "SEL-651RA"),
    ("SEL-651R", "SEL-651R"),
    ("SEL-351A", "SEL-351A"),
    ("SEL-351S", "SEL-351S"),
    ("SEL-351", "SEL-351"),
    ("SEL-700G", "SEL-700G"),
    ("SEL-751A", "SEL-751A"),
    ("SEL-751", "SEL-751"),
    ("SEL-851", "SEL-851"),
    ("SEL-735", "SEL-735"),
)
_REVISION = re.compile(r"^R(\d+)$")


def load_reference() -> List[Dict[str, Any]]:
    """Every reference file (newest manual first per model)."""

    docs = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(_DIR.glob("*.json"))]
    return sorted(docs, key=lambda d: (d["model"], d.get("manual_date") or ""), reverse=True)


def reference_model(observed: Optional[str]) -> Optional[str]:
    """``SEL-351-5`` -> ``SEL-351``, ``SEL-700GT`` -> ``SEL-700G``; None when not covered."""

    if not observed:
        return None
    model = observed.upper()
    for prefix, reference in _MODEL_MAP:
        if model.startswith(prefix):
            return reference
    return None


def revision_number(revision: Optional[str]) -> Optional[int]:
    match = _REVISION.match(revision or "")
    return int(match.group(1)) if match else None


__all__ = ["load_reference", "reference_model", "revision_number"]
