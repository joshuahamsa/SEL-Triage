"""Every known diagnostic threshold name (diagnosticThresholds keys), for resolve_thresholds.

Imports are resolved at call time so importing this module starts nothing.
"""

from typing import Tuple


def threshold_names() -> Tuple[str, ...]:
    from sel_triage.integrations.devices.rtac.diagnostics import DEFAULT_THRESHOLDS as RTAC_THRESHOLDS
    from sel_triage.integrations.devices.sel.diagnostics import DEFAULT_THRESHOLDS as SEL_THRESHOLDS
    from sel_triage.integrations.devices.sel.settings.checks import DEFAULT_THRESHOLDS as SEL_SETTINGS_THRESHOLDS

    return tuple(SEL_THRESHOLDS) + tuple(RTAC_THRESHOLDS) + tuple(SEL_SETTINGS_THRESHOLDS)


__all__ = ["threshold_names"]
