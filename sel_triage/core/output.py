"""JSON envelope — the machine-facing contract for all triage tools."""


SEL_SCHEMA_VERSION = "0.2"
_SEL_TOOL_IDS = {
    "sel_snapshot": "sel-snapshot",
    "sel-snapshot": "sel-snapshot",
    "sel_collect_events": "sel-collect-events",
    "sel-collect-events": "sel-collect-events",
    "sel_visualize": "sel-visualize",
    "sel-visualize": "sel-visualize",
    "rtac-snapshot": "rtac-snapshot",
    "rtac-api-snapshot": "rtac-api-snapshot",
    "sma-snapshot": "sma-snapshot",
}


def build_envelope(tool: str, ran_at: str, targets: list, errors: list) -> dict:
    ok = all(t.get("reachable") is True for t in targets) and not errors
    return {
        "tool": tool,
        "ran_at": ran_at,
        "ok": ok,
        "targets": targets,
        "errors": errors,
    }


def build_sel_envelope(
    tool: str,
    ran_at: str,
    targets: list,
    errors: list,
    provenance: dict,
) -> dict:
    """Build the versioned SEL v0.2 envelope without changing SMA v0.1."""

    try:
        canonical_tool = _SEL_TOOL_IDS[tool]
    except (KeyError, TypeError):
        raise ValueError("unknown SEL tool identifier") from None
    if not isinstance(targets, list):
        raise ValueError("SEL targets must be a list")
    if not isinstance(errors, list):
        raise ValueError("SEL errors must be a list")
    if not isinstance(provenance, dict):
        raise ValueError("SEL provenance must be an object")

    combined_errors = [
        dict(error) if isinstance(error, dict) else error for error in errors
    ]
    for target in targets:
        if not isinstance(target, dict):
            continue
        target_name = target.get("name")
        for error in target.get("errors", []):
            if isinstance(error, dict):
                item = dict(error)
                if target_name is not None:
                    item.setdefault("target", target_name)
                combined_errors.append(item)
            else:
                combined_errors.append(error)

    ok = bool(targets) and not combined_errors and all(
        isinstance(target, dict) and target.get("ok") is True
        for target in targets
    )
    partial = not ok and any(
        isinstance(target, dict)
        and (target.get("ok") is True or target.get("partial") is True)
        for target in targets
    )
    return {
        "schema_version": SEL_SCHEMA_VERSION,
        "tool": canonical_tool,
        "ran_at": ran_at,
        "ok": ok,
        "partial": partial,
        "targets": targets,
        "errors": combined_errors,
        "provenance": dict(provenance),
    }


__all__ = ["SEL_SCHEMA_VERSION", "build_envelope", "build_sel_envelope"]
