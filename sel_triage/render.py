"""Human-readable rendering of a tool result. Never raises on missing keys."""


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _message(value):
    if isinstance(value, dict):
        return value.get("message") or value.get("description") or "?"
    return "?" if value is None else str(value)


def _render_sel_snapshot(envelope, lines):
    for target_value in _list(envelope.get("targets")):
        target = _dict(target_value)
        identity = _dict(target.get("identity"))
        snapshot = _dict(target.get("snapshot"))
        meter = _dict(snapshot.get("meter"))
        breaker = _dict(snapshot.get("breaker"))
        lines.append(
            "  {0}  reachable={1}  model={2}  device_id={3}".format(
                target.get("name", "?"),
                target.get("reachable"),
                identity.get("observed_model"),
                identity.get("device_id"),
            )
        )
        measurements = (
            ("frequency_hz", meter.get("frequency_hz")),
            ("active_power_mw", meter.get("active_power_mw", meter.get("real_power_mw"))),
            ("breaker_state", breaker.get("breaker_state", breaker.get("state"))),
            ("breaker_wear_percent", breaker.get("breaker_wear_percent")),
        )
        available = [
            "{0}={1}".format(key, value)
            for key, value in measurements
            if value is not None
        ]
        if available:
            lines.append("      " + "  ".join(available))
        for diagnostic_value in _list(target.get("diagnostics")):
            diagnostic = _dict(diagnostic_value)
            lines.append(
                "      diagnostic[{0}]: {1}".format(
                    diagnostic.get("severity"), diagnostic.get("code", "?")
                )
            )
        for warning in _list(target.get("warnings")):
            lines.append("      warning: {0}".format(_message(warning)))
        for reference_value in _list(target.get("evidence")):
            reference = _dict(reference_value)
            lines.append("      evidence: {0}".format(reference.get("path", "?")))
        if target.get("manifest") is not None:
            lines.append("      manifest: {0}".format(target.get("manifest")))


def _render_sel_events(result, lines):
    targets = _list(result.get("targets"))
    if not targets:
        legacy_target = _dict(result.get("target"))
        legacy_target.update(
            {
                "source_identity": result.get("source_identity"),
                "selection": result.get("selection"),
                "ser": result.get("ser"),
                "artifacts": result.get("artifacts"),
                "warnings": result.get("warnings"),
                "manifest": result.get("manifest"),
            }
        )
        targets = [legacy_target]

    for target_value in targets:
        target = _dict(target_value)
        identity = _dict(target.get("source_identity"))
        selection = _dict(target.get("selection"))
        ser = _dict(target.get("ser"))
        lines.append(
            "  {0}  model={1}  mode={2}  count={3}".format(
                target.get("name", "?"),
                identity.get("observed_model"),
                selection.get("mode"),
                selection.get("count"),
            )
        )
        lines.append(
            "      SER rows={0}/{1} truncated={2}".format(
                ser.get("rows_returned"),
                ser.get("rows_available"),
                ser.get("truncated"),
            )
        )
        history = target.get("history")
        if isinstance(history, dict):
            lines.append("      HIS events={0}".format(len(_list(history.get("events")))))
        for artifact_value in _list(target.get("artifacts")):
            artifact = _dict(artifact_value)
            lines.append("      artifact: {0}".format(artifact.get("path", "?")))
        for warning in _list(target.get("warnings")):
            lines.append("      warning: {0}".format(_message(warning)))
        if target.get("manifest") is not None:
            lines.append("      manifest: {0}".format(target.get("manifest")))


def _render_visualizer(result, lines):
    targets = _list(result.get("targets"))
    if not targets:
        targets = [{"reports": result.get("reports")}]
    for target_value in targets:
        target = _dict(target_value)
        for report in _list(target.get("reports")):
            lines.append("  report: {0}".format(report))


def _render_rtac_snapshot(result, lines):
    for target_value in _list(result.get("targets")):
        target = _dict(target_value)
        identity = _dict(target.get("identity"))
        snapshot = _dict(target.get("snapshot"))
        soe = _dict(snapshot.get("soe"))
        lines.append(
            "  {0}  reachable={1}  model={2}  device_id={3}".format(
                target.get("name", "?"), target.get("reachable"),
                identity.get("observed_model"), identity.get("device_id"),
            )
        )
        facts = (
            ("firmware", soe.get("firmware")),
            ("project", soe.get("project")),
            ("last_power_up", soe.get("last_power_up")),
            ("soe_events", soe.get("event_count")),
            ("active_alarms", len(_list(snapshot.get("alarms"))) if "alarms" in snapshot else None),
            ("ethernet_ieds", len(_list(snapshot.get("ethernet_ieds"))) if "ethernet_ieds" in snapshot else None),
            ("serial_ieds", len(_list(snapshot.get("serial_ieds"))) if "serial_ieds" in snapshot else None),
        )
        available = ["{0}={1}".format(k, v) for k, v in facts if v is not None]
        if available:
            lines.append("      " + "  ".join(available))
        for diagnostic_value in _list(target.get("diagnostics")):
            diagnostic = _dict(diagnostic_value)
            lines.append("      diagnostic[{0}]: {1}".format(diagnostic.get("severity"), diagnostic.get("code", "?")))
        for reference_value in _list(target.get("evidence")):
            lines.append("      evidence: {0}".format(_dict(reference_value).get("path", "?")))
        if target.get("manifest") is not None:
            lines.append("      manifest: {0}".format(target.get("manifest")))


def _render_rtac_api_snapshot(result, lines):
    for target_value in _list(result.get("targets")):
        target = _dict(target_value)
        identity = _dict(target.get("identity"))
        snapshot = _dict(target.get("snapshot"))
        status = _dict(snapshot.get("status"))
        alarms = _dict(snapshot.get("alarms"))
        connections = _list(snapshot.get("connections"))
        tags = _dict(snapshot.get("tags"))
        lines.append(
            "  {0}  reachable={1}  model={2}  firmware={3}".format(
                target.get("name", "?"), target.get("reachable"),
                identity.get("observed_model"), identity.get("fid"),
            )
        )
        facts = (
            ("project", status.get("project")),
            ("state", status.get("project_state")),
            ("clock", status.get("clock")),
            ("time_source", status.get("time_source")),
            ("self_test", status.get("self_test")),
            ("active_alarms", len(_list(alarms.get("active"))) if alarms else None),
            ("ied_connections", len(connections) if "connections" in snapshot else None),
            ("ieds_offline", sum(1 for c in connections if _dict(c).get("status") == "Offline")
             if "connections" in snapshot else None),
            ("tags_read", tags.get("read") if tags else None),
        )
        available = ["{0}={1}".format(k, v) for k, v in facts if v is not None]
        if available:
            lines.append("      " + "  ".join(available))
        for diagnostic_value in _list(target.get("diagnostics")):
            diagnostic = _dict(diagnostic_value)
            lines.append("      diagnostic[{0}]: {1}".format(diagnostic.get("severity"), diagnostic.get("code", "?")))
        for error_value in _list(target.get("errors")):
            error = _dict(error_value)
            lines.append("      error[{0}]: {1}".format(error.get("capability", "-"), error.get("category", "?")))
        for reference_value in _list(target.get("evidence")):
            lines.append("      evidence: {0}".format(_dict(reference_value).get("path", "?")))
        if target.get("manifest") is not None:
            lines.append("      manifest: {0}".format(target.get("manifest")))


def render(envelope: dict) -> str:
    result = _dict(envelope)
    tool = result.get("tool", "?")
    lines = [
        "{0}  ran_at={1}  ok={2}".format(
            tool, result.get("ran_at"), result.get("ok")
        )
    ]
    if tool in ("sel_snapshot", "sel-snapshot"):
        _render_sel_snapshot(result, lines)
    elif tool in ("sel_collect_events", "sel-collect-events"):
        _render_sel_events(result, lines)
    elif tool == "sel-visualize":
        _render_visualizer(result, lines)
    elif tool == "rtac-snapshot":
        _render_rtac_snapshot(result, lines)
    elif tool == "rtac-api-snapshot":
        _render_rtac_api_snapshot(result, lines)
    elif tool in ("sel-inventory", "sel-settings-check", "sel-settings-rules", "sel-settings-diff",
                  "sel-settings-capture", "sel-settings-index"):
        from .integrations.devices.sel.settings import report as sel_settings_report

        renderer = {
            "sel-inventory": sel_settings_report.render_inventory,
            "sel-settings-check": sel_settings_report.render_check,
            "sel-settings-rules": sel_settings_report.render_rules,
            "sel-settings-diff": sel_settings_report.render_diff,
            "sel-settings-capture": sel_settings_report.render_capture,
            "sel-settings-index": sel_settings_report.render_index,
        }[tool]
        lines.extend(renderer(result))
    elif str(tool).startswith("sel-rdb-"):
        from .tools.sel_rdb import render_lines as render_rdb

        lines.extend(render_rdb(result))
    elif tool == "sel-breaker-trend":
        from .sel_archive.breaker_trend import render_lines as render_breaker_trend

        lines.extend(render_breaker_trend(result))

    event_collection = result.get("event_collection")
    if isinstance(event_collection, dict):
        lines.append("  included event collection:")
        _render_sel_events(event_collection, lines)
    for error in _list(result.get("errors")):
        if isinstance(error, dict):
            category = error.get("category", "error")
            lines.append("  ERROR[{0}]: {1}".format(category, _message(error)))
        else:
            lines.append("  ERROR: {0}".format(error))
    return "\n".join(lines)


__all__ = ["render"]
