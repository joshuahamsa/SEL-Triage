"""Human-readable lines for sel-inventory and sel-settings results."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _table(headers, rows) -> List[str]:
    widths = [max([len(str(r[i])) for r in rows] + [len(h)]) for i, h in enumerate(headers)]
    lines = ["  " + "  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip()]
    lines += ["  " + "  ".join(str(v).ljust(w) for v, w in zip(r, widths)).rstrip() for r in rows]
    return lines


def _evidence_text(evidence: Mapping[str, Any]) -> str:
    parts = []
    for key, value in evidence.items():
        if key in ("device", "site"):
            continue
        text = str(value)
        parts.append("{0}={1}".format(key, text if len(text) <= 90 else text[:87] + "..."))
    return "  ".join(parts)


def render_inventory(result: Mapping[str, Any]) -> List[str]:
    summary = _dict(result.get("summary"))
    lines = ["  {0} devices at {1} sites, {2} capture runs ({3} failed)".format(
        summary.get("devices"), summary.get("sites"), summary.get("capture_runs"), summary.get("failed_capture_runs"))]
    rows = []
    for row in _list(result.get("rows")):
        row = _dict(row)
        rows.append((
            row.get("device") or "?", row.get("model") or "-", row.get("firmware_revision") or "-",
            row.get("firmware_date") or "-", (row.get("capture_date") or "-")[:10], row.get("captures"),
            ",".join(_list(row.get("flags"))),
        ))
    if rows:
        lines += _table(("DEVICE", "MODEL", "FW", "FW DATE", "CAPTURED", "RUNS", "FLAGS"), rows)
    lines.append("  firmware by model:")
    for model, spread in _dict(summary.get("firmware")).items():
        newest = _dict(summary.get("newest_firmware")).get(model)
        lines.append("    {0}: {1}".format(model, ", ".join(
            "{0} x{1}{2}".format(fid, count, " (newest)" if fid == newest else "")
            for fid, count in _dict(spread).items())))
    flags = _dict(summary.get("flags"))
    if flags:
        lines.append("  flags: " + ", ".join("{0}={1}".format(k, v) for k, v in flags.items()))
    return lines


def render_check(result: Mapping[str, Any]) -> List[str]:
    summary = _dict(result.get("summary"))
    lines = ["  group {0}: {1} devices checked, {2} without settings, {3} with findings".format(
        result.get("group"), summary.get("devices_checked"), summary.get("devices_without_settings"),
        summary.get("devices_with_findings"))]
    for device in _list(result.get("devices")):
        device = _dict(device)
        findings = _list(device.get("findings"))
        if device.get("status") != "checked":
            lines.append("  {0}  (no settings capture)".format(device.get("device")))
            continue
        if not findings:
            continue
        lines.append("  {0}  {1}  {2}".format(device.get("device"), device.get("model"), (device.get("captured_at") or "")[:10]))
        for finding in findings:
            finding = _dict(finding)
            lines.append("    [{0}] {1}  {2}".format(
                finding.get("severity"), finding.get("code"), _evidence_text(_dict(finding.get("evidence")))))
    site_findings = _list(result.get("site_findings"))
    if site_findings:
        lines.append("  site consistency:")
        for finding in site_findings:
            finding = _dict(finding)
            evidence = _dict(finding.get("evidence"))
            lines.append("    [{0}] {1}  {2}  {3}".format(
                finding.get("severity"), finding.get("code"), evidence.get("site"), _evidence_text(evidence)))
    counts = _dict(summary.get("findings_by_code"))
    if counts:
        lines.append("  totals: " + ", ".join("{0}={1}".format(k, v) for k, v in counts.items()))
    return lines


def render_rules(result: Mapping[str, Any]) -> List[str]:
    return ["  {0:<36} {1:<8} {2:<7} {3}".format(
        rule.get("code"), rule.get("severity"), rule.get("scope"), rule.get("description"))
        for rule in map(_dict, _list(result.get("rules")))]


def render_diff(result: Mapping[str, Any]) -> List[str]:
    a, b = _dict(result.get("a")), _dict(result.get("b"))
    lines = [
        "  a: {0}  {1}  {2}".format(a.get("run"), a.get("model"), a.get("captured_at")),
        "  b: {0}  {1}  {2}".format(b.get("run"), b.get("model"), b.get("captured_at")),
        "  {0}".format("same device (drift)" if result.get("same_device") else "different devices (peers)"),
    ]
    for note in _list(result.get("notes")):
        lines.append("  note: {0}".format(note))
    for field, values in _dict(result.get("identity_changes")).items():
        lines.append("  identity {0}: {1} -> {2}".format(field, *(_list(values) + [None, None])[:2]))
    for name, label in (("classes_only_in_a", "only in a"), ("classes_only_in_b", "only in b")):
        if _list(result.get(name)):
            lines.append("  classes {0}: {1}".format(label, ", ".join(result[name])))
    changes = _list(result.get("changes"))

    def cell(value: Any) -> str:
        if value is None:
            return "-"
        text = str(value)
        return text if len(text) <= 60 else "{0}... ({1} chars)".format(text[:40], len(text))

    if changes:
        lines += _table(("CLASS", "KEY", "A", "B"), [
            (c.get("class"), c.get("key"), cell(c.get("a")), cell(c.get("b"))) for c in map(_dict, changes)])
    else:
        lines.append("  no setting differences")
    ignored = _dict(result.get("ignored"))
    if any(ignored.values()):
        lines.append("  ignored: " + ", ".join("{0}={1}".format(k, v) for k, v in ignored.items() if v))
    return lines


def render_capture(result: Mapping[str, Any]) -> List[str]:
    """sel-settings-capture: one row per device attempted, then skips and failures."""

    lines = ["  root: {0}".format(result.get("root"))]
    if result.get("skipped"):
        lines.append("  skipped: {0}".format(result.get("skipped")))
        if result.get("fix"):
            lines.append("  fix: {0}".format(result.get("fix")))
        return lines
    lines.append("  captured {0} of {1} attempted ({2} selected){3}".format(
        result.get("devices_captured"), result.get("devices_attempted"), result.get("devices_selected"),
        "; STOPPED EARLY (device network down)" if result.get("stopped_early") else ""))
    rows = []
    for row in map(_dict, _list(result.get("results"))):
        status = "ok" if row.get("ok") else (row.get("error_category") or "failed")
        detail = "{0} files{1}".format(
            len(_list(row.get("files"))),
            ", skipped " + ",".join(_list(row.get("skipped"))) if row.get("skipped") else "",
        ) if row.get("ok") else ""
        rows.append((row.get("device"), row.get("observed_model") or "-", row.get("method") or "-", status, detail))
    if rows:
        lines += _table(("DEVICE", "MODEL", "METHOD", "STATUS", "DETAIL"), rows)
    for entry in map(_dict, _list(result.get("recent_skipped"))):
        lines.append("  recent capture kept: {0} ({1})".format(entry.get("device"), entry.get("captured_at")))
    for entry in map(_dict, _list(result.get("duplicate_endpoints"))):
        lines.append("  inventory duplicate (same address, not logged into twice): {0} = {1}".format(
            entry.get("device"), entry.get("same_endpoint_as")))
    if result.get("index"):
        lines += render_index(_dict(result.get("index")))
    return lines


def render_index(result: Mapping[str, Any]) -> List[str]:
    lines = ["  index: {0}  ({1} new/changed, {2} unchanged, {3} removed, {4} unreadable; "
             "{5} captures of {6} devices ({7} matched to the inventory), {8} setting rows)".format(
                 result.get("db"), result.get("indexed"), result.get("unchanged"), result.get("removed"),
                 result.get("failed"), result.get("captures"), result.get("devices"),
                 result.get("matched_to_inventory"), result.get("settings_rows"))]
    if result.get("schema_reset"):
        lines.append("  index schema upgraded: the database was reset; re-index any other captures folders")
    return lines


__all__ = ["render_capture", "render_index", "render_check", "render_diff", "render_inventory", "render_rules"]
