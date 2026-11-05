"""Agent-facing entry point for bounded SEL event evidence collection."""

from sel_triage.integrations.devices.sel.workflows import (
    EventSelector,
    collect_events,
)


run = collect_events


__all__ = ["EventSelector", "collect_events", "run"]
