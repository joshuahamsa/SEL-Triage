"""Agent-facing entry point for the bounded SEL fast snapshot."""

from sel_triage.integrations.devices.sel.workflows import run_snapshot


run = run_snapshot


__all__ = ["run", "run_snapshot"]
