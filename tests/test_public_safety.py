import inspect
import json
import re
import unittest
from pathlib import Path

from sel_triage.integrations.devices import sel
from sel_triage.integrations.devices.sel import client as sel_client
from sel_triage.integrations.devices.sel import commands as sel_commands
from sel_triage.integrations.devices.sel.adapters.base import EventSelector
from sel_triage.integrations.devices.sel.adapters.sel651 import Sel651Adapter


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_COMMANDS = (
    "2AC",
    "SET",
    "OPEN",
    "CLOSE",
    "RESET",
    "CLEAR",
    "TEST",
    "TRIGGER",
    # FILE READ / FILE SHOW only copy from the device; no file verb may write or delete.
    "WRITE",
    "DEL",
    "DELETE",
)


def _is_forbidden(wire_text):
    normalized = " ".join(wire_text.upper().split())
    return any(
        re.search(r"(^|\s){0}(\s|$)".format(re.escape(token)), normalized)
        for token in FORBIDDEN_COMMANDS
    )


class TestSelPublicSafety(unittest.TestCase):
    def test_public_modules_expose_no_raw_send_api(self):
        for module in (sel, sel_client, sel_commands):
            with self.subTest(module=module.__name__):
                public_names = {
                    name for name in dir(module) if not name.startswith("_")
                }
                exported_names = set(getattr(module, "__all__", ()))
                self.assertNotIn("send_command", public_names)
                self.assertFalse(
                    {"send", "write", "write_line", "raw_command"}
                    & public_names
                )
                self.assertFalse(
                    {"send_command", "send", "write", "write_line", "raw_command"}
                    & exported_names
                )

        public_client_methods = {
            name
            for name, member in inspect.getmembers(sel_client.SelClient, callable)
            if not name.startswith("_")
        }
        self.assertEqual(
            public_client_methods,
            {"login", "logout", "run", "run_bytes", "read_file"},
        )

    def test_true_executable_policy_and_dynamic_event_recipes_are_read_only(self):
        rendered_wires = []
        for family, commands in sel_client._COMMAND_POLICY.items():
            for capability, command in commands.items():
                with self.subTest(family=family, capability=capability):
                    self.assertEqual(capability, command.capability)
                    self.assertGreater(command.max_bytes, 0)
                    self.assertGreater(command.max_seconds, 0)
                    argument = 1 if command.integer_argument else None
                    if command.filename_argument:
                        argument = "SET_1.TXT"
                    rendered_wires.append(command.render(argument))

        adapter = Sel651Adapter()
        selectors = (
            EventSelector.latest(count=2, event_format="eve"),
            EventSelector.latest(count=2, event_format="cev"),
            EventSelector.number(7, event_format="cev_raw"),
        )
        for selector in selectors:
            for request in adapter.event_requests(selector):
                with self.subTest(selector=selector, request=request):
                    command = sel_client._COMMAND_POLICY[adapter.family][
                        request.capability
                    ]
                    self.assertTrue(command.integer_argument)
                    rendered_wires.append(command.render(request.argument))

        for wire_text in rendered_wires:
            with self.subTest(wire_text=wire_text):
                self.assertFalse(_is_forbidden(wire_text))

    def test_documented_live_gate_and_example_config_keep_secrets_out_of_argv(self):
        guide_path = ROOT / "docs" / "sel-live-verification.md"
        self.assertTrue(guide_path.is_file(), "live verification guide is required")
        guide = guide_path.read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        config = json.loads(
            (ROOT / "config.example.json").read_text(encoding="utf-8")
        )

        keychain_command = (
            "security add-generic-password -U -s sel-triage "
            "-a <credential-ref> -w"
        )
        guide_lines = {line.strip() for line in guide.splitlines()}
        self.assertIn(keychain_command, guide_lines)
        self.assertFalse(
            any(line.startswith(keychain_command + " ") for line in guide_lines)
        )
        self.assertNotIn("password", json.dumps(config).lower())

        required_safety_text = (
            "trusted VPN",
            "Access Level 1",
            "Access Level 2",
            "latest one",
            "clean logout",
            "sentinel",
            "SHA-256",
        )
        for phrase in required_safety_text:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, guide)

        required_limitations = (
            "synthetic",
            "pending live validation",
            "HIS and SER only",
            "SEL-651 only",
            "runs offline on retrieved files",
        )
        for phrase in required_limitations:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, readme)

    def test_sensitive_evidence_default_is_private_documented_and_ignored(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs" / "sel-live-verification.md").read_text(
            encoding="utf-8"
        )
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()

        self.assertIn("evidence/", ignored)
        self.assertIn("private user data", readme)
        self.assertIn("owner-only", readme)
        self.assertIn("private user data", guide)
        self.assertNotIn("defaults to `./evidence`", readme)


if __name__ == "__main__":
    unittest.main()
