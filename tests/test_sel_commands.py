from dataclasses import FrozenInstanceError
import unittest

from sel_triage.integrations.devices.sel.commands import (
    COMMANDS_BY_FAMILY,
    SelCommand,
)


class TestSelCommandPolicy(unittest.TestCase):
    def test_capture_backed_family_surfaces_match_adapters(self):
        self.assertEqual(
            set(COMMANDS_BY_FAMILY["sel700g"]),
            {
                "identity",
                "help",
                "status",
                "meter",
                "breaker",
                "history",
                "target",
                "eve",
                "cev",
                "ser",
                "settings_global",
                "settings_group",
                "settings_logic",
                "settings_report",
                "file_read",
                "file_show",
            },
        )
        self.assertEqual(
            set(COMMANDS_BY_FAMILY["sel751"]),
            {"identity", "help", "status", "meter", "breaker", "history", "target", "eve", "ser", "file_read", "file_show"},
        )
        self.assertEqual(
            set(COMMANDS_BY_FAMILY["sel735"]),
            {"identity", "help", "status", "meter", "history", "target", "eve", "ser", "file_read", "file_show"},
        )
        self.assertEqual(set(COMMANDS_BY_FAMILY["generic"]), {"identity", "help", "file_read", "file_show"})
        self.assertEqual(
            set(COMMANDS_BY_FAMILY["sel651"]),
            {
                "identity",
                "status",
                "meter",
                "history",
                "eve",
                "cev",
                "cev_raw",
                "ser",
                "file_read",
                "file_show",
            },
        )

    def test_settings_file_commands_are_read_only_and_name_only_settings_files(self):
        for family, commands in COMMANDS_BY_FAMILY.items():
            with self.subTest(family=family):
                self.assertEqual(commands["file_read"].wire_text, "FILE READ")
                self.assertEqual(commands["file_show"].wire_text, "FILE SHOW")
                file_verbs = {
                    command.wire_text for command in commands.values() if command.wire_text.startswith("FILE")
                }
                self.assertEqual(file_verbs, {"FILE READ", "FILE SHOW"})
        command = COMMANDS_BY_FAMILY["generic"]["file_read"]
        for name in ("CFG.TXT", "cfg.txt", "SET_1.TXT", "set_G.txt", "SET_L1.TXT", "SET_HMI.TXT", "Set_Sys.txt"):
            self.assertEqual(command.render(name), "FILE READ " + name)
        for bad in ("CFG.TXT\r\nSET", "CFG.TXT ", " CFG.TXT", "SET_.TXT", "SET_TOOLONGNAME.TXT", "EVENTS.TXT",
                    "SET_1.TXT/../X", "SET_1.CEV", "", None, 1, b"CFG.TXT"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    command.render(bad)

    def test_every_model_family_allows_ser_and_eve(self):
        for family in ("sel700g", "sel651", "sel751", "sel851", "sel351", "sel735"):
            with self.subTest(family=family):
                commands = COMMANDS_BY_FAMILY[family]
                self.assertEqual(commands["ser"].wire_text, "SER")
                self.assertEqual(commands["eve"].wire_text, "EVE")
                self.assertTrue(commands["eve"].integer_argument)
        self.assertNotIn("ser", COMMANDS_BY_FAMILY["generic"])

    def test_command_surface_contains_no_mutating_verbs(self):
        forbidden = {
            "SET",
            "OPEN",
            "CLOSE",
            "RESET",
            "CLEAR",
            "TEST",
            "TRIGGER",
            "2AC",
        }
        wires = {
            command.wire_text.split()[0].upper()
            for family in COMMANDS_BY_FAMILY.values()
            for command in family.values()
        }

        self.assertTrue(forbidden.isdisjoint(wires))

    def test_settings_recipes_only_show_settings(self):
        for family in COMMANDS_BY_FAMILY.values():
            for capability, command in family.items():
                if capability.startswith("settings_"):
                    with self.subTest(capability=capability):
                        self.assertEqual(command.wire_text.split()[0], "SHO")
                        self.assertFalse(command.integer_argument)

    def test_command_definitions_are_frozen_and_bounded(self):
        command = COMMANDS_BY_FAMILY["generic"]["identity"]

        self.assertIsInstance(command, SelCommand)
        self.assertEqual(command.capability, "identity")
        self.assertIsInstance(command.terminal_prompt, bytes)
        self.assertGreater(command.max_bytes, 0)
        with self.assertRaises(FrozenInstanceError):
            command.wire_text = "SET 1"

    def test_command_keys_match_their_capability(self):
        for family in COMMANDS_BY_FAMILY.values():
            for capability, command in family.items():
                self.assertEqual(capability, command.capability)

    def test_command_policy_outer_and_family_mappings_are_immutable(self):
        with self.assertRaises(TypeError):
            COMMANDS_BY_FAMILY["generic"] = {}
        with self.assertRaises(TypeError):
            COMMANDS_BY_FAMILY["generic"]["identity"] = SelCommand(
                "identity", "SET 1", b"=>", 1024
            )


if __name__ == "__main__":
    unittest.main()
