"""HELP response parsing (synthetic text in the SEL-751 layout)."""

import unittest

from sel_triage.integrations.devices.sel.settings.help import parse_help

HELP = (
    "\x03HELP\r\n\x02\r\n"
    "89CLOSE          - Close Disconnect m n \r\n"
    "                   m = L or E for 3 Pos Disconnects, n = 1-8\r\n"
    "BREAKER          - Display breaker monitor data.\r\n"
    "HSG              - Display high-impedance fault long- and short- term histogram\r\n"
    "                   data.\r\n"
    "METER            - Display metering data.\r\n"
    "SET/SHOW         - Modify or display device settings.\r\n"
    "\r\n"
    "CAUTION: For security purposes, some commands are not provided in this HELP\r\n"
    "         response.  Elevated privilege commands are described in the manual.\r\n"
    "\x03\x02\r\n=>"
)


class TestParseHelp(unittest.TestCase):
    def test_commands_and_wrapped_descriptions(self):
        result = parse_help(HELP)
        self.assertEqual([c["command"] for c in result["commands"]], ["89CLOSE", "BREAKER", "HSG", "METER", "SET/SHOW"])
        self.assertEqual(result["commands"][0]["description"], "Close Disconnect m n m = L or E for 3 Pos Disconnects, n = 1-8")
        self.assertEqual(result["commands"][2]["description"],
                         "Display high-impedance fault long- and short- term histogram data.")
        self.assertFalse(result["rejected"])

    def test_caution_is_a_note_not_a_command(self):
        notes = parse_help(HELP)["notes"]
        self.assertEqual(len(notes), 1)
        self.assertTrue(notes[0].startswith("CAUTION: For security purposes"))
        self.assertTrue(notes[0].endswith("described in the manual."))

    def test_rejected_help(self):
        for text in ("\x03HELP\r\n\x02\r\nInvalid Command\x03\x02\r\n=>",
                     '\x03HELP\r\n\x02"HELP" unknown.  Enter "HELP" for more information.\r\n\x03\x02\r\n=>'):
            with self.subTest(text=text):
                result = parse_help(text)
                self.assertTrue(result["rejected"])
                self.assertEqual(result["commands"], [])


if __name__ == "__main__":
    unittest.main()
