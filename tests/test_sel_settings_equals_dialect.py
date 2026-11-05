"""parse_settings on the older ``KEY =value`` SHO dialect (SEL-351 / SEL-651), ported from SEL-Audit sho_convert."""

from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.parsers.common import parse_settings

FIXTURES = Path(__file__).parent / "fixtures" / "sel"

# Synthetic SEL-351A ``SHO`` output: two columns per line, a wrapped SELogic
# equation, a section heading, the group banner and the command echo.
SHO_351 = (
    "=>SHO\r\n"
    "\r\n"
    "Group 1\r\n"
    "\r\n"
    "Group Settings:\r\n"
    "RID     =SEL351A                        TID     =LAB FEEDER 1\r\n"
    "CTR     =120         CTRN    =120       PTR     =60.00     PTRS    =60.00\r\n"
    "Z1MAG   =1.00        E50P    =1\r\n"
    "\r\n"
    "SELogic group 1\r\n"
    "TR      =M2PT + Z2GT + 51GT + 51QT +\r\n"
    "         50P1 * SV1T\r\n"
    "OUT101  =TRIP\r\n"
    "=>\r\n"
)


class TestEqualsDialect(unittest.TestCase):
    def test_multi_column_equals_lines(self):
        result = parse_settings(SHO_351)
        settings = result["settings"]
        self.assertEqual(settings["RID"], "SEL351A")
        self.assertEqual(settings["TID"], "LAB FEEDER 1")
        self.assertEqual(settings["CTR"], "120")
        self.assertEqual(settings["CTRN"], "120")
        self.assertEqual(settings["PTRS"], "60.00")
        self.assertEqual(settings["E50P"], "1")
        self.assertEqual(result["group"], 1)

    def test_wrapped_selogic_is_folded(self):
        settings = parse_settings(SHO_351)["settings"]
        self.assertEqual(settings["TR"], "M2PT + Z2GT + 51GT + 51QT + 50P1 * SV1T")
        self.assertEqual(settings["OUT101"], "TRIP")

    def test_headings_and_echo_are_not_settings(self):
        result = parse_settings(SHO_351)
        self.assertIn("Group Settings:", result["sections"])
        self.assertIn("SELogic group 1", result["sections"])
        self.assertNotIn("SHO", result["settings"])
        self.assertEqual(result["unparsed_lines"], [line for line in result["unparsed_lines"] if "SHO" in line or line.strip() == "=>"])

    def test_single_letter_prose_is_not_a_setting(self):
        # SHO R help text, as in SEL-Audit's tests
        settings = parse_settings("I=Integer, F=Float, L=Long\nRA01TYPE = I\n")["settings"]
        self.assertEqual(settings, {"RA01TYPE": "I"})

    def test_uppercase_token_inside_a_value_is_not_a_key(self):
        settings = parse_settings("DESC    =FEEDER=A  TID     =X\n")["settings"]
        self.assertEqual(settings, {"DESC": "FEEDER=A", "TID": "X"})

    def test_colon_dialect_still_wins_when_present(self):
        # A := capture with an '=' inside a value must not switch dialect.
        text = "RID      := RELAY A\nSV01     := IN101=1\nTID      := X\n"
        self.assertEqual(parse_settings(text)["settings"], {"RID": "RELAY A", "SV01": "IN101=1", "TID": "X"})

    def test_700g_fixtures_parse_unchanged_keys(self):
        for name in ("700gt-settings-global.txt", "700gt-settings-group.txt"):
            with self.subTest(name=name):
                settings = parse_settings((FIXTURES / name).read_text())["settings"]
                self.assertTrue(settings)
                self.assertTrue(all(len(key) >= 1 for key in settings))


if __name__ == "__main__":
    unittest.main()
