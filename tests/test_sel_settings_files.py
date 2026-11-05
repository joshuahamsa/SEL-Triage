from pathlib import Path
import unittest

from sel_triage.integrations.devices.sel.settings.files import (
    parse_banner,
    parse_cfg,
    parse_fid,
    parse_id_text,
    parse_settings_file,
)


READS = Path(__file__).parent / "fixtures" / "sel" / "reads"


def read(*parts):
    return (READS.joinpath(*parts)).read_text()


# Fixtures under fixtures/sel/reads are trimmed FILE READ captures from the
# SEL-Audit corpus with invented site names, device IDs, serials and TEST-NET
# addresses. Two values were edited on purpose (see test_sel_settings_capture).
class TestParseFid(unittest.TestCase):
    def test_splits_model_revision_and_date(self):
        self.assertEqual(
            parse_fid("SEL-751-R400-V4-Z100100-D20241031"),
            {
                "fid": "SEL-751-R400-V4-Z100100-D20241031",
                "model": "SEL-751",
                "revision": "R400",
                "version": "V4",
                "z_number": "Z100100",
                "date": "2024-10-31",
            },
        )

    def test_model_keeps_dashed_suffixes(self):
        self.assertEqual(parse_fid("SEL-651R-2-R409-V0-Z009003-D20200205")["model"], "SEL-651R-2")
        self.assertEqual(parse_fid("SEL-351S-7-R518-V1-Z107106-D20210917")["model"], "SEL-351S-7")
        self.assertEqual(parse_fid("SLBT7XX-R602-V0-Z000000-D20220826")["model"], "SLBT7XX")

    def test_unrecognized_fid_keeps_text_only(self):
        self.assertEqual(parse_fid("garbage"), {"fid": "garbage"})


class TestParseIdText(unittest.TestCase):
    def test_751_identity(self):
        result = parse_id_text(read("Alpha Solar", "192.0.2.11_2381", "20260519T165050Z", "ID.txt"))
        self.assertEqual(result["model"], "SEL-751")
        self.assertEqual(result["firmware"]["revision"], "R400")
        self.assertEqual(result["firmware"]["date"], "2024-10-31")
        self.assertEqual(result["bfid"], "SLBTIND-R100-V0-Z000000-D20230315")
        self.assertEqual(result["device_id"], "ALPHA RELAY")
        self.assertEqual(result["part_number"], "751002B0X0X0X851D20")
        self.assertEqual(result["cid"], "ABCD")
        self.assertEqual(result["devcode"], "77")
        self.assertNotIn("serial_number", result)

    def test_serial_number_when_reported(self):
        result = parse_id_text(read("Charlie Solar", "192.0.2.32_2381", "20260519T181534Z", "ID.txt"))
        self.assertEqual(result["model"], "SEL-351A")
        self.assertEqual(result["serial_number"], "1234567890")

    def test_empty_or_unparsable_text(self):
        self.assertEqual(parse_id_text("ID\r\n\r\n=>"), {})


class TestParseCfg(unittest.TestCase):
    def test_plain_class_list(self):
        result = parse_cfg(read("Alpha Solar", "192.0.2.11_2381", "20260519T165050Z", "CFG.TXT"))
        self.assertEqual(result["relay_type"], "SEL-751")
        self.assertEqual(result["fid"], "SEL-751-R400-V4-Z100100-D20241031")
        self.assertEqual(result["classes"]["G"], {"name": "Global"})

    def test_quoted_class_list_keeps_checksums(self):
        result = parse_cfg(read("Charlie Solar", "192.0.2.31_2381", "20260519T172554Z", "CFG.TXT"))
        self.assertEqual(result["relay_type"], "0651R")
        self.assertEqual(result["classes"]["G"], {"name": "Global", "checksum": "46621D7E"})


class TestParseSettingsFile(unittest.TestCase):
    def test_key_value_rows_and_class(self):
        result = parse_settings_file(read("Alpha Solar", "192.0.2.11_2381", "20260519T165050Z", "set_G.txt"))
        self.assertEqual(result["class"], "G")
        self.assertEqual(result["info"]["RELAYTYPE"], "SEL-751")
        self.assertEqual(result["settings"]["PHROT"], "ACB")
        self.assertEqual(result["unparsed_lines"], [])

    def test_dotted_851_keys(self):
        result = parse_settings_file(read("Delta Solar", "192.0.2.41_2381", "20260519T175004Z", "set_1.txt"))
        self.assertEqual(result["settings"]["Sys.PhRot"], "ABC")
        self.assertEqual(result["settings"]["CTP.Rat"], "320")

    def test_doubled_quotes_are_unescaped(self):
        text = '[INFO]\r\nRELAYTYPE=SEL-851\r\n[H]\r\nDP_01.Set,"Bkr.Sta,""Main Breaker"",CLOSED,OPEN"\r\n'
        self.assertEqual(
            parse_settings_file(text)["settings"]["DP_01.Set"], 'Bkr.Sta,"Main Breaker",CLOSED,OPEN'
        )

    def test_record_separators_and_unknown_lines(self):
        text = '[1]\r\nCTR,"200"\x1c\r\nnot a setting\r\n'
        result = parse_settings_file(text)
        self.assertEqual(result["settings"], {"CTR": "200"})
        self.assertEqual(result["unparsed_lines"], ["not a setting"])

    def test_password_like_keys_are_redacted(self):
        text = '[P1]\r\nFTPPASS,"hunter2"\r\nPW1,"x"\r\nWEBPWD,"y"\r\nSNMPCOMM,"public"\r\nFTPUSER,"FTPUSER"\r\nTR,"0"\r\n'
        settings = parse_settings_file(text)["settings"]
        self.assertEqual(settings["FTPPASS"], "[REDACTED]")
        self.assertEqual(settings["WEBPWD"], "[REDACTED]")
        self.assertEqual(settings["PW1"], "[REDACTED]")
        self.assertEqual(settings["SNMPCOMM"], "[REDACTED]")
        self.assertEqual(settings["TR"], "0")
        self.assertNotIn("hunter2", repr(parse_settings_file(text)))


class TestParseBanner(unittest.TestCase):
    def test_four_digit_year_and_time_source(self):
        text = read("Alpha Solar", "192.0.2.11_2381", "20260601T120000Z", "transcript.txt")
        self.assertEqual(
            parse_banner(text), {"relay_time": "2026-06-01T08:12:00", "time_source": "Internal"}
        )

    def test_two_digit_year_without_time_source(self):
        text = read("Charlie Solar", "192.0.2.32_2381", "20260519T181534Z", "transcript.txt")
        self.assertEqual(parse_banner(text), {"relay_time": "2026-05-19T14:15:36"})

    def test_date_format_setting(self):
        text = "X  Date: 2026/05/19  Time: 01:02:03\r\n"
        self.assertEqual(parse_banner(text, "YMD"), {"relay_time": "2026-05-19T01:02:03"})
        text = "X  Date: 19/05/2026  Time: 01:02:03\r\n"
        self.assertEqual(parse_banner(text, "DMY"), {"relay_time": "2026-05-19T01:02:03"})

    def test_keeps_nothing_but_the_banner_fields(self):
        text = ">>> ACC\r\n<<< Password: ? \r\n>>> SECRETVALUE\r\nno banner\r\n"
        self.assertEqual(parse_banner(text), {})


if __name__ == "__main__":
    unittest.main()
