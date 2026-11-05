"""Unit tests for (ported from SEL-Audit) :mod:`sel_triage.integrations.devices.sel.rdb.rdb_pack`.

Run from the repository root with::

    python -m unittest discover -s tests
"""

import unittest
from pathlib import Path


from sel_triage.integrations.devices.sel.rdb.pack import (
    _is_settings_stream,
    add_record_terminators,
    overlay_set_stream,
)


class SettingsStreamNameTests(unittest.TestCase):
    """Which stream names are treated as record-terminated settings files."""

    def test_set_group_files_are_settings_streams(self):
        """set_1.txt ... set_R.txt are settings streams."""
        for name in ("set_1.txt", "set_G.txt", "set_L1.txt", "set_PF.txt"):
            self.assertTrue(_is_settings_stream(name))

    def test_set_hmi_is_a_settings_stream(self):
        """SET_HMI.TXT shares the format and is matched case-insensitively."""
        self.assertTrue(_is_settings_stream("SET_HMI.TXT"))

    def test_cfg_and_id_are_not_settings_streams(self):
        """CFG.TXT and ID.txt are not record-terminated settings streams."""
        self.assertFalse(_is_settings_stream("CFG.TXT"))
        self.assertFalse(_is_settings_stream("ID.txt"))

# A relay-native settings stream: [INFO]/[group] use plain CRLF, data lines too.
_RELAY_STREAM = (
    b"[INFO]\r\nRELAYTYPE=SEL-751\r\n[1]\r\n"
    b'RID,"SEL-751"\r\nFNOM,"60"\r\n50P1P,"OFF"\r\n'
)


class RecordTerminatorTests(unittest.TestCase):
    """Converting relay-native streams to .rdb record-terminated form."""

    def test_data_lines_gain_fs_terminator(self):
        """Each KEY,"VALUE" data line ends with 0x1C + CRLF."""
        out = add_record_terminators(_RELAY_STREAM)
        self.assertIn(b'RID,"SEL-751"\x1c\r\n', out)
        self.assertIn(b'50P1P,"OFF"\x1c\r\n', out)

    def test_info_and_group_lines_keep_plain_crlf(self):
        """The [INFO] block and [group] header are not record-terminated."""
        out = add_record_terminators(_RELAY_STREAM)
        self.assertIn(b"[INFO]\r\nRELAYTYPE=SEL-751\r\n[1]\r\n", out)
        self.assertNotIn(b"[1]\x1c", out)

    def test_idempotent(self):
        """Re-running on an already-terminated stream changes nothing."""
        once = add_record_terminators(_RELAY_STREAM)
        twice = add_record_terminators(once)
        self.assertEqual(once, twice)


class OverlayTests(unittest.TestCase):
    """Overlaying captured values onto a full-schema template stream."""

    def setUp(self):
        # Template: full schema, .rdb form. Capture: a subset, relay-native.
        self.template = (
            b"[INFO]\r\n[1]\r\n"
            b'FNOM,"60"\x1c\r\n50P1P,"OFF"\x1c\r\n25VLO,"OFF"\x1c\r\n'
        )
        self.capture = b'[INFO]\r\n[1]\r\nFNOM,"60"\r\n50P1P,"3.50"\r\n'

    def test_captured_values_override_the_template(self):
        """A key present in the capture takes the capture's value."""
        out = overlay_set_stream(self.template, self.capture)
        self.assertIn(b'50P1P,"3.50"\x1c\r\n', out)

    def test_template_only_keys_keep_their_default(self):
        """A key absent from the capture (inactive setting) keeps the default."""
        out = overlay_set_stream(self.template, self.capture)
        self.assertIn(b'25VLO,"OFF"\x1c\r\n', out)

    def test_full_schema_key_set_is_preserved(self):
        """The result keeps every template key -- the capture cannot drop one."""
        out = overlay_set_stream(self.template, self.capture)
        for key in (b"FNOM", b"50P1P", b"25VLO"):
            self.assertIn(key + b',"', out)

    def test_output_is_record_terminated(self):
        """Every overlaid data line is in .rdb form (0x1C terminated)."""
        out = overlay_set_stream(self.template, self.capture)
        data_lines = [ln for ln in out.split(b"\r\n") if b',"' in ln]
        self.assertTrue(all(ln.endswith(b"\x1c") for ln in data_lines))


if __name__ == "__main__":
    unittest.main()
