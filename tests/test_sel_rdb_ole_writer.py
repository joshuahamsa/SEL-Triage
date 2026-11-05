"""Unit tests for (ported from SEL-Audit) :mod:`sel_triage.integrations.devices.sel.rdb.ole_writer`.

The writer's output is verified by reading it back with ``olefile`` -- the same
library used to read genuine ``.rdb`` files. Run from the repository root::

    python -m unittest discover -s tests
"""

import os
import tempfile
import unittest
from pathlib import Path


import olefile

from sel_triage.integrations.devices.sel.rdb.ole_writer import write_ole


def _round_trip(streams: dict[str, bytes]) -> dict[str, bytes]:
    """Write ``streams`` to an OLE file and read every stream back."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.rdb")
        write_ole(path, streams)
        if not olefile.isOleFile(path):
            raise AssertionError("output is not recognised as an OLE file")
        ole = olefile.OleFileIO(path)
        try:
            return {
                "/".join(parts): ole.openstream(parts).read()
                for parts in ole.listdir(streams=True, storages=False)
            }
        finally:
            ole.close()


class OleWriterRoundTripTests(unittest.TestCase):
    """Streams written by :func:`write_ole` read back byte-identical."""

    def test_single_small_stream(self):
        """A single mini-stream file round-trips."""
        streams = {"Relays/Dev/Misc/Cfg.txt": b"[INFO]\r\nRELAYTYPE=SEL-751\r\n"}
        self.assertEqual(_round_trip(streams), streams)

    def test_large_stream_uses_regular_sectors(self):
        """A stream past the 4096-byte cutoff round-trips from regular sectors."""
        streams = {"Relays/Dev/set_1.txt": bytes(range(256)) * 40}  # 10240 bytes
        self.assertEqual(_round_trip(streams), streams)

    def test_empty_stream(self):
        """A zero-length stream round-trips as empty."""
        streams = {"Relays/Dev/set_HMI.txt": b""}
        self.assertEqual(_round_trip(streams), streams)

    def test_mini_and_big_streams_mixed(self):
        """Mini and regular streams in one file are both read back correctly."""
        streams = {
            "Relays/Dev/Misc/Cfg.txt": b"C" * 300,
            "Relays/Dev/Misc/Version": b"V" * 64,
            "Relays/Dev/set_1.txt": b"1" * 8000,
            "Relays/Dev/set_G.txt": b"G" * 4096,  # exactly at the cutoff -> big
            "Relays/Dev/set_R.txt": b"R" * 4095,  # just under -> mini
        }
        self.assertEqual(_round_trip(streams), streams)

    def test_sector_boundary_sizes(self):
        """Streams sized exactly on sector boundaries round-trip."""
        streams = {
            "a.txt": b"a" * 64,  # one mini sector
            "b.txt": b"b" * 65,  # spills to a second mini sector
            "c.txt": b"c" * 512,  # one regular sector (still mini-classified)
            "d.txt": b"d" * 9216,  # exactly 18 regular sectors
        }
        self.assertEqual(_round_trip(streams), streams)

    def test_many_streams_in_one_storage(self):
        """A storage with many children exercises the sibling tree."""
        streams = {
            f"Relays/Dev/set_{name}.txt": f"settings {name}".encode()
            for name in ("1", "2", "3", "4", "G", "L1", "L2", "P1", "M", "R", "F")
        }
        self.assertEqual(_round_trip(streams), streams)

    def test_nested_storages(self):
        """Deeply nested storage paths are preserved."""
        streams = {
            "Relays/Dev/Misc/Cfg.txt": b"cfg",
            "Relays/Dev/Misc/Device.txt": b"Dev",
            "Relays/Dev/set_1.txt": b"grp1",
        }
        self.assertEqual(_round_trip(streams), streams)


if __name__ == "__main__":
    unittest.main()
