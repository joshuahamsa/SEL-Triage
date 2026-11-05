"""Ported from SEL-Audit ``relay_tools/ole_writer.py``.

Minimal OLE2 / Compound File Binary Format writer for building ``.rdb`` files.

A SEL ``.rdb`` relay database is an OLE2 compound document -- the same container
format as legacy ``.doc``/``.xls`` files. The ``olefile`` package can *read*
these but cannot create them, so this module implements just enough of the
writer side (the Microsoft Compound File Binary format, MS-CFB) to assemble a
valid ``.rdb`` from a set of named streams.

Scope is deliberately small and matches what ``.rdb`` files need:

* version-3 files (512-byte sectors, 64-byte mini sectors);
* the mini stream, for streams smaller than 4096 bytes;
* a balanced directory tree.

The output is verified by round-tripping through ``olefile`` in the tests.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Compound File geometry for a version-3 file.
SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_STREAM_CUTOFF = 4096
DIR_ENTRY_SIZE = 128
DIR_ENTRIES_PER_SECTOR = SECTOR_SIZE // DIR_ENTRY_SIZE  # 4
FAT_ENTRIES_PER_SECTOR = SECTOR_SIZE // 4  # 128
MAX_HEADER_DIFAT = 109  # FAT sector pointers that fit in the header

# Special FAT cell / sector-chain values.
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

# Directory entry object types.
_TYPE_STORAGE = 1
_TYPE_STREAM = 2
_TYPE_ROOT = 5

_OLE_SIGNATURE = bytes.fromhex("d0cf11e0a1b11ae1")
_MAX_NAME_CHARS = 31  # 31 UTF-16 chars + a NUL terminator = 64 bytes


@dataclass
class _Entry:
    """One directory entry -- the root, a storage (folder) or a stream."""

    name: str
    obj_type: int
    data: bytes = b""
    children: list["_Entry"] = field(default_factory=list)
    did: int = NOSTREAM
    left: int = NOSTREAM
    right: int = NOSTREAM
    child: int = NOSTREAM
    start: int = ENDOFCHAIN
    size: int = 0


def _build_tree(streams: dict[str, bytes]) -> _Entry:
    """Turn ``{path: data}`` into a storage/stream tree under a Root Entry."""
    root = _Entry("Root Entry", _TYPE_ROOT)
    for path, data in streams.items():
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        if not parts:
            raise ValueError(f"empty stream path: {path!r}")
        node = root
        for index, part in enumerate(parts):
            if len(part) > _MAX_NAME_CHARS:
                raise ValueError(f"name too long for CFBF (max 31): {part!r}")
            is_leaf = index == len(parts) - 1
            existing = next((c for c in node.children if c.name == part), None)
            if existing is None:
                existing = _Entry(
                    part, _TYPE_STREAM if is_leaf else _TYPE_STORAGE
                )
                node.children.append(existing)
            node = existing
        node.data = data
    return root


def _cfbf_sort_key(entry: _Entry) -> tuple[int, str]:
    """CFBF sibling ordering: shorter names first, then case-insensitive."""
    return (len(entry.name), entry.name.upper())


def _build_sibling_bst(nodes: list[_Entry]) -> int:
    """Build a balanced BST from CFBF-sorted siblings; return the root DID."""
    if not nodes:
        return NOSTREAM
    mid = len(nodes) // 2
    node = nodes[mid]
    node.left = _build_sibling_bst(nodes[:mid])
    node.right = _build_sibling_bst(nodes[mid + 1 :])
    return node.did


def _assign_directory(root: _Entry) -> list[_Entry]:
    """Assign directory IDs and per-storage sibling trees. Root is DID 0."""
    entries: list[_Entry] = []

    def _collect(entry: _Entry) -> None:
        entry.did = len(entries)
        entries.append(entry)
        for child in entry.children:
            _collect(child)

    _collect(root)
    for entry in entries:
        if entry.children:
            ordered = sorted(entry.children, key=_cfbf_sort_key)
            entry.child = _build_sibling_bst(ordered)
    return entries


def _encode_dir_entry(entry: _Entry) -> bytes:
    """Serialise one 128-byte directory entry."""
    raw = bytearray(DIR_ENTRY_SIZE)
    name_utf16 = entry.name.encode("utf-16-le")
    raw[0 : len(name_utf16)] = name_utf16
    struct.pack_into("<H", raw, 64, len(name_utf16) + 2)  # length incl. NUL
    raw[66] = entry.obj_type
    raw[67] = 1  # node colour: black (CFBF readers do not require red/black)
    struct.pack_into("<III", raw, 68, entry.left, entry.right, entry.child)
    struct.pack_into("<I", raw, 116, entry.start & 0xFFFFFFFF)
    struct.pack_into("<Q", raw, 120, entry.size)
    return bytes(raw)


def _empty_dir_entry() -> bytes:
    """A 128-byte unused directory slot (pads the directory to a full sector)."""
    raw = bytearray(DIR_ENTRY_SIZE)
    struct.pack_into("<III", raw, 68, NOSTREAM, NOSTREAM, NOSTREAM)
    return bytes(raw)


def _chain(fat: list[int], start: int, sector_count: int) -> None:
    """Write a sequential FAT chain of ``sector_count`` sectors from ``start``."""
    for offset in range(sector_count):
        is_last = offset == sector_count - 1
        fat[start + offset] = ENDOFCHAIN if is_last else start + offset + 1


def _ceil_div(value: int, unit: int) -> int:
    """Integer ceiling division."""
    return (value + unit - 1) // unit


def _layout_mini_stream(
    mini: list[_Entry],
) -> tuple[bytes, list[int]]:
    """Pack small streams into the mini stream and build its mini-FAT.

    Each small stream is assigned a run of 64-byte mini sectors; ``entry.start``
    becomes its first mini-sector index. Returns the concatenated mini stream
    bytes and the mini-FAT chain array.
    """
    mini_stream = bytearray()
    mini_fat: list[int] = []
    next_mini_sector = 0
    for entry in mini:
        sector_count = _ceil_div(len(entry.data), MINI_SECTOR_SIZE)
        entry.start = next_mini_sector
        entry.size = len(entry.data)
        padded = entry.data.ljust(sector_count * MINI_SECTOR_SIZE, b"\x00")
        mini_stream.extend(padded)
        for offset in range(sector_count):
            is_last = offset == sector_count - 1
            mini_fat.append(ENDOFCHAIN if is_last else next_mini_sector + offset + 1)
        next_mini_sector += sector_count
    return bytes(mini_stream), mini_fat


def write_ole(path: str, streams: dict[str, bytes]) -> None:
    """Write an OLE2 compound file containing ``streams``.

    Args:
        path: Output file path.
        streams: Maps ``/``-separated stream paths to their byte content.
            Intermediate path components become storages (folders).

    Raises:
        ValueError: If a name exceeds 31 characters or the file would need
            more than 109 FAT sectors (~7 MB, far beyond any ``.rdb``).
    """
    root = _build_tree(streams)
    entries = _assign_directory(root)
    stream_entries = [e for e in entries if e.obj_type == _TYPE_STREAM]

    # Small streams live in the mini stream; large ones get their own sectors.
    mini = [e for e in stream_entries if 0 < len(e.data) < MINI_STREAM_CUTOFF]
    big = [e for e in stream_entries if len(e.data) >= MINI_STREAM_CUTOFF]
    mini_stream, mini_fat = _layout_mini_stream(mini)
    for entry in big:
        entry.size = len(entry.data)

    # Count the sectors each region needs.
    dir_sectors = _ceil_div(len(entries), DIR_ENTRIES_PER_SECTOR)
    minifat_sectors = _ceil_div(len(mini_fat), FAT_ENTRIES_PER_SECTOR)
    mini_container_sectors = _ceil_div(len(mini_stream), SECTOR_SIZE)
    big_sector_counts = [_ceil_div(len(e.data), SECTOR_SIZE) for e in big]
    non_fat_sectors = (
        dir_sectors + minifat_sectors + mini_container_sectors + sum(big_sector_counts)
    )

    # The FAT must also describe its own sectors, so solve for its size.
    fat_sectors = 1
    while fat_sectors * FAT_ENTRIES_PER_SECTOR < non_fat_sectors + fat_sectors:
        fat_sectors += 1
    if fat_sectors > MAX_HEADER_DIFAT:
        raise ValueError("file too large for a header-only DIFAT")

    # Lay out sectors: [FAT][directory][mini-FAT][mini stream][big streams].
    cursor = fat_sectors
    dir_start = cursor
    cursor += dir_sectors
    minifat_start = cursor if minifat_sectors else ENDOFCHAIN
    cursor += minifat_sectors
    mini_container_start = cursor if mini_container_sectors else ENDOFCHAIN
    cursor += mini_container_sectors
    for entry, count in zip(big, big_sector_counts):
        entry.start = cursor
        cursor += count

    # The Root Entry owns the mini stream.
    root.start = mini_container_start
    root.size = len(mini_stream)

    # Build the FAT: chain every region, mark the FAT's own sectors.
    fat = [FREESECT] * (fat_sectors * FAT_ENTRIES_PER_SECTOR)
    for index in range(fat_sectors):
        fat[index] = FATSECT
    _chain(fat, dir_start, dir_sectors)
    if minifat_sectors:
        _chain(fat, minifat_start, minifat_sectors)
    if mini_container_sectors:
        _chain(fat, mini_container_start, mini_container_sectors)
    for entry, count in zip(big, big_sector_counts):
        _chain(fat, entry.start, count)

    # Serialise each region to whole sectors.
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    dir_bytes = b"".join(_encode_dir_entry(e) for e in entries)
    dir_bytes += _empty_dir_entry() * (
        dir_sectors * DIR_ENTRIES_PER_SECTOR - len(entries)
    )
    minifat_padded = mini_fat + [FREESECT] * (
        minifat_sectors * FAT_ENTRIES_PER_SECTOR - len(mini_fat)
    )
    minifat_bytes = struct.pack(f"<{len(minifat_padded)}I", *minifat_padded)
    mini_bytes = mini_stream.ljust(mini_container_sectors * SECTOR_SIZE, b"\x00")
    big_bytes = b"".join(
        e.data.ljust(count * SECTOR_SIZE, b"\x00")
        for e, count in zip(big, big_sector_counts)
    )

    # Header.
    header = bytearray(SECTOR_SIZE)
    header[0:8] = _OLE_SIGNATURE
    struct.pack_into("<H", header, 24, 0x003E)  # minor version
    struct.pack_into("<H", header, 26, 3)  # major version (512-byte sectors)
    struct.pack_into("<H", header, 28, 0xFFFE)  # little-endian byte order
    struct.pack_into("<H", header, 30, 9)  # sector shift: 2**9 = 512
    struct.pack_into("<H", header, 32, 6)  # mini sector shift: 2**6 = 64
    struct.pack_into("<I", header, 44, fat_sectors)
    struct.pack_into("<I", header, 48, dir_start)
    struct.pack_into("<I", header, 56, MINI_STREAM_CUTOFF)
    struct.pack_into("<I", header, 60, minifat_start)
    struct.pack_into("<I", header, 64, minifat_sectors)
    struct.pack_into("<I", header, 68, ENDOFCHAIN)  # first DIFAT sector (none)
    difat = list(range(fat_sectors)) + [FREESECT] * (MAX_HEADER_DIFAT - fat_sectors)
    struct.pack_into(f"<{MAX_HEADER_DIFAT}I", header, 76, *difat)

    with open(path, "wb") as fh:
        fh.write(header)
        fh.write(fat_bytes)
        fh.write(dir_bytes)
        fh.write(minifat_bytes)
        fh.write(mini_bytes)
        fh.write(big_bytes)
