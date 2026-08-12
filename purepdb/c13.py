"""C13 debug subsections: the line tables at the tail of a module stream.

A module stream is

    signature | symbols | C11 line info | C13 line info

bounded by `sym_byte_size`, `c11_byte_size` and `c13_byte_size` in that
module's DBI record. The C13 region is a series of

    uint32 Kind
    uint32 Length
    payload, padded to a 4-byte boundary

Two kinds carry what is needed to answer "which source line is this address?":

`DEBUG_S_FILECHECKSUMS` is a table of file entries, each an offset into the
`/names` string table plus a checksum. A line block names a file by the *byte
offset of its entry* in this table, not by an index, which is why the raw
offsets are kept as the key.

`DEBUG_S_LINES` gives a `(segment, offset)` base and a code size, then blocks
of line entries per file. Each entry is an offset from that base plus a packed
word: the line number in the low 24 bits, the end-of-statement delta in the
next 7, and a statement flag in the top bit. An optional column block follows
each line block when the header says so, and is stepped over.

C11 line info predates this layout and is not parsed; no PDB produced by a
supported toolchain carries any (all three fixtures have `c11_byte_size == 0`).

Format reference: https://llvm.org/docs/PDB/CodeViewSymbols.html and the
`DEBUG_S_*` subsection layouts in Microsoft's `cvinfo.h`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

DEBUG_S_LINES = 0xF2
DEBUG_S_STRINGTABLE = 0xF3
DEBUG_S_FILECHECKSUMS = 0xF4
DEBUG_S_INLINEELINES = 0xF6

# Set on a subsection the consumer should skip.
DEBUG_S_IGNORE = 0x80000000

# LineFragmentHeader.Flags
LF_HAVE_COLUMNS = 0x0001

# Two line numbers that are markers rather than lines: code the compiler
# generated with no source behind it, and code the debugger should not step
# into. sqlite3 carries three of the latter. They are reported as they appear
# -- a consumer mapping an address to a line needs to know the answer is "none
# of the source", not inherit the line before.
LINE_COMPILER_GENERATED = 0xFEEFEE
LINE_NOT_STEPPABLE = 0xF00F00
LINE_MARKERS = frozenset({LINE_COMPILER_GENERATED, LINE_NOT_STEPPABLE})

_LINE_FRAGMENT_HEADER = struct.Struct("<IHHI")  # RelocOffset, Segment, Flags, CodeSize
_LINE_BLOCK_HEADER = struct.Struct("<III")      # NameIndex, NumLines, BlockSize
_LINE_ENTRY = struct.Struct("<II")              # Offset, Flags


@dataclass
class Subsection:
    kind: int
    payload: bytes


@dataclass
class LineEntry:
    """One source line, at a `segment:offset` in the image."""

    segment: int
    offset: int
    line: int
    file_offset: int  # into the /names string table
    is_statement: bool


def iter_subsections(data: bytes):
    """Yield each C13 subsection. Stops at the first header that does not fit.

    A subsection whose kind carries `DEBUG_S_IGNORE` is stepped over rather
    than yielded: `cvinfo.h` defines the bit as "if this bit is set in a
    subsection type then ignore the subsection contents". Masking it off
    instead would turn a deliberately excluded `DEBUG_S_LINES` block into a
    live one and report line data the producer marked as not to be used.
    """
    pos = 0
    while pos + 8 <= len(data):
        kind, length = struct.unpack_from("<II", data, pos)
        pos += 8
        if length > len(data) - pos:
            return
        if not kind & DEBUG_S_IGNORE:
            yield Subsection(kind=kind, payload=data[pos : pos + length])
        pos += length
        pos += -pos % 4


def parse_file_checksums(payload: bytes) -> dict[int, int]:
    """Map each entry's byte offset -> its `/names` offset.

    The offset is the key because that is how `DEBUG_S_LINES` refers to a file.
    Entries are variable-length (the checksum is inline) and 4-byte aligned.
    """
    out: dict[int, int] = {}
    pos = 0
    while pos + 6 <= len(payload):
        entry_offset = pos
        name_offset, checksum_size, _kind = struct.unpack_from("<IBB", payload, pos)
        out[entry_offset] = name_offset
        pos += 6 + checksum_size
        pos += -pos % 4
    return out


def parse_lines(payload: bytes) -> list[LineEntry]:
    """Decode one DEBUG_S_LINES subsection."""
    if len(payload) < _LINE_FRAGMENT_HEADER.size:
        return []
    base_offset, segment, flags, _code_size = _LINE_FRAGMENT_HEADER.unpack_from(payload, 0)
    have_columns = bool(flags & LF_HAVE_COLUMNS)

    out: list[LineEntry] = []
    pos = _LINE_FRAGMENT_HEADER.size
    while pos + _LINE_BLOCK_HEADER.size <= len(payload):
        file_entry, num_lines, block_size = _LINE_BLOCK_HEADER.unpack_from(payload, pos)
        entries_at = pos + _LINE_BLOCK_HEADER.size
        needed = num_lines * _LINE_ENTRY.size
        if have_columns:
            needed += num_lines * 4
        if needed > len(payload) - entries_at:
            break

        for i in range(num_lines):
            offset, packed = _LINE_ENTRY.unpack_from(payload, entries_at + i * _LINE_ENTRY.size)
            out.append(LineEntry(
                segment=segment,
                offset=base_offset + offset,
                line=packed & 0x00FFFFFF,
                file_offset=file_entry,
                is_statement=bool(packed & 0x80000000),
            ))

        # BlockSize covers the header, the line entries and any column entries.
        # Trust it to advance, but never backwards: a zero would spin forever.
        step = block_size if block_size > _LINE_BLOCK_HEADER.size else (
            _LINE_BLOCK_HEADER.size + needed)
        pos += step
    return out
