"""IMAGE_SECTION_HEADER table -> segment:offset to RVA resolution.

Symbol records store addresses as a 1-based `segment` index plus a byte
`offset` into that section. To get the RVA that a debugger/profiler wants:

    rva = section[segment - 1].virtual_address + offset

The section-header table is stored verbatim (as it appears in the linked
PE image) in a dedicated stream named by DBI's Optional Debug Header slot 5.
Each IMAGE_SECTION_HEADER is 40 bytes.

When that stream is absent, DBI's Section Map substream is the fallback. It
describes the same segments -- flags and length per segment, in image order --
but records no addresses: every entry's `Offset` is 0. The addresses have to be
rebuilt by laying the segments out the way the linker did, each starting at the
next multiple of the image's section alignment. See `sections_from_map`.

Format reference: the PE/COFF specification for IMAGE_SECTION_HEADER, and
https://llvm.org/docs/PDB/DbiStream.html for the Section Map substream.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_SECTION_HEADER = struct.Struct(
    "<8s"  # Name
    "I"    # VirtualSize
    "I"    # VirtualAddress
    "I"    # SizeOfRawData
    "I"    # PointerToRawData
    "I"    # PointerToRelocations
    "I"    # PointerToLinenumbers
    "H"    # NumberOfRelocations
    "H"    # NumberOfLinenumbers
    "I"    # Characteristics
)
assert _SECTION_HEADER.size == 40


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    characteristics: int = 0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))


class SectionTable:
    def __init__(self, sections: list[Section]):
        self.sections = sections

    @classmethod
    def parse(cls, data: bytes) -> SectionTable:
        n = len(data) // _SECTION_HEADER.size
        sections: list[Section] = []
        for i in range(n):
            (name, vsize, vaddr, _rawsize, _rawptr,
             _relocs, _lines, _nrelocs, _nlines, chars) = _SECTION_HEADER.unpack_from(
                data, i * _SECTION_HEADER.size
            )
            sections.append(
                Section(
                    name=name.rstrip(b"\x00").decode("ascii", errors="replace"),
                    virtual_address=vaddr,
                    virtual_size=vsize,
                    characteristics=chars,
                )
            )
        return cls(sections)

    def to_rva(self, segment: int, offset: int) -> int | None:
        """Resolve a 1-based segment + offset to an image RVA.

        Returns None when the segment index names no section, which happens for
        real symbols and is not an error:

          * segment 0 is used for absolute symbols;
          * segment `len(sections) + 1` carries Control Flow Guard load-config
            metadata (`__guard_fids_table`, `__guard_flags`, `__safe_se_handler_count`).
            MSVC emits a handful of these per image. None are function-flagged,
            so `functions()` is unaffected.
        """
        if segment < 1 or segment > len(self.sections):
            return None
        return self.sections[segment - 1].virtual_address + offset

    def is_executable(self, segment: int) -> bool:
        """Whether a 1-based segment index names a code section."""
        if segment < 1 or segment > len(self.sections):
            return False
        return self.sections[segment - 1].executable


# --- DBI Section Map --------------------------------------------------------

_SECTION_MAP_HEADER = struct.Struct("<HH")  # Count, LogCount
_SECTION_MAP_ENTRY = struct.Struct(
    "<H"   # Flags
    "H"    # Ovl
    "H"    # Group
    "H"    # Frame          -- the 1-based segment index, for a real segment
    "H"    # SectionName
    "H"    # ClassName
    "I"    # Offset         -- 0 in everything link.exe and rust-lld emit
    "I"    # SectionLength
)
assert _SECTION_MAP_ENTRY.size == 20

# OMFSegDescFlags (subset).
SEG_READ = 0x0001
SEG_WRITE = 0x0002
SEG_EXECUTE = 0x0004
SEG_IS_ABSOLUTE = 0x0200

# PE's default SectionAlignment, and the only value any fixture uses. The PDB
# does not record the image's alignment anywhere, so rebuilding addresses from
# the Section Map has to assume one.
DEFAULT_SECTION_ALIGNMENT = 0x1000


@dataclass
class SectionMapEntry:
    flags: int
    frame: int   # 1-based segment index for a real segment
    offset: int
    length: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & SEG_EXECUTE)

    @property
    def is_absolute(self) -> bool:
        """The trailing pseudo-segment for absolute symbols, not a real one."""
        return bool(self.flags & SEG_IS_ABSOLUTE)


def parse_section_map(data: bytes) -> list[SectionMapEntry]:
    """Parse the DBI Section Map substream: a 4-byte header, then 20-byte entries."""
    if len(data) < _SECTION_MAP_HEADER.size:
        return []
    (count, _log_count) = _SECTION_MAP_HEADER.unpack_from(data, 0)
    body = data[_SECTION_MAP_HEADER.size:]
    n = min(count, len(body) // _SECTION_MAP_ENTRY.size)
    out = []
    for i in range(n):
        (flags, _ovl, _group, frame, _name, _cls,
         offset, length) = _SECTION_MAP_ENTRY.unpack_from(body, i * _SECTION_MAP_ENTRY.size)
        out.append(SectionMapEntry(flags=flags, frame=frame,
                                   offset=offset, length=length))
    return out


def sections_from_map(entries: list[SectionMapEntry],
                      alignment: int = DEFAULT_SECTION_ALIGNMENT) -> list[Section]:
    """Rebuild a section table from a Section Map, for PDBs missing slot 5.

    The map records no addresses -- `Offset` is 0 throughout -- so the layout
    is reconstructed the way the linker built it: the first segment starts one
    alignment unit in, and each subsequent one at the next multiple of the
    alignment past the end of the last. That reproduces the real table exactly
    on every fixture, which is the evidence this is the right rule; it is still
    a reconstruction, and an image built with a non-default SectionAlignment
    would come out wrong.

    Names are not recoverable: `SectionName` indexes a table these PDBs do not
    populate (it is 0xFFFF throughout), so segments are named by index.

    Returns an empty list -- no reconstruction at all -- when the real segments
    are not the contiguous 1..n that positional resolution assumes. A symbol's
    segment is resolved by position in this list, so a map that numbers its
    frames otherwise would shift every address after the gap. Refusing leaves
    `Function.rva` None and `diagnose()` saying why, which is the answer this
    parser is allowed to give; a shifted address is not.
    """
    real = [e for e in entries if not e.is_absolute]
    if [e.frame for e in real] != list(range(1, len(real) + 1)):
        return []

    out: list[Section] = []
    cursor = alignment
    for entry in real:
        characteristics = 0
        if entry.executable:
            characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
        out.append(Section(
            name=f"seg{entry.frame}",
            virtual_address=cursor,
            virtual_size=entry.length,
            characteristics=characteristics,
        ))
        cursor += -(-entry.length // alignment) * alignment
    return out
