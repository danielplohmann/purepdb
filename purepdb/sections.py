"""IMAGE_SECTION_HEADER table -> segment:offset to RVA resolution.

Symbol records store addresses as a 1-based `segment` index plus a byte
`offset` into that section. To get the RVA that a debugger/profiler wants:

    rva = section[segment - 1].virtual_address + offset

The section-header table is stored verbatim (as it appears in the linked
PE image) in a dedicated stream named by DBI's Optional Debug Header slot 5.
Each IMAGE_SECTION_HEADER is 40 bytes.
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
    def parse(cls, data: bytes) -> "SectionTable":
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

        Returns None if the segment index is out of range (e.g. absolute
        symbols use segment 0)."""
        if segment < 1 or segment > len(self.sections):
            return None
        return self.sections[segment - 1].virtual_address + offset

    def is_executable(self, segment: int) -> bool:
        """Whether a 1-based segment index names a code section."""
        if segment < 1 or segment > len(self.sections):
            return False
        return self.sections[segment - 1].executable
