"""DBI (Debug Information) stream — always stream index 3.

The DBI stream is the index of everything else. For function discovery we
extract four things from it:

  * `public_stream_index`  -> the stream holding S_PUB32 records
  * `symrecord_stream_index` -> global symbol-record stream
  * per-module `sym_stream` -> module symbol substream (S_*PROC32 live here)
  * the Section Contribution substream -> which module each address came from
  * the Optional Debug Header, whose slot 5 names the section-headers stream

The stream begins with a 64-byte header followed by seven variable-length
substreams whose sizes are given in the header, in this fixed order:
ModuleInfo, SectionContribution, SectionMap, SourceInfo, TypeServerMap,
ECSubstream, OptionalDbgHeader.

Format reference: https://llvm.org/docs/PDB/DbiStream.html
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field

from .msf import MsfError, UnsupportedPdbError
from .reader import Reader
from .sections import SectionMapEntry, parse_section_map

# Optional Debug Header slot indices.
DBG_OMAP_TO_SRC = 3    # final image -> original image
DBG_OMAP_FROM_SRC = 4  # original image -> final image
DBG_SECTION_HDR = 5    # array of IMAGE_SECTION_HEADER for the linked image
DBG_SECTION_HDR_ORIG = 10  # the same, for the image before BBT moved code

_HEADER = struct.Struct(
    "<i"   # VersionSignature (-1)
    "I"    # VersionHeader
    "I"    # Age
    "H"    # GlobalStreamIndex
    "H"    # BuildNumber
    "H"    # PublicStreamIndex
    "H"    # PdbDllVersion
    "H"    # SymRecordStreamIndex
    "H"    # PdbDllRbld
    "i"    # ModInfoSize
    "i"    # SectionContributionSize
    "i"    # SectionMapSize
    "i"    # SourceInfoSize
    "i"    # TypeServerMapSize
    "I"    # MFCTypeServerIndex
    "i"    # OptionalDbgHeaderSize
    "i"    # ECSubstreamSize
    "H"    # Flags
    "H"    # Machine
    "I"    # Padding
)
assert _HEADER.size == 64

# SectionContribEntry, both as embedded in each ModuleInfo record and as the
# element type of the Section Contribution substream.
_SEC_CONTRIB = struct.Struct(
    "<H"   # Section (1-based)
    "H"    # Padding
    "i"    # Offset
    "i"    # Size
    "I"    # Characteristics
    "H"    # ModuleIndex
    "H"    # Padding
    "I"    # DataCrc
    "I"    # RelocCrc
)
assert _SEC_CONTRIB.size == 28

# The substream is versioned, and the version decides the entry size: V2 adds a
# trailing uint32 ISectCoff. Only Ver60 has been seen in practice.
SEC_CONTRIB_VER60 = 0xF12EBA2D
SEC_CONTRIB_V2 = 0xF13151E4
_SEC_CONTRIB_ENTRY_SIZE = {SEC_CONTRIB_VER60: 28, SEC_CONTRIB_V2: 32}


@dataclass
class ModuleInfo:
    index: int
    module_name: str
    obj_file_name: str
    sym_stream: int          # stream index of this module's symbols (or 0xFFFF)
    sym_byte_size: int       # size of the symbol substream, incl. 4-byte sig
    c11_byte_size: int = 0   # legacy line info, following the symbols
    c13_byte_size: int = 0   # C13 line info, following that

    @property
    def has_symbols(self) -> bool:
        return self.sym_stream != 0xFFFF and self.sym_byte_size > 4

    @property
    def has_lines(self) -> bool:
        return self.sym_stream != 0xFFFF and self.c13_byte_size > 0


@dataclass
class SectionContribution:
    """One linker input's claim on a range of an output section.

    The linker writes one of these per contributing `.obj`/`.lib` member per
    section, so the ranges partition the image and name what produced each
    byte -- which is what makes library code distinguishable from application
    code without guessing from names.
    """

    segment: int  # 1-based section index
    offset: int   # byte offset within that section
    size: int
    characteristics: int
    module_index: int  # index into DbiStream.modules

    def contains(self, segment: int, offset: int) -> bool:
        return self.segment == segment and self.offset <= offset < self.offset + self.size


class ContributionMap:
    """Address -> contributing module, by binary search."""

    def __init__(self, contributions: list[SectionContribution]):
        self.contributions = contributions
        # Empty contributions cover no address and real linkers emit them --
        # 348 of the 2267 in the rust-lld fixture. Leaving them in the search
        # index would let one shadow the real contribution it shares a start
        # address with. The substream is written in address order, but the
        # lookup is a binary search and a file that is not sorted would
        # otherwise answer wrongly.
        self._sorted = sorted((c for c in contributions if c.size > 0),
                              key=lambda c: (c.segment, c.offset))
        self._keys = [(c.segment, c.offset) for c in self._sorted]

    def __len__(self) -> int:
        return len(self.contributions)

    def find(self, segment: int, offset: int) -> "SectionContribution | None":
        """The contribution covering `segment:offset`, or None for a gap."""
        i = bisect.bisect_right(self._keys, (segment, offset)) - 1
        if i < 0:
            return None
        contrib = self._sorted[i]
        return contrib if contrib.contains(segment, offset) else None


@dataclass
class DbiStream:
    age: int
    global_stream_index: int
    public_stream_index: int
    symrecord_stream_index: int
    machine: int
    modules: list[ModuleInfo] = field(default_factory=list)
    section_map: list[SectionMapEntry] = field(default_factory=list)
    section_contributions: list[SectionContribution] = field(default_factory=list)
    dbg_header: list[int] = field(default_factory=list)  # optional dbg header slots

    def dbg_stream(self, slot: int) -> int:
        """The stream index in an Optional Debug Header slot, or 0xFFFF."""
        if len(self.dbg_header) > slot:
            return self.dbg_header[slot]
        return 0xFFFF

    @property
    def section_header_stream(self) -> int:
        return self.dbg_stream(DBG_SECTION_HDR)

    @property
    def original_section_header_stream(self) -> int:
        """Section headers of the pre-BBT image, present only alongside OMAP."""
        return self.dbg_stream(DBG_SECTION_HDR_ORIG)

    @property
    def omap_from_src_stream(self) -> int:
        return self.dbg_stream(DBG_OMAP_FROM_SRC)

    @property
    def omap_to_src_stream(self) -> int:
        return self.dbg_stream(DBG_OMAP_TO_SRC)

    @classmethod
    def parse(cls, data: bytes) -> "DbiStream":
        if len(data) < _HEADER.size:
            if not data:
                raise UnsupportedPdbError(
                    "the DBI stream is empty: this is a compiler-intermediate "
                    "PDB (the vc140.pdb / vc110.pdb kind that cl.exe writes "
                    "next to the .obj files), which holds types but no module "
                    "or symbol information. Use the PDB the linker produced "
                    "alongside the executable instead"
                )
            raise MsfError(
                f"DBI stream truncated: {len(data)} bytes, need at least "
                f"{_HEADER.size} for the header"
            )
        (
            _ver_sig, _ver_hdr, age,
            global_idx, _build, public_idx, _dllver, symrec_idx, _rbld,
            modinfo_size, seccontrib_size, secmap_size, srcinfo_size,
            tsmap_size, _mfc, dbg_hdr_size, ec_size, _flags, machine, _pad,
        ) = _HEADER.unpack_from(data, 0)

        self = cls(
            age=age,
            global_stream_index=global_idx,
            public_stream_index=public_idx,
            symrecord_stream_index=symrec_idx,
            machine=machine,
        )

        off = _HEADER.size
        self.modules = _parse_module_list(data[off : off + modinfo_size])
        off += modinfo_size
        self.section_contributions = _parse_section_contributions(
            data[off : off + seccontrib_size]
        )
        off += seccontrib_size
        self.section_map = parse_section_map(data[off : off + secmap_size])
        off += secmap_size
        off += srcinfo_size
        off += tsmap_size
        off += ec_size
        self.dbg_header = _parse_dbg_header(data[off : off + dbg_hdr_size])
        return self


def _parse_module_list(data: bytes) -> list[ModuleInfo]:
    """Parse the ModuleInfo substream: a packed array of variable-length
    records, each ending in two NUL-terminated strings, 4-byte aligned."""
    mods: list[ModuleInfo] = []
    r = Reader(data)
    idx = 0
    while r.remaining() >= 64:  # minimum fixed portion + 2 empty strings
        start = r.pos
        r.u32()  # Unused1
        r.bytes(_SEC_CONTRIB.size)  # SectionContr
        r.u16()  # Flags
        sym_stream = r.u16()
        sym_byte_size = r.u32()
        c11_byte_size = r.u32()
        c13_byte_size = r.u32()
        r.u16()  # SourceFileCount
        r.u16()  # Padding
        r.u32()  # Unused2
        r.u32()  # SourceFileNameIndex
        r.u32()  # PdbFilePathNameIndex
        module_name = r.cstring()
        obj_file_name = r.cstring()
        # Records are padded so the next one starts 4-byte aligned relative
        # to the substream start.
        consumed = r.pos - start
        pad = (-consumed) % 4
        r.bytes(pad)
        mods.append(
            ModuleInfo(
                index=idx,
                module_name=module_name,
                obj_file_name=obj_file_name,
                sym_stream=sym_stream,
                sym_byte_size=sym_byte_size,
                c11_byte_size=c11_byte_size,
                c13_byte_size=c13_byte_size,
            )
        )
        idx += 1
    return mods


def _parse_section_contributions(data: bytes) -> list[SectionContribution]:
    """Parse the Section Contribution substream: a version, then fixed entries.

    Returns an empty list rather than guessing when the version is one we do
    not know or the substream does not divide into whole entries -- attributing
    functions to the wrong module would be worse than not attributing them.
    """
    if len(data) < 4:
        return []
    (version,) = struct.unpack_from("<I", data, 0)
    entry_size = _SEC_CONTRIB_ENTRY_SIZE.get(version)
    body = data[4:]
    if entry_size is None or len(body) % entry_size:
        return []

    out: list[SectionContribution] = []
    for off in range(0, len(body), entry_size):
        (segment, _pad1, offset, size, chars,
         module_index, _pad2, _dcrc, _rcrc) = _SEC_CONTRIB.unpack_from(body, off)
        out.append(SectionContribution(
            segment=segment,
            offset=offset,
            size=size,
            characteristics=chars,
            module_index=module_index,
        ))
    return out


def _parse_dbg_header(data: bytes) -> list[int]:
    n = len(data) // 2
    if n == 0:
        return []
    return list(struct.unpack_from(f"<{n}H", data, 0))
