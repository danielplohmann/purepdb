"""DBI (Debug Information) stream — always stream index 3.

The DBI stream is the index of everything else. For function discovery we
extract three things from it:

  * `public_stream_index`  -> the stream holding S_PUB32 records
  * `symrecord_stream_index` -> global symbol-record stream
  * per-module `sym_stream` -> module symbol substream (S_*PROC32 live here)
  * the Optional Debug Header, whose slot 5 names the section-headers stream

The stream begins with a 64-byte header followed by seven variable-length
substreams whose sizes are given in the header, in this fixed order:
ModuleInfo, SectionContribution, SectionMap, SourceInfo, TypeServerMap,
ECSubstream, OptionalDbgHeader.

Format reference: https://llvm.org/docs/PDB/DbiStream.html
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .msf import MsfError, UnsupportedPdbError
from .reader import Reader
from .sections import SectionMapEntry, parse_section_map

# Optional Debug Header slot indices.
DBG_SECTION_HDR = 5  # array of IMAGE_SECTION_HEADER for the linked image

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

# SectionContribEntry embedded in each ModuleInfo record.
_SEC_CONTRIB = struct.Struct("<HHiiIHHII")  # 28 bytes
assert _SEC_CONTRIB.size == 28


@dataclass
class ModuleInfo:
    index: int
    module_name: str
    obj_file_name: str
    sym_stream: int          # stream index of this module's symbols (or 0xFFFF)
    sym_byte_size: int       # size of the symbol substream, incl. 4-byte sig

    @property
    def has_symbols(self) -> bool:
        return self.sym_stream != 0xFFFF and self.sym_byte_size > 4


@dataclass
class DbiStream:
    age: int
    global_stream_index: int
    public_stream_index: int
    symrecord_stream_index: int
    machine: int
    modules: list[ModuleInfo] = field(default_factory=list)
    section_map: list[SectionMapEntry] = field(default_factory=list)
    dbg_header: list[int] = field(default_factory=list)  # optional dbg header slots

    @property
    def section_header_stream(self) -> int:
        if len(self.dbg_header) > DBG_SECTION_HDR:
            return self.dbg_header[DBG_SECTION_HDR]
        return 0xFFFF

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
        r.u32()  # C11ByteSize
        r.u32()  # C13ByteSize
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
            )
        )
        idx += 1
    return mods


def _parse_dbg_header(data: bytes) -> list[int]:
    n = len(data) // 2
    if n == 0:
        return []
    return list(struct.unpack_from(f"<{n}H", data, 0))
