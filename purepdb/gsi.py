"""Publics and globals hash streams (GSI).

DBI names two streams that are commonly mistaken for symbol containers but are
not: `PublicStreamIndex` and `GlobalStreamIndex`. Neither holds symbol records.
Both hold a hash table whose entries are *byte offsets into the symbol-record
stream* (`SymRecordStreamIndex`), which is where the records actually live.

Reading S_PUB32 records straight out of the publics stream therefore yields
nothing at all -- no exception, just an empty result. That was the shape of the
bug this module exists to prevent, so `PDB.public_symbols()` reads the
symbol-record stream and uses the publics stream only for what it genuinely
provides: an address-sorted ordering of those records.

Publics stream layout:

    PublicsStreamHeader     28 bytes
    GSIHashHeader + buckets SymHash bytes
    address map             AddrMap bytes -- uint32[] record offsets, sorted by
                                             (segment, offset) of the record
    thunk map               uint32[NumThunks]
    section map             NumSections * 8 bytes

Note that `SizeOfThunk` is the size of a thunk in *code* bytes (5 for a near
jmp), not the size of a thunk-map entry; the map entries are 4 bytes each.

Format reference: https://llvm.org/docs/PDB/PublicStream.html and
https://llvm.org/docs/PDB/GlobalStream.html
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_PUBLICS_HEADER = struct.Struct(
    "<I"   # SymHash       -- byte size of the hash-table portion
    "I"    # AddrMap       -- byte size of the address map
    "I"    # NumThunks
    "I"    # SizeOfThunk   -- code bytes per thunk, not map-entry size
    "H"    # ISectThunkTable
    "H"    # Padding
    "I"    # OffThunkTable
    "I"    # NumSections
)
assert _PUBLICS_HEADER.size == 28

# GSIHashHeader, the first 16 bytes of the hash-table portion.
_GSI_HASH_HEADER = struct.Struct("<IIII")  # VerSignature, VerHdr, HrSize, NumBuckets
GSI_HASH_SIGNATURE = 0xFFFFFFFF
GSI_HASH_VERSION_V70 = 0xEFFE0000 + 19990810


@dataclass
class PublicsStream:
    """The parsed publics hash stream.

    `addr_map` is the useful part: record offsets into the symbol-record
    stream, in ascending address order.
    """

    sym_hash_size: int
    addr_map_size: int
    num_thunks: int
    size_of_thunk: int
    thunk_table_section: int
    thunk_table_offset: int
    num_sections: int
    addr_map: list[int]

    @classmethod
    def parse(cls, data: bytes) -> PublicsStream:
        if len(data) < _PUBLICS_HEADER.size:
            raise ValueError("publics stream too small for its header")
        (sym_hash, addr_map_size, num_thunks, size_of_thunk,
         isect, _pad, off_thunk, num_sections) = _PUBLICS_HEADER.unpack_from(data, 0)

        start = _PUBLICS_HEADER.size + sym_hash
        end = start + addr_map_size
        if end > len(data):
            raise ValueError(
                f"publics address map runs past end of stream "
                f"(need {end} bytes, have {len(data)})"
            )
        n = addr_map_size // 4
        addr_map = list(struct.unpack_from(f"<{n}I", data, start)) if n else []

        return cls(
            sym_hash_size=sym_hash,
            addr_map_size=addr_map_size,
            num_thunks=num_thunks,
            size_of_thunk=size_of_thunk,
            thunk_table_section=isect,
            thunk_table_offset=off_thunk,
            num_sections=num_sections,
            addr_map=addr_map,
        )
