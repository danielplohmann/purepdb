"""The IPI stream (stream 4): names for the things symbols refer to by id.

TPI and IPI share a layout -- a 56-byte header, then length-prefixed records,
with record *n* carrying type index `TypeIndexBegin + n`. purepdb reads only
IPI, and only the three record kinds that carry a name:

    LF_FUNC_ID    uint32 ParentScope; uint32 FunctionType; char Name[]
    LF_MFUNC_ID   uint32 ParentType;  uint32 FunctionType; char Name[]
    LF_STRING_ID  uint32 Id;          char Name[]

`S_INLINESITE.Inlinee` is an item id into this stream, so this is what turns an
inlined body into a name. Everything else -- the type graph itself, in TPI --
stays out of scope: nothing here decodes a type, only reads a string that
happens to live beside one.

Format reference: https://llvm.org/docs/PDB/TpiStream.html and the LF_*_ID
layouts in Microsoft's `cvinfo.h`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .codeview import iter_records
from .reader import Reader

LF_FUNC_ID = 0x1601
LF_MFUNC_ID = 0x1602
LF_STRING_ID = 0x1605

_NAMED_ID_KINDS = frozenset({LF_FUNC_ID, LF_MFUNC_ID, LF_STRING_ID})

_HEADER = struct.Struct(
    "<I"   # Version
    "I"    # HeaderSize
    "I"    # TypeIndexBegin
    "I"    # TypeIndexEnd
    "I"    # TypeRecordBytes
    "H"    # HashStreamIndex
    "H"    # HashAuxStreamIndex
    "I"    # HashKeySize
    "I"    # NumHashBuckets
    "i"    # HashValueBufferOffset
    "I"    # HashValueBufferLength
    "i"    # IndexOffsetBufferOffset
    "I"    # IndexOffsetBufferLength
    "i"    # HashAdjBufferOffset
    "I"    # HashAdjBufferLength
)
assert _HEADER.size == 56


@dataclass
class IdTable:
    """Item id -> name, for the id records that carry one."""

    names: dict[int, str] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.names)

    def get(self, item_id: int) -> str | None:
        return self.names.get(item_id)

    @classmethod
    def parse(cls, data: bytes) -> IdTable | None:
        """None when the stream is too small or its header does not fit it."""
        if len(data) < _HEADER.size:
            return None
        (_version, header_size, index_begin, _index_end,
         record_bytes, *_rest) = _HEADER.unpack_from(data, 0)
        if header_size < _HEADER.size or header_size > len(data):
            return None
        end = min(header_size + record_bytes, len(data))

        names: dict[int, str] = {}
        # Records are positional: the n'th record is index_begin + n, whether or
        # not it is a kind we decode, so every record has to be walked.
        for n, record in enumerate(iter_records(data[:end], header_size)):
            if record.kind not in _NAMED_ID_KINDS:
                continue
            r = Reader(record.payload)
            try:
                r.u32()
                if record.kind != LF_STRING_ID:
                    r.u32()
                names[index_begin + n] = r.cstring()
            except EOFError:
                continue  # shorter than the kind requires; skip it
        return cls(names=names)
