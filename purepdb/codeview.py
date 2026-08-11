"""CodeView symbol-record parsing.

Symbol records are the leaf data we ultimately care about. Each record is
length-prefixed:

    uint16 RecordLen   # bytes that follow (i.e. excluding this field)
    uint16 RecordKind  # S_* constant
    <payload>          # RecordLen - 2 bytes

We only decode the handful of record kinds needed for function discovery.
Unknown kinds are skipped using RecordLen, so the stream stays in sync.

Format reference: the record kinds and layouts are those declared in
Microsoft's `cvinfo.h`, published under the MIT license in
https://github.com/microsoft/microsoft-pdb, and documented at
https://llvm.org/docs/PDB/CodeViewSymbols.html
"""

from __future__ import annotations

import collections
from dataclasses import dataclass

from .reader import Reader

# --- symbol kinds we handle -------------------------------------------------
S_PUB32 = 0x110E       # public symbol (name + seg:off, with flags)
S_LPROC32 = 0x110F     # local (static) procedure start
S_GPROC32 = 0x1110     # global procedure start
S_LPROC32_ID = 0x1146  # same layout, type index is an ID
S_GPROC32_ID = 0x1147
S_END = 0x0006
S_PROC_ID_END = 0x114F

S_LDATA32 = 0x110C     # local (static) data symbol
S_GDATA32 = 0x110D     # global data symbol

_PROC_KINDS = frozenset({S_LPROC32, S_GPROC32, S_LPROC32_ID, S_GPROC32_ID})
_DATA_KINDS = frozenset({S_LDATA32, S_GDATA32})

# Kinds we don't decode but can name, so a diagnostic report reads as something
# other than a list of hex numbers. Not exhaustive and not meant to be.
S_OBJNAME = 0x1101
S_THUNK32 = 0x1102
S_LABEL32 = 0x1105
S_CONSTANT = 0x1107
S_UDT = 0x1108
S_BPREL32 = 0x110A
S_TRAMPOLINE = 0x112C
S_COMPILE3 = 0x113C
S_ENVBLOCK = 0x113D
S_LOCAL = 0x113E
S_INLINESITE = 0x114D
S_PROCREF = 0x1125
S_LPROCREF = 0x1127

# Managed (.NET) code. A Windows-format PDB for a managed assembly describes
# methods with these instead of S_*PROC32, keyed by metadata token rather than
# segment:offset -- so there is nothing for us to resolve to an RVA. Recognised
# only so diagnostics can say that plainly.
S_MANSLOT = 0x1120
S_GMANPROC = 0x112A
S_LMANPROC = 0x112B

MANAGED_PROC_KINDS = frozenset({S_GMANPROC, S_LMANPROC})

KIND_NAMES: dict[int, str] = {
    S_END: "S_END",
    S_OBJNAME: "S_OBJNAME",
    S_THUNK32: "S_THUNK32",
    S_LABEL32: "S_LABEL32",
    S_CONSTANT: "S_CONSTANT",
    S_UDT: "S_UDT",
    S_BPREL32: "S_BPREL32",
    S_LDATA32: "S_LDATA32",
    S_GDATA32: "S_GDATA32",
    S_PUB32: "S_PUB32",
    S_LPROC32: "S_LPROC32",
    S_GPROC32: "S_GPROC32",
    S_PROCREF: "S_PROCREF",
    S_LPROCREF: "S_LPROCREF",
    S_TRAMPOLINE: "S_TRAMPOLINE",
    S_COMPILE3: "S_COMPILE3",
    S_ENVBLOCK: "S_ENVBLOCK",
    S_LOCAL: "S_LOCAL",
    S_INLINESITE: "S_INLINESITE",
    S_LPROC32_ID: "S_LPROC32_ID",
    S_GPROC32_ID: "S_GPROC32_ID",
    S_PROC_ID_END: "S_PROC_ID_END",
    S_MANSLOT: "S_MANSLOT",
    S_GMANPROC: "S_GMANPROC",
    S_LMANPROC: "S_LMANPROC",
}


def kind_name(kind: int) -> str:
    """A readable label for a record kind; hex for the ones we can't name."""
    return KIND_NAMES.get(kind, f"{kind:#06x}")

# PublicSymFlags bits (subset)
PUBLIC_FLAG_CODE = 0x1
PUBLIC_FLAG_FUNCTION = 0x2


@dataclass
class PublicSymbol:
    name: str
    segment: int      # 1-based section index
    offset: int       # offset within the section
    flags: int
    record_offset: int = 0  # where this record sits in the symbol-record stream

    @property
    def is_function(self) -> bool:
        return bool(self.flags & PUBLIC_FLAG_FUNCTION)


@dataclass
class ProcSymbol:
    name: str
    segment: int      # 1-based section index
    offset: int       # offset within the section (== entry point)
    code_size: int
    type_index: int
    kind: int         # which S_*PROC32 record this came from

    @property
    def is_global(self) -> bool:
        return self.kind in (S_GPROC32, S_GPROC32_ID)


@dataclass
class DataSymbol:
    name: str
    segment: int      # 1-based section index
    offset: int       # offset within the section
    type_index: int
    kind: int         # S_GDATA32 or S_LDATA32

    @property
    def is_global(self) -> bool:
        return self.kind == S_GDATA32


@dataclass
class RawRecord:
    kind: int
    payload: bytes
    offset: int = 0  # byte offset of the record's length field within the stream


def iter_records(data: bytes, start: int = 0):
    """Yield RawRecord for every length-prefixed record in `data`.

    Records are padded/aligned by their length field, so we trust RecordLen
    for advancing rather than re-parsing each kind.
    """
    r = Reader(data, start)
    while r.remaining() >= 4:
        rec_start = r.pos
        rec_len = r.u16()
        if rec_len < 2:
            break  # corrupt / padding tail
        kind = r.u16()
        payload_len = rec_len - 2
        if r.remaining() < payload_len:
            break
        payload = r.bytes(payload_len)
        yield RawRecord(kind, payload, rec_start)


def parse_public(payload: bytes) -> PublicSymbol:
    r = Reader(payload)
    flags = r.u32()
    offset = r.u32()
    segment = r.u16()
    name = r.cstring()
    return PublicSymbol(name=name, segment=segment, offset=offset, flags=flags)


def parse_proc(kind: int, payload: bytes) -> ProcSymbol:
    r = Reader(payload)
    r.u32()  # Parent
    r.u32()  # End
    r.u32()  # Next
    code_size = r.u32()
    r.u32()  # DbgStart
    r.u32()  # DbgEnd
    type_index = r.u32()
    offset = r.u32()
    segment = r.u16()
    r.u8()   # ProcSymFlags
    name = r.cstring()
    return ProcSymbol(
        name=name,
        segment=segment,
        offset=offset,
        code_size=code_size,
        type_index=type_index,
        kind=kind,
    )


def parse_data(kind: int, payload: bytes) -> DataSymbol:
    r = Reader(payload)
    type_index = r.u32()
    offset = r.u32()
    segment = r.u16()
    name = r.cstring()
    return DataSymbol(
        name=name, segment=segment, offset=offset,
        type_index=type_index, kind=kind,
    )


def extract_data(data: bytes) -> list[DataSymbol]:
    out: list[DataSymbol] = []
    for rec in iter_records(data):
        if rec.kind in _DATA_KINDS:
            out.append(parse_data(rec.kind, rec.payload))
    return out


def extract_publics(data: bytes) -> list[PublicSymbol]:
    """Extract S_PUB32 records from the *symbol-record* stream.

    Not from the publics hash stream -- that one holds offsets into this one,
    and scanning it finds nothing. See `purepdb.gsi`.
    """
    out: list[PublicSymbol] = []
    for rec in iter_records(data):
        if rec.kind == S_PUB32:
            sym = parse_public(rec.payload)
            sym.record_offset = rec.offset
            out.append(sym)
    return out


def count_kinds(data: bytes) -> "collections.Counter[int]":
    """Histogram of record kinds, for diagnostics."""
    return collections.Counter(rec.kind for rec in iter_records(data))


def extract_procs(data: bytes) -> list[ProcSymbol]:
    """Extract procedure symbols from a *module* symbol substream.

    `data` should already have the leading 4-byte CV signature stripped.
    """
    out: list[ProcSymbol] = []
    for rec in iter_records(data):
        if rec.kind in _PROC_KINDS:
            out.append(parse_proc(rec.kind, rec.payload))
    return out
