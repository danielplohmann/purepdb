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
import struct
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

S_PROCREF = 0x1125     # globals index entry for a global procedure
S_LPROCREF = 0x1127    # ... and for a static one

PROC_KINDS = frozenset({S_LPROC32, S_GPROC32, S_LPROC32_ID, S_GPROC32_ID})
_DATA_KINDS = frozenset({S_LDATA32, S_GDATA32})
_PROC_REF_KINDS = frozenset({S_PROCREF, S_LPROCREF})

# Kinds we don't decode but can name, so a diagnostic report reads as something
# other than a list of hex numbers. Not exhaustive and not meant to be.
S_OBJNAME = 0x1101
S_THUNK32 = 0x1102
S_BLOCK32 = 0x1103
S_LABEL32 = 0x1105
S_CONSTANT = 0x1107
S_UDT = 0x1108
S_BPREL32 = 0x110B
S_REGREL32 = 0x1111
S_TRAMPOLINE = 0x112C
S_FRAMEPROC = 0x1012
S_EXPORT = 0x1138
S_CALLSITEINFO = 0x1139
S_COMPILE3 = 0x113C
S_ENVBLOCK = 0x113D
S_LOCAL = 0x113E
S_INLINESITE = 0x114D
S_INLINESITE_END = 0x114E

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
    S_FRAMEPROC: "S_FRAMEPROC",
    S_OBJNAME: "S_OBJNAME",
    S_THUNK32: "S_THUNK32",
    S_BLOCK32: "S_BLOCK32",
    S_LABEL32: "S_LABEL32",
    S_CONSTANT: "S_CONSTANT",
    S_UDT: "S_UDT",
    S_BPREL32: "S_BPREL32",
    S_REGREL32: "S_REGREL32",
    S_EXPORT: "S_EXPORT",
    S_CALLSITEINFO: "S_CALLSITEINFO",
    S_INLINESITE_END: "S_INLINESITE_END",
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


# Numeric leaves. A value below LF_NUMERIC *is* the value; at or above it, the
# tag says what follows. Only the integer leaves are decoded -- reals, complex
# numbers and the string leaves have no place in a symbol-recovery tool, and
# skipping one costs a single record rather than the stream, because each
# record's payload is bounded by its own length field.
LF_NUMERIC = 0x8000
_NUMERIC_LEAVES = {
    0x8000: "<b",  # LF_CHAR
    0x8001: "<h",  # LF_SHORT
    0x8002: "<H",  # LF_USHORT
    0x8003: "<i",  # LF_LONG
    0x8004: "<I",  # LF_ULONG
    0x8009: "<q",  # LF_QUADWORD
    0x800A: "<Q",  # LF_UQUADWORD
}


def parse_numeric(r: Reader) -> "int | None":
    """Read a numeric leaf, or None for a leaf kind we do not decode.

    On None the reader is left where the leaf started, since its length is
    exactly what is unknown -- the caller cannot read past it either.
    """
    start = r.pos
    leaf = r.u16()
    if leaf < LF_NUMERIC:
        return leaf
    fmt = _NUMERIC_LEAVES.get(leaf)
    if fmt is None:
        r.seek(start)
        return None
    return struct.unpack(fmt, r.bytes(struct.calcsize(fmt)))[0]


@dataclass
class Constant:
    """S_CONSTANT: a named compile-time value -- enumerator, `const`, `#define`
    that survived as a symbol."""

    name: str
    value: int
    type_index: int


@dataclass
class UserDefinedType:
    """S_UDT: a name bound to a type index. The type itself lives in TPI, which
    purepdb does not read, so `type_index` is carried uninterpreted."""

    name: str
    type_index: int


@dataclass
class ProcRef:
    """S_PROCREF / S_LPROCREF: the globals' index of one procedure.

    Carries a name, the module that defined it, and the byte offset of the
    S_*PROC32 record inside that module's stream -- but no address of its own.
    """

    name: str
    module_index: int  # index into DbiStream.modules
    sym_offset: int    # byte offset of the proc record in the module's stream
    kind: int          # S_PROCREF or S_LPROCREF

    @property
    def is_global(self) -> bool:
        return self.kind == S_PROCREF


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


@dataclass
class Truncation:
    """Where a record walk stopped short of the end of the buffer, and why."""

    offset: int  # byte offset of the record that could not be read
    reason: str


def iter_records(data: bytes, start: int = 0, *,
                 truncation: "list[Truncation] | None" = None):
    """Yield RawRecord for every length-prefixed record in `data`.

    Records are padded/aligned by their length field, so we trust RecordLen
    for advancing rather than re-parsing each kind.

    A malformed length ends the walk instead of raising, because a caller may
    legitimately be looking at padding rather than at records. That leaves the
    result indistinguishable from a stream that ended cleanly, so pass a list
    as `truncation` to be told: a single `Truncation` is appended to it when
    the walk stops early, and nothing is appended when the buffer is consumed.
    """
    r = Reader(data, start)
    while r.remaining() >= 4:
        rec_start = r.pos
        rec_len = r.u16()
        if rec_len < 2:
            if truncation is not None:
                truncation.append(Truncation(
                    rec_start,
                    f"record length {rec_len} is below the 2-byte minimum",
                ))
            return
        kind = r.u16()
        payload_len = rec_len - 2
        if r.remaining() < payload_len:
            if truncation is not None:
                truncation.append(Truncation(
                    rec_start,
                    f"record length {rec_len} runs "
                    f"{payload_len - r.remaining()} bytes past the end of the "
                    f"{len(data)}-byte stream",
                ))
            return
        payload = r.bytes(payload_len)
        yield RawRecord(kind, payload, rec_start)
    if r.remaining() > 0 and truncation is not None:
        truncation.append(Truncation(
            r.pos, f"{r.remaining()} trailing bytes are too few for a record header"
        ))


def parse_record(kind: int, payload: bytes):
    """Decode one record, or None for a kind we do not decode.

    Raises EOFError when the payload is shorter than the kind requires; see
    `decode_record` for the tolerant form the extractors use.
    """
    if kind == S_PUB32:
        return parse_public(payload)
    if kind in PROC_KINDS:
        return parse_proc(kind, payload)
    if kind in _DATA_KINDS:
        return parse_data(kind, payload)
    return None


def decode_record(kind: int, payload: bytes):
    """`parse_record`, but None instead of raising on a payload that is too short.

    `RecordLen` is the record's own claim about its size, and nothing checks it
    against the fixed portion its kind requires. A record that claims less than
    it needs hands a truncated payload to a parser expecting a whole one -- so
    a damaged file could raise EOFError out of `functions()`, which is exactly
    the leak `PdbError` exists to prevent. Skipping the record keeps the rest
    of the stream, and `count_malformed_records` counts what was skipped.
    """
    try:
        return parse_record(kind, payload)
    except EOFError:
        return None


def count_malformed_records(data: bytes) -> int:
    """Records whose payload is too short for the kind they claim to be."""
    total = 0
    for rec in iter_records(data):
        try:
            parse_record(rec.kind, rec.payload)
        except EOFError:
            total += 1
    return total


def find_truncation(data: bytes, start: int = 0) -> "Truncation | None":
    """Where `data` stops being a well-formed record stream, or None."""
    report: list[Truncation] = []
    for _ in iter_records(data, start, truncation=report):
        pass
    return report[0] if report else None


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


def parse_proc_ref(kind: int, payload: bytes) -> ProcRef:
    r = Reader(payload)
    r.u32()  # SumName, a name hash; zero in everything we have seen
    sym_offset = r.u32()
    module = r.u16()  # 1-based
    return ProcRef(name=r.cstring(), module_index=module - 1,
                   sym_offset=sym_offset, kind=kind)


def extract_proc_refs(data: bytes) -> list[ProcRef]:
    """S_PROCREF/S_LPROCREF from the *symbol-record* stream.

    Not from the globals stream: like the publics stream, that one holds a hash
    table of offsets into this one and scanning it for records finds nothing.
    See `purepdb.gsi`.
    """
    out: list[ProcRef] = []
    for rec in iter_records(data):
        if rec.kind not in _PROC_REF_KINDS:
            continue
        try:
            out.append(parse_proc_ref(rec.kind, rec.payload))
        except EOFError:
            continue  # shorter than the kind requires; skip it, keep the rest
    return out


def parse_constant(payload: bytes) -> "Constant | None":
    """None when the value uses a numeric leaf we do not decode: the name sits
    after the value, so an unknown length means the name cannot be found."""
    r = Reader(payload)
    type_index = r.u32()
    value = parse_numeric(r)
    if value is None:
        return None
    return Constant(name=r.cstring(), value=value, type_index=type_index)


def parse_udt(payload: bytes) -> UserDefinedType:
    r = Reader(payload)
    type_index = r.u32()
    return UserDefinedType(name=r.cstring(), type_index=type_index)


def extract_constants(data: bytes) -> list[Constant]:
    out = []
    for rec in iter_records(data):
        if rec.kind != S_CONSTANT:
            continue
        try:
            constant = parse_constant(rec.payload)
        except EOFError:
            continue  # shorter than the kind requires; skip it, keep the rest
        if constant is not None:
            out.append(constant)
    return out


def extract_udts(data: bytes) -> list[UserDefinedType]:
    out = []
    for rec in iter_records(data):
        if rec.kind != S_UDT:
            continue
        try:
            out.append(parse_udt(rec.payload))
        except EOFError:
            continue
    return out


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
            sym = decode_record(rec.kind, rec.payload)
            if sym is not None:
                out.append(sym)
    return out


def extract_publics(data: bytes) -> list[PublicSymbol]:
    """Extract S_PUB32 records from the *symbol-record* stream.

    Not from the publics hash stream -- that one holds offsets into this one,
    and scanning it finds nothing. See `purepdb.gsi`.
    """
    out: list[PublicSymbol] = []
    for rec in iter_records(data):
        if rec.kind == S_PUB32:
            sym = decode_record(rec.kind, rec.payload)
            if sym is not None:
                sym.record_offset = rec.offset
                out.append(sym)
    return out


def count_kinds(data: bytes, *,
                truncation: "list[Truncation] | None" = None) -> "collections.Counter[int]":
    """Histogram of record kinds, for diagnostics."""
    return collections.Counter(
        rec.kind for rec in iter_records(data, truncation=truncation)
    )


def extract_procs(data: bytes) -> list[ProcSymbol]:
    """Extract procedure symbols from a *module* symbol substream.

    `data` should already have the leading 4-byte CV signature stripped.
    """
    out: list[ProcSymbol] = []
    for rec in iter_records(data):
        if rec.kind in PROC_KINDS:
            proc = decode_record(rec.kind, rec.payload)
            if proc is not None:
                out.append(proc)
    return out
