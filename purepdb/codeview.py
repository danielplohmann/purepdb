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
from collections.abc import Callable
from dataclasses import dataclass, field

from .reader import Reader

# --- symbol kinds we handle -------------------------------------------------
S_PUB32 = 0x110E       # public symbol (name + seg:off, with flags)
S_LPROC32 = 0x110F     # local (static) procedure start
S_GPROC32 = 0x1110     # global procedure start
S_LPROC32_ID = 0x1146  # same layout, type index is an ID
S_GPROC32_ID = 0x1147
S_LPROC32_DPC = 0x1155     # same layout again: a procedure compiled for a DPC
S_LPROC32_DPC_ID = 0x1156  # (C++ AMP) target, which cvinfo.h lists as PROCSYM32
S_END = 0x0006
S_PROC_ID_END = 0x114F

S_LDATA32 = 0x110C     # local (static) data symbol
S_GDATA32 = 0x110D     # global data symbol

S_LTHREAD32 = 0x1112   # thread-local data symbol, internal linkage
S_GTHREAD32 = 0x1113   # ... and external linkage

S_PROCREF = 0x1125     # globals index entry for a global procedure
S_LPROCREF = 0x1127    # ... and for a static one

PROC_KINDS = frozenset({S_LPROC32, S_GPROC32, S_LPROC32_ID, S_GPROC32_ID,
                        S_LPROC32_DPC, S_LPROC32_DPC_ID})
_DATA_KINDS = frozenset({S_LDATA32, S_GDATA32})
THREAD_KINDS = frozenset({S_LTHREAD32, S_GTHREAD32})
PROC_REF_KINDS = frozenset({S_PROCREF, S_LPROCREF})

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
S_ANNOTATION = 0x1019
S_SECTION = 0x1136
S_COFFGROUP = 0x1137
S_EXPORT = 0x1138
S_CALLSITEINFO = 0x1139
S_COMPILE2 = 0x1116   # what S_COMPILE3 replaced: the same facts, three-part versions
S_COMPILE3 = 0x113C
S_ENVBLOCK = 0x113D
COMPILE_KINDS = frozenset({S_COMPILE2, S_COMPILE3})
S_LOCAL = 0x113E
S_DEFRANGE = 0x113F
S_DEFRANGE_SUBFIELD = 0x1140
S_DEFRANGE_REGISTER = 0x1141
S_DEFRANGE_FRAMEPOINTER_REL = 0x1142
S_DEFRANGE_SUBFIELD_REGISTER = 0x1143
S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE = 0x1144
S_DEFRANGE_REGISTER_REL = 0x1145
S_BUILDINFO = 0x114C
S_REGISTER = 0x1106
S_UNAMESPACE = 0x1124
S_FRAMECOOKIE = 0x113A
S_FILESTATIC = 0x1153
S_ARMSWITCHTABLE = 0x1159
S_CALLEES = 0x115A
S_CALLERS = 0x115B
S_POGODATA = 0x115C
S_HEAPALLOCSITE = 0x115E
S_FASTLINK = 0x1167
S_INLINESITE = 0x114D
S_INLINESITE_END = 0x114E
S_INLINESITE2 = 0x115D  # S_INLINESITE plus an invocation count before the annotations
S_SEPCODE = 0x1132      # a code range split off from its procedure (hot/cold)
S_INLINEES = 0x1168
INLINE_SITE_KINDS = frozenset({S_INLINESITE, S_INLINESITE2})

# Managed (.NET) code. A Windows-format PDB for a managed assembly describes
# methods with these instead of S_*PROC32, keyed by metadata token rather than
# segment:offset -- so there is nothing for us to resolve to an RVA. Recognised
# only so diagnostics can say that plainly.
S_MANSLOT = 0x1120
S_GMANPROC = 0x112A
S_LMANPROC = 0x112B

MANAGED_PROC_KINDS = frozenset({S_GMANPROC, S_LMANPROC})

# One-kind sets for the extractors that want a single kind, so they can hand
# `iter_records` a filter rather than test every record themselves.
_PUBLIC_KINDS = frozenset({S_PUB32})
_THUNK_KINDS = frozenset({S_THUNK32})
_LABEL_KINDS = frozenset({S_LABEL32})
_TRAMPOLINE_KINDS = frozenset({S_TRAMPOLINE})
_CONSTANT_KINDS = frozenset({S_CONSTANT})
_UDT_KINDS = frozenset({S_UDT})

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
    S_LTHREAD32: "S_LTHREAD32",
    S_GTHREAD32: "S_GTHREAD32",
    S_PUB32: "S_PUB32",
    S_LPROC32: "S_LPROC32",
    S_GPROC32: "S_GPROC32",
    S_PROCREF: "S_PROCREF",
    S_LPROCREF: "S_LPROCREF",
    S_TRAMPOLINE: "S_TRAMPOLINE",
    S_COMPILE2: "S_COMPILE2",
    S_COMPILE3: "S_COMPILE3",
    S_ENVBLOCK: "S_ENVBLOCK",
    S_LOCAL: "S_LOCAL",
    S_ANNOTATION: "S_ANNOTATION",
    S_SECTION: "S_SECTION",
    S_COFFGROUP: "S_COFFGROUP",
    S_DEFRANGE: "S_DEFRANGE",
    S_DEFRANGE_SUBFIELD: "S_DEFRANGE_SUBFIELD",
    S_DEFRANGE_REGISTER: "S_DEFRANGE_REGISTER",
    S_DEFRANGE_FRAMEPOINTER_REL: "S_DEFRANGE_FRAMEPOINTER_REL",
    S_DEFRANGE_SUBFIELD_REGISTER: "S_DEFRANGE_SUBFIELD_REGISTER",
    S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE",
    S_DEFRANGE_REGISTER_REL: "S_DEFRANGE_REGISTER_REL",
    S_BUILDINFO: "S_BUILDINFO",
    S_REGISTER: "S_REGISTER",
    S_UNAMESPACE: "S_UNAMESPACE",
    S_FRAMECOOKIE: "S_FRAMECOOKIE",
    S_FILESTATIC: "S_FILESTATIC",
    S_ARMSWITCHTABLE: "S_ARMSWITCHTABLE",
    S_CALLEES: "S_CALLEES",
    S_CALLERS: "S_CALLERS",
    S_POGODATA: "S_POGODATA",
    S_HEAPALLOCSITE: "S_HEAPALLOCSITE",
    S_FASTLINK: "S_FASTLINK",
    S_INLINEES: "S_INLINEES",
    S_INLINESITE: "S_INLINESITE",
    S_INLINESITE2: "S_INLINESITE2",
    S_SEPCODE: "S_SEPCODE",
    S_LPROC32_ID: "S_LPROC32_ID",
    S_GPROC32_ID: "S_GPROC32_ID",
    S_LPROC32_DPC: "S_LPROC32_DPC",
    S_LPROC32_DPC_ID: "S_LPROC32_DPC_ID",
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
    end: int = 0
    """Byte offset of the record that closes this procedure's scope, in the
    module stream as stored -- signature included, like S_PROCREF's. Records
    between the procedure and it belong to it."""

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


def parse_numeric(r: Reader) -> int | None:
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


# THUNK_ORDINAL values, the tag for the variant data after a thunk's name.
THUNK_NOTYPE = 0
# 4 is THUNK_ORDINAL_LOAD and 5 and 6 are the two *trampoline* ordinals, which
# is what `llvm-pdbutil` calls "unknown load", "tramp incremental" and "branch
# island". They were named after delay-loading, which no ordinal means.
THUNK_ORDINAL_NAMES = {
    THUNK_NOTYPE: "notype",
    1: "adjustor",
    2: "vcall",
    3: "pcode",
    4: "load",
    5: "tramp-incremental",
    6: "tramp-branchisland",
}

# TRAMP_* values: which flavour of compiler-generated jump this is.
TRAMP_INCREMENTAL = 0
TRAMP_BRANCH_ISLAND = 1


@dataclass
class ThunkSymbol:
    """A named jump stub: an import thunk, an adjustor thunk, a vcall stub.

    Real code with a real name, and on x86 the name here is the *undecorated*
    one where the public at the same address carries the decoration -- so a
    thunk record is worth reading even when the address is already known.
    """

    name: str
    segment: int   # 1-based section index
    offset: int    # offset within the section
    length: int    # size of the thunk in code bytes
    ordinal: int   # THUNK_ORDINAL: what the variant data after the name is

    @property
    def ordinal_name(self) -> str:
        return THUNK_ORDINAL_NAMES.get(self.ordinal, f"{self.ordinal:#04x}")


@dataclass
class LabelSymbol:
    """S_LABEL32: a named code address inside a procedure.

    An assembly label, an exception continuation target, an interrupt-return
    point -- code with a name but not an entry point, which is why these are
    reported separately from functions rather than merged into them.
    """

    name: str
    segment: int   # 1-based section index
    offset: int    # offset within the section
    flags: int     # CV_PROCFLAGS, the same byte S_*PROC32 carries


@dataclass
class Trampoline:
    """An incremental-link jump stub. Unlike a thunk it carries no name.

    It does carry both ends of the jump, which is what makes it useful: a code
    range that is not a function, pointing at one that is.
    """

    kind: int      # TRAMP_INCREMENTAL or TRAMP_BRANCH_ISLAND
    size: int      # size of the trampoline in code bytes
    segment: int
    offset: int
    target_segment: int
    target_offset: int


# Binary annotation opcodes, the compressed instruction stream that follows an
# S_INLINESITE record. The ones that advance the code cursor are acted on; the
# line/column ones are decoded far enough to step over their operands. The one
# that *rebases* the cursor, CHANGE_CODE_OFFSET_BASE, ends the walk -- see
# `parse_inline_site`.
BA_OP_INVALID = 0
BA_OP_CODE_OFFSET = 1
BA_OP_CHANGE_CODE_OFFSET_BASE = 2
BA_OP_CHANGE_CODE_OFFSET = 3
BA_OP_CHANGE_CODE_LENGTH = 4
BA_OP_CHANGE_FILE = 5
BA_OP_CHANGE_LINE_OFFSET = 6
BA_OP_CHANGE_LINE_END_DELTA = 7
BA_OP_CHANGE_RANGE_KIND = 8
BA_OP_CHANGE_COLUMN_START = 9
BA_OP_CHANGE_COLUMN_END_DELTA = 10
BA_OP_CHANGE_CODE_OFFSET_AND_LINE_OFFSET = 11
BA_OP_CHANGE_CODE_LENGTH_AND_CODE_OFFSET = 12
BA_OP_CHANGE_COLUMN_END = 13

# Every opcode takes one compressed operand except this one, which takes two.
_BA_TWO_OPERANDS = BA_OP_CHANGE_CODE_LENGTH_AND_CODE_OFFSET


def _uncompress_at(data: bytes, pos: int) -> tuple[int | None, int]:
    """Read one compressed unsigned integer at `pos`; the value and the
    position after it.

    The top bits of the first byte give the width: 1, 2 or 4 bytes. None for
    the 4th encoding, which is not defined -- and, since operand widths are
    what keep the stream in step, means the rest cannot be read either.
    Raises IndexError past the end of `data`, which the caller treats the way
    it treats a Reader's EOFError: the walk ends.
    """
    b0 = data[pos]
    if b0 & 0x80 == 0:
        return b0, pos + 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3F) << 8) | data[pos + 1], pos + 2
    if b0 & 0xE0 == 0xC0:
        return (((b0 & 0x1F) << 24) | (data[pos + 1] << 16)
                | (data[pos + 2] << 8) | data[pos + 3]), pos + 4
    return None, pos + 1


@dataclass(slots=True)
class InlineSite:
    """S_INLINESITE: a function body the compiler pasted into another one.

    `ranges` are `(offset, length)` pairs *relative to the start of the
    enclosing procedure*, because that is how the annotations express them.
    `inlinee` is an item id into the IPI stream, not a name; `purepdb.ipi`
    turns it into one.

    `separated_ranges` are `(chunk, offset, length)` triples for code the
    annotations place in one of the procedure's separated code chunks -- the
    cold half of a hot/cold split, which MSVC's profile-guided optimiser
    writes as an `S_SEPCODE` record after the procedure's scope. `chunk` is
    1-based in the order those records appear; the offset is relative to that
    chunk's start, not the procedure's. Resolving one needs the module's
    `S_SEPCODE` records, so the two lists are kept apart.
    """

    inlinee: int
    ranges: list[tuple[int, int]] = field(default_factory=list)
    separated_ranges: list[tuple[int, int, int]] = field(default_factory=list)

    @property
    def code_size(self) -> int:
        return (sum(length for _offset, length in self.ranges)
                + sum(length for _chunk, _offset, length in self.separated_ranges))


@dataclass
class SepCode:
    """S_SEPCODE: a range of a procedure's code moved away from its body.

    Profile-guided optimisation splits a function into a hot part, which
    stays where the procedure record says, and a cold part, which the linker
    lays out elsewhere. This names the cold part: its own `segment:offset`
    and `length`, and the `segment:offset` of the procedure it belongs to.
    The record sits after the procedure's `S_END` rather than inside its
    scope, so the parent address is the link.
    """

    segment: int
    offset: int
    length: int
    flags: int
    parent_segment: int
    parent_offset: int


def parse_sepcode(payload: bytes) -> SepCode:
    r = Reader(payload)
    r.u32()  # Parent
    r.u32()  # End
    length = r.u32()
    flags = r.u32()
    offset = r.u32()
    parent_offset = r.u32()
    segment = r.u16()
    parent_segment = r.u16()
    return SepCode(segment=segment, offset=offset, length=length, flags=flags,
                   parent_segment=parent_segment, parent_offset=parent_offset)


def extract_sepcodes(data: bytes) -> list[SepCode]:
    """S_SEPCODE records, in stream order -- which is what numbers them."""
    return _decoded(parse_sepcode,
                    (r for r in iter_records(data) if r.kind == S_SEPCODE))


_INLINE_FIXED = struct.Struct("<III")  # Parent, End, Inlinee
assert _INLINE_FIXED.size == 12


def parse_inline_site(payload: bytes, kind: int = S_INLINESITE) -> InlineSite:
    """Decode the record and walk its annotations for the code it covers.

    A malformed or unrecognised annotation ends the walk: operand widths are
    what keep the stream in step, so there is nothing sensible to read past
    one. The ranges found before it are still real and are kept.

    `S_INLINESITE2` is the same record with an invocation count between the
    inlinee and the annotations; the count is stepped over, since how often a
    body was inlined is not where it is.

    The annotations are walked with an integer cursor over the payload rather
    than a Reader, and the one-byte operand -- nearly all of them -- is read
    inline: there are 1.6 million of these records in a 355 MB node.pdb,
    with nine operand bytes each on average, and a method call per byte was
    most of the cost of both `inline_sites()` and `diagnose()` on it.
    """
    fixed = _INLINE_FIXED.size + (4 if kind == S_INLINESITE2 else 0)
    if len(payload) < fixed:
        raise EOFError(f"read past end of buffer (need {fixed}, have {len(payload)})")
    _parent, _end, inlinee = _INLINE_FIXED.unpack_from(payload, 0)

    site = InlineSite(inlinee=inlinee)
    ranges = site.ranges
    separated = site.separated_ranges
    code_offset = 0
    chunk = 0  # 0 is the procedure's own body; n is its n'th separated chunk
    pos = fixed
    end = len(payload)
    try:
        while pos < end:
            opcode = payload[pos]
            pos += 1
            if opcode & 0x80:
                opcode, pos = _uncompress_at(payload, pos - 1)
            if opcode is None or opcode == BA_OP_INVALID:
                break
            if opcode > BA_OP_CHANGE_COLUMN_END:
                # An opcode outside the defined range has unknown operand
                # widths, so the bytes after it cannot be split into
                # instructions at all. Reading one operand and carrying on
                # would resynchronise on whatever happened to follow and
                # fabricate ranges from it.
                break
            first = payload[pos]
            pos += 1
            if first & 0x80:
                first, pos = _uncompress_at(payload, pos - 1)
                if first is None:
                    break
            # The cursor is a running offset from the start of the chunk the
            # ranges are in. The two opcodes that close a range treat it
            # differently, and the difference is not a matter of taste: a
            # standalone length is "length of code, default next start" in
            # cvinfo.h, so the next delta is measured from the end of the
            # range it closed; the length fused into
            # ChangeCodeLengthAndCodeOffset does *not* move the cursor, and
            # the next delta is measured from where that range began. Treating
            # the two alike -- which this parser did until 0.6.0 -- placed the
            # second and later ranges of an MSVC site past the end of the
            # procedure 5582 times in one python312.pdb, and past the end of
            # the cold chunk they were in; measured from the range's start,
            # none of 79187 ranges overflows or overlaps. It is also the
            # reading llvm-pdbutil has always used.
            if opcode == _BA_TWO_OPERANDS:
                # The only opcode taking two operands, handled here so the
                # second one is read and used in the same place.
                second, pos = _uncompress_at(payload, pos)
                if second is None:
                    break
                code_offset += second
                if chunk == 0:
                    ranges.append((code_offset, first))
                else:
                    separated.append((chunk, code_offset, first))
            elif opcode in (BA_OP_CODE_OFFSET, BA_OP_CHANGE_CODE_OFFSET):
                code_offset += first
            elif opcode == BA_OP_CHANGE_CODE_OFFSET_AND_LINE_OFFSET:
                # One operand packs both: the code delta in the low 4 bits.
                code_offset += first & 0xF
            elif opcode == BA_OP_CHANGE_CODE_LENGTH:
                if chunk == 0:
                    ranges.append((code_offset, first))
                else:
                    separated.append((chunk, code_offset, first))
                code_offset += first
            elif opcode == BA_OP_CHANGE_CODE_OFFSET_BASE:
                # "nth separated code chunk (main code chunk == 0)", per
                # cvinfo.h: the ranges that follow are in the procedure's
                # n'th S_SEPCODE chunk, measured from its start. MSVC's
                # profile-guided optimiser emits it first thing for a body
                # inlined into the cold half of a split function -- 21 of
                # the 103 sites in a python 3.12 _bz2.pdb -- and every one
                # of those used to be dropped as describing no code.
                chunk = first
                code_offset = 0
    except IndexError:
        # An operand cut off by the end of the payload, which is what a
        # Reader reported as EOFError: the ranges already found stand.
        pass
    return site


def parse_inline_site_record(kind: int, payload: bytes) -> InlineSite:
    """`parse_inline_site` in the `(kind, payload)` convention the dispatch uses."""
    return parse_inline_site(payload, kind)


def extract_inline_sites(data: bytes) -> list[tuple[int, InlineSite]]:
    """Every S_INLINESITE in a module symbol region, with its record offset.

    A record whose payload is shorter than the fixed portion the kind requires
    is skipped: RecordLen is the record's own claim, and a short one would
    otherwise raise out of the public API.
    """
    out = []
    for rec in iter_records(data, kinds=INLINE_SITE_KINDS):
        try:
            out.append((rec.offset, parse_inline_site(rec.payload, rec.kind)))
        except EOFError:
            continue
    return out


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
class ThreadLocalSymbol:
    """S_GTHREAD32/S_LTHREAD32: a `__declspec(thread)` or `thread_local` variable.

    The fixed portion is laid out exactly like `DataSymbol`'s, and the type is
    separate for what the address *means* rather than for how it is read.
    `segment:offset` points into the image's TLS initialisation template -- the
    bytes each new thread's copy is initialised from -- and not at the variable,
    which lives at a per-thread address computed from the TEB at runtime and is
    in no section of the image at all.
    """

    name: str
    segment: int      # 1-based section index, the .tls section in practice
    offset: int       # offset within the TLS template, not within the image
    type_index: int
    kind: int         # S_GTHREAD32 or S_LTHREAD32

    @property
    def is_global(self) -> bool:
        return self.kind == S_GTHREAD32


@dataclass(slots=True)
class RawRecord:
    """One record as the walk found it. Slotted: one is built per record the
    caller asked for, which for `count_kinds` is every record in the file."""

    kind: int
    payload: bytes
    offset: int = 0  # byte offset of the record's length field within the stream


@dataclass
class Truncation:
    """Where a record walk stopped short of the end of the buffer, and why."""

    offset: int  # byte offset of the record that could not be read
    reason: str
    ragged_tail: bool = False
    """True when the walk ran out with fewer than 4 bytes left, rather than
    abandoning readable ones.

    Those bytes cannot hold a record header, so nothing is recoverable either
    way -- but nothing is provably lost either. It is padding from a producer
    that does not 4-align, or a file cut inside a header, and the two are
    indistinguishable from here. The other two shapes *do* abandon readable
    bytes, and callers should say so differently."""


_RECORD_HEADER = struct.Struct("<HH")  # RecordLen, RecordKind
assert _RECORD_HEADER.size == 4


def iter_records(data: bytes, start: int = 0, *,
                 kinds: frozenset[int] | None = None,
                 truncation: list[Truncation] | None = None):
    """Yield RawRecord for every length-prefixed record in `data`.

    Records are padded/aligned by their length field, so we trust RecordLen
    for advancing rather than re-parsing each kind.

    `kinds` narrows what is *yielded*, not what is walked: every record is
    still stepped over by its length, so the walk stays in sync and the
    truncation report is the same whatever the filter. What it saves is a
    payload slice and a RawRecord per record the caller would have discarded
    on sight -- which, for an extractor after one kind, is nearly all of them.
    This walk is the hottest loop in the parser (three quarters of the time
    of every listing on a 3 MB file before it was written this way), which is
    why it reads the header with one `unpack_from` rather than through a
    `Reader`: the cursor object cost two slices, two unpacks and two bounds
    checks per record for a header that is one struct.

    A malformed length ends the walk instead of raising, because a caller may
    legitimately be looking at padding rather than at records. That leaves the
    result indistinguishable from a stream that ended cleanly, so pass a list
    as `truncation` to be told: a single `Truncation` is appended to it when
    the walk stops early, and nothing is appended when the buffer is consumed.
    """
    unpack = _RECORD_HEADER.unpack_from
    end = len(data)
    pos = start
    while end - pos >= 4:
        rec_len, kind = unpack(data, pos)
        if rec_len < 2:
            if truncation is not None:
                truncation.append(Truncation(
                    pos, f"record length {rec_len} is below the 2-byte minimum",
                ))
            return
        payload_len = rec_len - 2
        body = pos + 4
        if end - body < payload_len:
            if truncation is not None:
                truncation.append(Truncation(
                    pos,
                    f"record length {rec_len} runs "
                    f"{payload_len - (end - body)} bytes past the end of the "
                    f"{end}-byte stream",
                ))
            return
        if kinds is None or kind in kinds:
            yield RawRecord(kind, data[body : body + payload_len], pos)
        pos = body + payload_len
    if end - pos > 0 and truncation is not None:
        truncation.append(Truncation(
            pos, f"{end - pos} trailing bytes are too few for a record header",
            ragged_tail=True,
        ))


def parse_record(kind: int, payload: bytes):
    """Decode one record, or None for a kind we do not decode.

    Every kind with a parser is dispatched here, because this is also what
    `count_malformed_records` asks "is this record shorter than it claims to
    be?" with. A kind missing from `_RECORD_PARSERS` is one whose damaged
    records are dropped by the extractors and counted by nothing -- a symbol
    that vanishes with no diagnostic, which is the one failure this parser must
    not have.

    That covers every record a parser rejects by *raising*. Two kinds can also
    be dropped without an exception -- a constant whose numeric leaf we do not
    decode, and an inline site whose annotations place no code -- which is what
    `count_undecoded_constants` and `Diagnostics.unplaced_inline_sites` are for.

    Raises EOFError when the payload is shorter than the kind requires; see
    `decode_record` for the tolerant form the extractors use.
    """
    parser = _RECORD_PARSERS.get(kind)
    if parser is None:
        return None
    return parser(kind, payload)


# `_RECORD_PARSERS` and `DISPATCHED_KINDS` are assembled at the foot of this
# module, because the parsers they name are defined below this point.


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


def count_malformed_records(data: bytes, kind: int | None = None) -> int:
    """Records whose payload is too short for the kind they claim to be.

    `kind` narrows the count to one kind, which is how a caller separates a
    record it could not parse from one it parsed and could not use.
    """
    # Only a dispatched kind can be malformed in this sense, so the walk is
    # asked for those alone; an undispatched record costs a header read and
    # nothing else.
    wanted = DISPATCHED_KINDS if kind is None else frozenset({kind})
    total = 0
    for rec in iter_records(data, kinds=wanted):
        try:
            parse_record(rec.kind, rec.payload)
        except EOFError:
            total += 1
    return total


@dataclass
class RecordSurvey:
    """Everything one walk of a record stream can say about it, for diagnostics.

    `count_kinds`, `count_malformed_records` and `find_truncation` each answer
    one question with one walk; `diagnose()` asks all three of every module
    stream, then walked them again for the procedures and inline sites. This
    is the one walk that answers all of it, so a 400 MB file is read once.
    """

    kinds: collections.Counter[int] = field(default_factory=collections.Counter)
    malformed: collections.Counter[int] = field(default_factory=collections.Counter)
    """Per kind: records shorter than the kind requires. Its total is what
    `count_malformed_records` answers, and its entry for a kind is what the
    same function narrowed to that kind answers."""
    kept: list[tuple[int, int, object]] = field(default_factory=list)
    """`(offset, kind, decoded)` for the kinds the caller asked to keep, in
    stream order. Only records that decoded are here; a short one is in
    `malformed` instead, which keeps the two disjoint the way the extractors
    and `count_malformed_records` keep them."""


def survey_records(data: bytes, *, keep: frozenset[int] = frozenset(),
                   truncation: list[Truncation] | None = None,
                   parse: frozenset[int] | None = None) -> RecordSurvey:
    """Count every record by kind, try dispatched parsers, keep some.

    Trying the parser on every dispatched kind is what makes `malformed`
    exactly `count_malformed_records`'s answer, and it means a procedure or
    an inline site the caller wants has already been decoded by the time it
    is asked for, so `keep` costs nothing more than holding the result.

    `parse` narrows which kinds are decoded. The histogram still counts
    every record. `diagnose()` uses this to skip inline sites: they are
    parsed on a later walk so the millions in one xul.pdb module are not
    held next to the procs and sepcodes they need to be placed against.
    """
    survey = RecordSurvey()
    kinds = survey.kinds
    malformed = survey.malformed
    kept = survey.kept
    parsers = _RECORD_PARSERS
    parse_kinds = DISPATCHED_KINDS if parse is None else parse
    for rec in iter_records(data, truncation=truncation):
        kind = rec.kind
        kinds[kind] += 1
        if kind not in parse_kinds:
            continue
        parser = parsers.get(kind)
        if parser is None:
            continue
        try:
            decoded = parser(kind, rec.payload)
        except EOFError:
            malformed[kind] += 1
            continue
        if kind in keep:
            kept.append((rec.offset, kind, decoded))
    return survey


def find_truncation(data: bytes, start: int = 0) -> Truncation | None:
    """Where `data` stops being a well-formed record stream, or None."""
    report: list[Truncation] = []
    for _ in iter_records(data, start, truncation=report):
        pass
    return report[0] if report else None


# The fixed portion of each named record, as one struct. A parser reads it
# with a single unpack_from and finds the name's NUL with one `find`, rather
# than walking a Reader field by field -- eight or nine method calls per
# record, and parse_proc alone runs 35k times on a 20 MB PDB. The failure
# contract is the Reader's: EOFError when the payload is shorter than the
# fixed portion or the name has no terminator, which is what the extractors
# and `count_malformed_records` catch.
_PUBLIC_FIXED = struct.Struct("<IIH")          # Flags, Offset, Segment
assert _PUBLIC_FIXED.size == 10
_PROC_FIXED = struct.Struct(
    "<I"   # Parent
    "I"    # End
    "I"    # Next
    "I"    # CodeSize
    "I"    # DbgStart
    "I"    # DbgEnd
    "I"    # FunctionType
    "I"    # CodeOffset
    "H"    # Segment
    "B"    # Flags
)
assert _PROC_FIXED.size == 35
_PROC_REF_FIXED = struct.Struct("<IIH")        # SumName, SymOffset, Module
assert _PROC_REF_FIXED.size == 10
_DATA_FIXED = struct.Struct("<IIH")            # Type, DataOffset, Segment
assert _DATA_FIXED.size == 10
_LABEL_FIXED = struct.Struct("<IHB")           # CodeOffset, Segment, Flags
assert _LABEL_FIXED.size == 7
_THUNK_FIXED = struct.Struct("<IIIIHHB")  # Parent, End, Next, Offset, Segment, Length, Ordinal
assert _THUNK_FIXED.size == 21
_UDT_FIXED = struct.Struct("<I")               # Type
assert _UDT_FIXED.size == 4
_COMPILE3_FIXED = struct.Struct("<IH4H4H")     # Flags, Machine, frontend x4, backend x4
assert _COMPILE3_FIXED.size == 22
_TRAMPOLINE = struct.Struct("<HHIIHH")   # Type, Size, ThunkOff, TargetOff, ThunkSect, TargetSect
assert _TRAMPOLINE.size == 16


def _fixed_then_name(payload: bytes, fixed: struct.Struct) -> tuple[tuple, str]:
    """The fixed fields, then the NUL-terminated name that follows them."""
    size = fixed.size
    if len(payload) < size:
        raise EOFError(f"read past end of buffer (need {size}, have {len(payload)})")
    end = payload.find(b"\x00", size)
    if end == -1:
        raise EOFError("unterminated C string")
    return fixed.unpack_from(payload, 0), payload[size:end].decode("utf-8", errors="replace")


def parse_public(payload: bytes) -> PublicSymbol:
    (flags, offset, segment), name = _fixed_then_name(payload, _PUBLIC_FIXED)
    return PublicSymbol(name=name, segment=segment, offset=offset, flags=flags)


def parse_proc(kind: int, payload: bytes) -> ProcSymbol:
    (_parent, end, _next, code_size, _dbg_start, _dbg_end, type_index, offset,
     segment, _flags), name = _fixed_then_name(payload, _PROC_FIXED)
    return ProcSymbol(
        name=name,
        segment=segment,
        offset=offset,
        code_size=code_size,
        type_index=type_index,
        kind=kind,
        end=end,
    )


def parse_proc_ref(kind: int, payload: bytes) -> ProcRef:
    # SumName is a name hash, zero in everything we have seen; Module is
    # 1-based.
    (_sum_name, sym_offset, module), name = _fixed_then_name(payload, _PROC_REF_FIXED)
    return ProcRef(name=name, module_index=module - 1,
                   sym_offset=sym_offset, kind=kind)


def extract_proc_refs(data: bytes) -> list[ProcRef]:
    """S_PROCREF/S_LPROCREF from the *symbol-record* stream.

    Not from the globals stream: like the publics stream, that one holds a hash
    table of offsets into this one and scanning it for records finds nothing.
    See `purepdb.gsi`.
    """
    out: list[ProcRef] = []
    for rec in iter_records(data, kinds=PROC_REF_KINDS):
        try:
            out.append(parse_proc_ref(rec.kind, rec.payload))
        except EOFError:
            continue  # shorter than the kind requires; skip it, keep the rest
    return out


def parse_constant(payload: bytes) -> Constant | None:
    """None when the value uses a numeric leaf we do not decode: the name sits
    after the value, so an unknown length means the name cannot be found."""
    r = Reader(payload)
    type_index = r.u32()
    value = parse_numeric(r)
    if value is None:
        return None
    return Constant(name=r.cstring(), value=value, type_index=type_index)


def parse_udt(payload: bytes) -> UserDefinedType:
    (type_index,), name = _fixed_then_name(payload, _UDT_FIXED)
    return UserDefinedType(name=name, type_index=type_index)


def extract_constants(data: bytes) -> list[Constant]:
    out = []
    for rec in iter_records(data, kinds=_CONSTANT_KINDS):
        try:
            constant = parse_constant(rec.payload)
        except EOFError:
            continue  # shorter than the kind requires; skip it, keep the rest
        if constant is not None:
            out.append(constant)
    return out


def count_undecoded_constants(data: bytes) -> int:
    """S_CONSTANT records whose value uses a numeric leaf we do not decode.

    These are not malformed -- the record is exactly what it claims to be --
    so `count_malformed_records` does not see them, and `parse_constant`
    answers None rather than raising. But the name sits *after* the value, so
    an unknown value length loses the name too: the record is dropped, and
    without this nothing would say so. A `constexpr float` is the everyday
    case; no fixture in the corpus has one.
    """
    total = 0
    for rec in iter_records(data, kinds=_CONSTANT_KINDS):
        try:
            if parse_constant(rec.payload) is None:
                total += 1
        except EOFError:
            continue  # short for its kind, which `count_malformed_records` has
    return total


def extract_udts(data: bytes) -> list[UserDefinedType]:
    out = []
    for rec in iter_records(data, kinds=_UDT_KINDS):
        try:
            out.append(parse_udt(rec.payload))
        except EOFError:
            continue
    return out


# CV_CFL_LANG, the source-language field of S_COMPILE3. Values as declared in
# cvinfo.h and llvm/DebugInfo/CodeView/CodeViewLanguages.def; the two character
# codes at the end are the outliers that file records as such.
LANGUAGE_NAMES: dict[int, str] = {
    0x00: "C",
    0x01: "C++",
    0x02: "Fortran",
    0x03: "MASM",
    0x04: "Pascal",
    0x05: "Basic",
    0x06: "COBOL",
    0x07: "Link",
    0x08: "cvtres",
    0x09: "cvtpgd",
    0x0A: "C#",
    0x0B: "Visual Basic",
    0x0C: "ILAsm",
    0x0D: "Java",
    0x0E: "JScript",
    0x0F: "MSIL",
    0x10: "HLSL",
    0x11: "Objective-C",
    0x12: "Objective-C++",
    0x13: "Swift",
    0x14: "AliasObj",
    0x15: "Rust",
    0x16: "Go",
    0x44: "D",           # 'D'
    0x53: "Swift",       # 'S', what older Swift compilers emitted
}

# CV_CPU_TYPE_e, the target field of S_COMPILE3. Same sources.
CPU_NAMES: dict[int, str] = {
    0x00: "Intel 8080",
    0x01: "Intel 8086",
    0x02: "Intel 80286",
    0x03: "Intel 80386",
    0x04: "Intel 80486",
    0x05: "Pentium",
    0x06: "Pentium Pro",
    0x07: "Pentium III",
    0x10: "MIPS",
    0x11: "MIPS16",
    0x12: "MIPS32",
    0x13: "MIPS64",
    0x14: "MIPS I",
    0x15: "MIPS II",
    0x16: "MIPS III",
    0x17: "MIPS IV",
    0x18: "MIPS V",
    0x20: "M68000",
    0x21: "M68010",
    0x22: "M68020",
    0x23: "M68030",
    0x24: "M68040",
    0x30: "Alpha",
    0x31: "Alpha 21164",
    0x32: "Alpha 21164A",
    0x33: "Alpha 21264",
    0x34: "Alpha 21364",
    0x40: "PPC 601",
    0x41: "PPC 603",
    0x42: "PPC 604",
    0x43: "PPC 620",
    0x44: "PPC FP",
    0x45: "PPC BE",
    0x50: "SH3",
    0x51: "SH3E",
    0x52: "SH3DSP",
    0x53: "SH4",
    0x54: "SHmedia",
    0x60: "ARM3",
    0x61: "ARM4",
    0x62: "ARM4T",
    0x63: "ARM5",
    0x64: "ARM5T",
    0x65: "ARM6",
    0x66: "ARM XMAC",
    0x67: "ARM WMMX",
    0x68: "ARM7",
    0x70: "Omni",
    0x80: "IA64",
    0x81: "IA64-2",
    0x90: "CEE",
    0xA0: "AM33",
    0xB0: "M32R",
    0xC0: "TriCore",
    0xD0: "x64",
    0xE0: "EBC",
    0xF0: "Thumb",
    0xF4: "ARM NT",
    0xF6: "ARM64",
    0xF7: "Hybrid x86-ARM64",
    0xF8: "ARM64EC",
    0xF9: "ARM64X",
    0xFF: "unknown",
    0x100: "D3D11 shader",
}


@dataclass
class CompileInfo:
    """S_COMPILE3: which compiler produced a module, and for what target.

    `language` states what a name-shape heuristic can only guess at -- Rust,
    C++, or the linker's own contribution -- and it is per module, which is why
    `module` is carried alongside it.
    """

    language: int
    machine: int
    frontend: tuple[int, int, int, int]  # major, minor, build, QFE
    backend: tuple[int, int, int, int]
    compiler: str    # free text, e.g. "clang LLVM (rustc version 1.94.1 ...)"
    module: str = ""
    """The linker input this came from, as DBI names it. Filled in by
    `PDB.compile_info()`, which is what knows the module."""

    @property
    def language_name(self) -> str:
        return LANGUAGE_NAMES.get(self.language, f"{self.language:#04x}")

    @property
    def machine_name(self) -> str:
        return CPU_NAMES.get(self.machine, f"{self.machine:#06x}")


def parse_compile_info(payload: bytes) -> CompileInfo:
    # The language is the low byte of the flags; the rest are feature bits.
    (flags, machine, *versions), compiler = _fixed_then_name(payload, _COMPILE3_FIXED)
    fe_major, fe_minor, fe_build, fe_qfe, be_major, be_minor, be_build, be_qfe = versions
    return CompileInfo(
        language=flags & 0xFF,
        machine=machine,
        frontend=(fe_major, fe_minor, fe_build, fe_qfe),
        backend=(be_major, be_minor, be_build, be_qfe),
        compiler=compiler,
    )


def parse_compile2(payload: bytes) -> CompileInfo:
    """S_COMPILE2, the record S_COMPILE3 replaced in VS2010.

    The same fields with three-part version numbers -- no QFE -- and an
    optional block of NUL-terminated strings after the version string, which
    is not read. A VS2008 python27.pdb carries eleven of these beside 500
    S_COMPILE3 records (the modules the linker synthesised), and a toolchain
    of that age writes nothing else. `cvinfo.h` calls the version string
    length-prefixed, which is the `_ST` form; the SZ record that this kind
    is holds a NUL-terminated one, and `link.exe` 9.00 writes it so.
    """
    r = Reader(payload)
    flags = r.u32()
    machine = r.u16()
    frontend = (r.u16(), r.u16(), r.u16(), 0)
    backend = (r.u16(), r.u16(), r.u16(), 0)
    return CompileInfo(
        language=flags & 0xFF,
        machine=machine,
        frontend=frontend,
        backend=backend,
        compiler=r.cstring(),
    )


def extract_compile_infos(data: bytes) -> list[CompileInfo]:
    """Every S_COMPILE3 (or S_COMPILE2) in one module's symbol region.

    A module is not limited to one. An import library arrives as a single DBI
    module holding the records of every member `.obj` in it, so those modules
    carry one identical record per import -- 25 of them in one module of the
    sqlite x64 fixture. Reporting only the first would undercount the file by
    half.
    """
    out: list[CompileInfo] = []
    for rec in iter_records(data, kinds=COMPILE_KINDS):
        info = decode_record(rec.kind, rec.payload)
        if info is not None:
            out.append(info)
    return out


def parse_thunk(payload: bytes) -> ThunkSymbol:
    (_parent, _end, _next, offset, segment, length,
     ordinal), name = _fixed_then_name(payload, _THUNK_FIXED)
    # Variant data keyed by `ordinal` follows the name; we do not decode it.
    return ThunkSymbol(name=name, segment=segment, offset=offset,
                       length=length, ordinal=ordinal)


def parse_label(payload: bytes) -> LabelSymbol:
    (offset, segment, flags), name = _fixed_then_name(payload, _LABEL_FIXED)
    return LabelSymbol(name=name, segment=segment, offset=offset, flags=flags)


def parse_trampoline(payload: bytes) -> Trampoline:
    if len(payload) < _TRAMPOLINE.size:
        raise EOFError(f"read past end of buffer (need {_TRAMPOLINE.size}, "
                       f"have {len(payload)})")
    (kind, size, offset, target_offset, segment,
     target_segment) = _TRAMPOLINE.unpack_from(payload, 0)
    return Trampoline(kind=kind, size=size, segment=segment, offset=offset,
                      target_segment=target_segment, target_offset=target_offset)


def _decoded(parse, records):
    """Run `parse` over each record, skipping any whose payload is shorter than
    the kind requires -- RecordLen is the record's own claim, and a short one
    would otherwise raise out of the public API."""
    out = []
    for rec in records:
        try:
            out.append(parse(rec.payload))
        except EOFError:
            continue
    return out


def extract_thunks(data: bytes) -> list[ThunkSymbol]:
    """S_THUNK32 records. The scope each opens is closed by a later S_END,
    which the flat record walk steps over like any other record."""
    return _decoded(parse_thunk, iter_records(data, kinds=_THUNK_KINDS))


def extract_trampolines(data: bytes) -> list[Trampoline]:
    return _decoded(parse_trampoline, iter_records(data, kinds=_TRAMPOLINE_KINDS))


def extract_labels(data: bytes) -> list[LabelSymbol]:
    """S_LABEL32 records. They sit inside a procedure's scope, which the flat
    record walk steps through like any other nesting."""
    return _decoded(parse_label, iter_records(data, kinds=_LABEL_KINDS))


def parse_data(kind: int, payload: bytes) -> DataSymbol:
    (type_index, offset, segment), name = _fixed_then_name(payload, _DATA_FIXED)
    return DataSymbol(
        name=name, segment=segment, offset=offset,
        type_index=type_index, kind=kind,
    )


def parse_thread_local(kind: int, payload: bytes) -> ThreadLocalSymbol:
    """Same fixed portion as `parse_data`; see `ThreadLocalSymbol` for why the
    address it carries is not the same kind of address."""
    (type_index, offset, segment), name = _fixed_then_name(payload, _DATA_FIXED)
    return ThreadLocalSymbol(
        name=name, segment=segment, offset=offset,
        type_index=type_index, kind=kind,
    )


def extract_thread_locals(data: bytes) -> list[ThreadLocalSymbol]:
    out: list[ThreadLocalSymbol] = []
    for rec in iter_records(data, kinds=THREAD_KINDS):
        sym = decode_record(rec.kind, rec.payload)
        if sym is not None:
            out.append(sym)
    return out


def extract_data(data: bytes) -> list[DataSymbol]:
    out: list[DataSymbol] = []
    for rec in iter_records(data, kinds=_DATA_KINDS):
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
    for rec in iter_records(data, kinds=_PUBLIC_KINDS):
        sym = decode_record(rec.kind, rec.payload)
        if sym is not None:
            sym.record_offset = rec.offset
            out.append(sym)
    return out


def count_kinds(data: bytes, *,
                truncation: list[Truncation] | None = None) -> collections.Counter[int]:
    """Histogram of record kinds, for diagnostics."""
    return collections.Counter(
        rec.kind for rec in iter_records(data, truncation=truncation)
    )


def extract_procs(data: bytes) -> list[ProcSymbol]:
    """Extract procedure symbols from a *module* symbol substream.

    `data` should already have the leading 4-byte CV signature stripped.
    """
    out: list[ProcSymbol] = []
    for rec in iter_records(data, kinds=PROC_KINDS):
        proc = decode_record(rec.kind, rec.payload)
        if proc is not None:
            out.append(proc)
    return out


# kind -> parser, as (kind, payload) so the two calling conventions among the
# parsers do not leak into the dispatch. This table IS the dispatch: it is what
# `parse_record` walks and what `DISPATCHED_KINDS` is derived from, so a kind
# cannot be decoded without the truncation guard in tests/test_truncation.py
# covering it. Keeping those two in step by hand drifted three times; see
# issue #46.
_RECORD_PARSERS: dict[int, Callable[[int, bytes], object]] = {
    S_PUB32: lambda _kind, payload: parse_public(payload),
    S_LABEL32: lambda _kind, payload: parse_label(payload),
    S_THUNK32: lambda _kind, payload: parse_thunk(payload),
    S_TRAMPOLINE: lambda _kind, payload: parse_trampoline(payload),
    S_CONSTANT: lambda _kind, payload: parse_constant(payload),
    S_UDT: lambda _kind, payload: parse_udt(payload),
    S_COMPILE3: lambda _kind, payload: parse_compile_info(payload),
    S_COMPILE2: lambda _kind, payload: parse_compile2(payload),
    S_SEPCODE: lambda _kind, payload: parse_sepcode(payload),
    **dict.fromkeys(INLINE_SITE_KINDS, parse_inline_site_record),
    **dict.fromkeys(PROC_KINDS, parse_proc),
    **dict.fromkeys(_DATA_KINDS, parse_data),
    **dict.fromkeys(PROC_REF_KINDS, parse_proc_ref),
    **dict.fromkeys(THREAD_KINDS, parse_thread_local),
}

# The kinds `parse_record` decodes. Exported so a test can walk the dispatch
# rather than restate it -- the restatement is what kept falling behind.
DISPATCHED_KINDS = frozenset(_RECORD_PARSERS)
