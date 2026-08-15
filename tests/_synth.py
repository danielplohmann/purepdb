"""Builders for synthetic MSF/PDB data used by the test suite.

These let us exercise the full read path (block mapping, stream directory,
DBI, CodeView) without needing a real compiler-produced PDB in the sandbox.
The MSF builder is deliberately independent of the reader so the tests
validate an actual round trip rather than a shared bug.
"""

from __future__ import annotations

import struct

from purepdb.dbi import SEC_CONTRIB_V2, SEC_CONTRIB_VER60
from purepdb.msf import BIG_MSF_MAGIC


def _ceil_div(a, b):
    return (a + b - 1) // b


def build_msf(streams: list[bytes], block_size: int = 512) -> bytes:
    """Serialise a list of streams into a valid MSF 7.00 container."""
    bs = block_size
    next_block = 3  # 0=superblock, 1=FPM1, 2=FPM2

    placed = []  # (size, [block indices], data)
    for data in streams:
        n = _ceil_div(len(data), bs) if data else 0
        blocks = list(range(next_block, next_block + n))
        next_block += n
        placed.append((len(data), blocks, data))

    # Stream directory bytes.
    dir_parts = [struct.pack("<I", len(streams))]
    for size, _blocks, _data in placed:
        dir_parts.append(struct.pack("<I", size))
    for _size, blocks, _data in placed:
        dir_parts.append(struct.pack(f"<{len(blocks)}I", *blocks) if blocks else b"")
    directory = b"".join(dir_parts)

    n_dir_blocks = _ceil_div(len(directory), bs)
    dir_blocks = list(range(next_block, next_block + n_dir_blocks))
    next_block += n_dir_blocks

    block_map_block = next_block
    next_block += 1

    num_blocks = next_block
    buf = bytearray(num_blocks * bs)

    # Superblock.
    struct.pack_into(
        "<32sIIIIII", buf, 0,
        BIG_MSF_MAGIC,
        bs,               # BlockSize
        1,                # FreeBlockMapBlock
        num_blocks,       # NumBlocks
        len(directory),   # NumDirectoryBytes
        0,                # Unknown
        block_map_block,  # BlockMapAddr
    )

    def write_blocks(blocks, data):
        for i, blk in enumerate(blocks):
            chunk = data[i * bs : (i + 1) * bs]
            buf[blk * bs : blk * bs + len(chunk)] = chunk

    for _size, blocks, data in placed:
        write_blocks(blocks, data)
    write_blocks(dir_blocks, directory)

    block_map = struct.pack(f"<{n_dir_blocks}I", *dir_blocks)
    buf[block_map_block * bs : block_map_block * bs + len(block_map)] = block_map

    return bytes(buf)


# --- CodeView record builders ----------------------------------------------

def make_record(kind: int, payload: bytes) -> bytes:
    """Length-prefixed, 4-byte-aligned CodeView record."""
    total = 2 + 2 + len(payload)  # len field + kind + payload
    pad = (-total) % 4
    payload = payload + b"\x00" * pad
    rec_len = 2 + len(payload)  # kind + payload
    return struct.pack("<HH", rec_len, kind) + payload


def pub32(name: str, segment: int, offset: int, flags: int = 0x2) -> bytes:
    payload = struct.pack("<IIH", flags, offset, segment) + name.encode() + b"\x00"
    return make_record(0x110E, payload)


def gproc32(name: str, segment: int, offset: int, code_size: int = 0x10,
            type_index: int = 0x1000) -> bytes:
    payload = struct.pack(
        "<IIIIIIIIHB",
        0, 0, 0,            # parent, end, next
        code_size,
        0, code_size,       # dbg start, dbg end
        type_index,
        offset, segment,
        0,                  # flags
    ) + name.encode() + b"\x00"
    return make_record(0x1110, payload)


def proc_ref(name: str, module: int, sym_offset: int, kind: int = 0x1125) -> bytes:
    """S_PROCREF/S_LPROCREF. `module` is 1-based, as the record stores it, and
    `sym_offset` is into the module stream including its CodeView signature."""
    payload = struct.pack(
        "<IIH",
        0,           # SumName
        sym_offset,
        module,
    ) + name.encode() + b"\x00"
    return make_record(kind, payload)


def thunk32(name: str, segment: int, offset: int, length: int = 6,
            ordinal: int = 0) -> bytes:
    payload = struct.pack(
        "<IIIIHHB",
        0, 0, 0,            # parent, end, next
        offset, segment,
        length,
        ordinal,
    ) + name.encode() + b"\x00"
    return make_record(0x1102, payload)


def trampoline(*, thunk_segment: int, thunk_offset: int,
               target_segment: int, target_offset: int,
               size: int = 5, kind: int = 0) -> bytes:
    payload = struct.pack(
        "<HHIIHH",
        kind, size, thunk_offset, target_offset, thunk_segment, target_segment,
    )
    return make_record(0x112C, payload)


def inline_site(*, inlinee: int, annotations: bytes) -> bytes:
    payload = struct.pack("<III", 0, 0, inlinee) + annotations
    return make_record(0x114D, payload)


_ID_KINDS = {"func": 0x1601, "mfunc": 0x1602, "string": 0x1605, "other": 0x1603}


def ipi_stream(records: list[tuple[str, str | None]],
               index_begin: int = 0x1000) -> bytes:
    """The IPI stream: a 56-byte header, then id records.

    Each entry is `(kind, name)`; `("other", None)` writes a record purepdb
    does not decode, which still consumes an item index.
    """
    body = b""
    for kind, name in records:
        code = _ID_KINDS[kind]
        if name is None:
            payload = struct.pack("<II", 0, 0)
        elif kind == "string":
            payload = struct.pack("<I", 0) + name.encode() + b"\x00"
        else:
            payload = struct.pack("<II", 0, 0x1000) + name.encode() + b"\x00"
        body += make_record(code, payload)

    header = struct.pack(
        "<IIIIIHHIIiIiIiI",
        20040203,                    # Version
        56,                          # HeaderSize
        index_begin,
        index_begin + len(records),  # TypeIndexEnd
        len(body),                   # TypeRecordBytes
        0xFFFF, 0xFFFF,              # hash stream indices
        4, 0,                        # HashKeySize, NumHashBuckets
        0, 0, 0, 0, 0, 0,            # hash/index/adj buffer offsets and lengths
    )
    return header + body


# --- DBI / stream builders --------------------------------------------------

def module_info(module_name: str, obj_name: str, sym_stream: int,
                sym_byte_size: int, c11_byte_size: int = 0,
                c13_byte_size: int = 0) -> bytes:
    """One ModuleInfo record, 4-byte aligned."""
    fixed = struct.pack(
        "<I28sHHIIIHHIII",
        0,                  # Unused1
        b"\x00" * 28,       # SectionContr
        0,                  # Flags
        sym_stream,
        sym_byte_size,
        c11_byte_size, c13_byte_size,
        0, 0,               # source file count, padding
        0,                  # Unused2
        0, 0,               # source name idx, pdb path idx
    )
    rec = fixed + module_name.encode() + b"\x00" + obj_name.encode() + b"\x00"
    pad = (-len(rec)) % 4
    return rec + b"\x00" * pad


def section_map(entries: list[tuple[int, int, int]]) -> bytes:
    """The DBI Section Map substream, as link.exe writes it.

    Each entry is `(flags, frame, length)`. `Offset` is written as 0, which is
    what real linkers emit and the reason addresses have to be rebuilt.
    """
    out = [struct.pack("<HH", len(entries), len(entries))]
    for flags, frame, length in entries:
        out.append(struct.pack(
            "<HHHHHHII",
            flags,
            0,        # Ovl
            0,        # Group
            frame,
            0xFFFF,   # SectionName
            0xFFFF,   # ClassName
            0,        # Offset
            length,
        ))
    return b"".join(out)


def section_contributions(entries: list[tuple[int, int, int, int]],
                          version: int = SEC_CONTRIB_VER60) -> bytes:
    """The Section Contribution substream: a version, then fixed-size entries.

    Each entry is `(segment, offset, size, module_index)`. V2 appends a
    trailing ISectCoff, which is what makes its entries 32 bytes rather than 28.
    """
    out = [struct.pack("<I", version)]
    for segment, offset, size, module_index in entries:
        out.append(struct.pack(
            "<HHiiIHHII",
            segment, 0, offset, size,
            CODE_CHARACTERISTICS,
            module_index, 0,
            0, 0,  # data crc, reloc crc
        ))
        if version == SEC_CONTRIB_V2:
            out.append(struct.pack("<I", 0))  # ISectCoff
    return b"".join(out)


def dbi_stream(*, public_stream: int, symrecord_stream: int,
               module_list: bytes, dbg_header: list[int],
               sec_map: bytes = b"", sec_contrib: bytes = b"") -> bytes:
    dbg_bytes = struct.pack(f"<{len(dbg_header)}H", *dbg_header)
    header = struct.pack(
        "<iIIHHHHHHiiiiiIiiHHI",
        -1,                 # VersionSignature
        19990903,           # VersionHeader (V70)
        1,                  # Age
        0xFFFF,             # GlobalStreamIndex
        0,                  # BuildNumber
        public_stream,      # PublicStreamIndex
        0,                  # PdbDllVersion
        symrecord_stream,   # SymRecordStreamIndex
        0,                  # PdbDllRbld
        len(module_list),   # ModInfoSize
        len(sec_contrib),   # SectionContributionSize
        len(sec_map),       # SectionMapSize
        0, 0,               # srcinfo, tsmap
        0,                  # MFCTypeServerIndex
        len(dbg_bytes),     # OptionalDbgHeaderSize
        0,                  # ECSubstreamSize
        0,                  # Flags
        0x8664,             # Machine (AMD64)
        0,                  # Padding
    )
    # Substream order is fixed by the header: contributions precede the map.
    return header + module_list + sec_contrib + sec_map + dbg_bytes


CODE_CHARACTERISTICS = 0x60000020  # CNT_CODE | MEM_EXECUTE | MEM_READ
DATA_CHARACTERISTICS = 0xC0000040  # CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE


def section_header(name: str, vaddr: int, vsize: int = 0x1000,
                   characteristics: int | None = None) -> bytes:
    """One IMAGE_SECTION_HEADER.

    Characteristics default by name, because whether a section is executable
    now decides whether publics inside it count as functions.
    """
    if characteristics is None:
        characteristics = (CODE_CHARACTERISTICS if name.startswith(".text")
                           else DATA_CHARACTERISTICS)
    return struct.pack(
        "<8sIIIIIIHHI",
        name.encode(), vsize, vaddr, vsize, 0, 0, 0, 0, 0, characteristics,
    )


def module_sym_stream(records: bytes) -> bytes:
    """A module symbol substream: 4-byte CV signature + records."""
    return struct.pack("<I", 4) + records


def publics_hash_stream(record_offsets: list[int]) -> bytes:
    """A publics *hash* stream, as real linkers emit it.

    Deliberately contains no symbol records -- only offsets into the
    symbol-record stream. A parser that scans this stream for S_PUB32 finds
    nothing, which is exactly the regression the tests guard against.
    """
    from purepdb.gsi import GSI_HASH_SIGNATURE, GSI_HASH_VERSION_V70

    gsi_hash = struct.pack("<IIII", GSI_HASH_SIGNATURE, GSI_HASH_VERSION_V70, 0, 0)
    addr_map = struct.pack(f"<{len(record_offsets)}I", *record_offsets) if record_offsets else b""
    header = struct.pack(
        "<IIIIHHII",
        len(gsi_hash),    # SymHash
        len(addr_map),    # AddrMap
        0,                # NumThunks
        0,                # SizeOfThunk
        0, 0,             # ISectThunkTable, Padding
        0,                # OffThunkTable
        0,                # NumSections
    )
    return header + gsi_hash + addr_map


def pdb_info_stream(named_streams: dict[str, int]) -> bytes:
    """Stream 1: the version/signature/age/GUID header, then the named stream map."""
    header = struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16
    return header + named_stream_map(named_streams)


def named_stream_map(entries: dict[str, int]) -> bytes:
    """A string buffer plus a serialised hash table, as the PDB Info stream ends.

    Only the occupied buckets are written; which ones they are comes from the
    "present" bit vector. Placing them at 0, 1, 2... is not what a real hash
    does, but the reader is not supposed to care.
    """
    strings = bytearray()
    offsets = {}
    for name in entries:
        offsets[name] = len(strings)
        strings += name.encode() + b"\x00"

    count = len(entries)
    present_words = (count + 31) // 32
    words = [0] * present_words
    for i in range(count):
        words[i // 32] |= 1 << (i % 32)

    out = [struct.pack("<I", len(strings)), bytes(strings)]
    out.append(struct.pack("<II", count, max(count * 2, 1)))
    out.append(struct.pack(f"<{1 + present_words}I", present_words, *words))
    out.append(struct.pack("<I", 0))  # deleted bit vector: no words
    for name, index in entries.items():
        out.append(struct.pack("<II", offsets[name], index))
    return b"".join(out)


def names_stream(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    """The `/names` stream, and each string's offset within it."""
    buf = bytearray()
    offsets = {}
    for s in strings:
        offsets[s] = len(buf)
        buf += s.encode() + b"\x00"
    header = struct.pack("<III", 0xEFFEEFFE, 1, len(buf))
    # Hash buckets and the name count follow the strings; purepdb reads by
    # offset and never consults them, but a real stream has them.
    tail = struct.pack("<I", 0) + struct.pack("<I", len(strings))
    return header + bytes(buf) + tail, offsets


def subsection(kind: int, payload: bytes) -> bytes:
    """One C13 subsection: kind, length, payload, padded to 4 bytes."""
    return (struct.pack("<II", kind, len(payload)) + payload
            + b"\x00" * (-len(payload) % 4))


def file_checksums(entries: list[tuple[int, bytes]]) -> tuple[bytes, list[int]]:
    """A DEBUG_S_FILECHECKSUMS payload, and each entry's byte offset in it."""
    out = bytearray()
    offsets = []
    for name_offset, checksum in entries:
        offsets.append(len(out))
        out += struct.pack("<IBB", name_offset, len(checksum), 1 if checksum else 0)
        out += checksum
        out += b"\x00" * (-len(out) % 4)
    return bytes(out), offsets


def line_entries(*, segment: int, base_offset: int, file_entry: int,
                 entries: list[tuple[int, int, bool]]) -> bytes:
    """A DEBUG_S_LINES payload holding one block.

    Each entry is `(offset from base, line number, is_statement)`.
    """
    lines = b"".join(
        struct.pack("<II", offset, (line & 0x00FFFFFF) | (0x80000000 if stmt else 0))
        for offset, line, stmt in entries
    )
    block = struct.pack("<III", file_entry, len(entries), 12 + len(lines)) + lines
    header = struct.pack("<IHHI", base_offset, segment, 0, 0x100)
    return header + block


def record_offsets(records: list[bytes]) -> list[int]:
    """Byte offset of each record in the concatenation of `records`."""
    offsets, pos = [], 0
    for rec in records:
        offsets.append(pos)
        pos += len(rec)
    return offsets


def omap_stream(entries: list[tuple[int, int]]) -> bytes:
    """An OMAP table: `struct { uint32 rva; uint32 rvaTo; }` sorted by rva."""
    return b"".join(struct.pack("<II", rva, rva_to) for rva, rva_to in entries)


def numeric_leaf(value: int) -> bytes:
    """Encode an integer the way CodeView does: small values inline, larger
    ones behind an LF_* tag naming the width."""
    if 0 <= value < 0x8000:
        return struct.pack("<H", value)
    for leaf, fmt in ((0x8000, "<b"), (0x8002, "<H"), (0x8001, "<h"),
                      (0x8004, "<I"), (0x8003, "<i"),
                      (0x800A, "<Q"), (0x8009, "<q")):
        try:
            return struct.pack("<H", leaf) + struct.pack(fmt, value)
        except struct.error:
            continue
    raise ValueError(f"{value} does not fit any numeric leaf")


def constant(name: str, value: int, type_index: int = 0x74,
             raw_value: bytes | None = None) -> bytes:
    """S_CONSTANT. `raw_value` overrides the encoding, for unknown-leaf tests."""
    leaf = numeric_leaf(value) if raw_value is None else raw_value
    payload = struct.pack("<I", type_index) + leaf + name.encode() + b"\x00"
    return make_record(0x1107, payload)


def udt(name: str, type_index: int = 0x1004) -> bytes:
    payload = struct.pack("<I", type_index) + name.encode() + b"\x00"
    return make_record(0x1108, payload)


def gdata32(name: str, segment: int, offset: int, type_index: int = 0x74,
            kind: int = 0x110D) -> bytes:
    """S_GDATA32, or S_LDATA32 with `kind=0x110C`: same layout either way."""
    payload = struct.pack("<IIH", type_index, offset, segment) + name.encode() + b"\x00"
    return make_record(kind, payload)
