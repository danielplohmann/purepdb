"""Builders for synthetic MSF/PDB data used by the test suite.

These let us exercise the full read path (block mapping, stream directory,
DBI, CodeView) without needing a real compiler-produced PDB in the sandbox.
The MSF builder is deliberately independent of the reader so the tests
validate an actual round trip rather than a shared bug.
"""

from __future__ import annotations

import struct

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


# --- DBI / stream builders --------------------------------------------------

def module_info(module_name: str, obj_name: str, sym_stream: int,
                sym_byte_size: int) -> bytes:
    """One ModuleInfo record, 4-byte aligned."""
    fixed = struct.pack(
        "<I28sHHIIIHHIII",
        0,                  # Unused1
        b"\x00" * 28,       # SectionContr
        0,                  # Flags
        sym_stream,
        sym_byte_size,
        0, 0,               # C11, C13
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


def dbi_stream(*, public_stream: int, symrecord_stream: int,
               module_list: bytes, dbg_header: list[int],
               sec_map: bytes = b"") -> bytes:
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
        0,                  # SectionContributionSize
        len(sec_map),       # SectionMapSize
        0, 0,               # srcinfo, tsmap
        0,                  # MFCTypeServerIndex
        len(dbg_bytes),     # OptionalDbgHeaderSize
        0,                  # ECSubstreamSize
        0,                  # Flags
        0x8664,             # Machine (AMD64)
        0,                  # Padding
    )
    return header + module_list + sec_map + dbg_bytes


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


def gdata32(name: str, segment: int, offset: int, type_index: int = 0x74) -> bytes:
    payload = struct.pack("<IIH", type_index, offset, segment) + name.encode() + b"\x00"
    return make_record(0x110D, payload)
