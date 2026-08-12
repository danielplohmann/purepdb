"""Multi-Stream File (MSF) container reader.

An MSF file is the on-disk container for a PDB. It is a block-based
file system: the file is divided into fixed-size blocks, and each logical
"stream" is stored as an ordered list of (possibly non-contiguous) blocks.

Layout (MSF 7.00 / "big" MSF, the only format shipped since VS 2015):

    +----------------+  offset 0
    | SuperBlock     |  56 bytes: magic + 6 x uint32
    +----------------+
    | ... blocks ... |
    +----------------+

The SuperBlock's BlockMapAddr points at a block that holds an array of
uint32 block indices; those blocks concatenated (truncated to
NumDirectoryBytes) form the *stream directory*, which describes every
stream in the file.

Format reference: the MSF container layout as described in LLVM's PDB
documentation (https://llvm.org/docs/PDB/MsfFile.html) and Microsoft's own
published PDB sources. This is an independent implementation; see NOTICE.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# 32-byte magic for the MSF 7.00 ("big") format.
BIG_MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

# Magics we recognise only to name them in the error. Scanning a directory of
# real binaries turns these up constantly -- .NET projects ship Portable PDBs,
# which are not MSF containers at all -- so "bad magic" is not a useful answer.
_SMALL_MSF_MAGIC = b"Microsoft C/C++ program database 2.00"
_PORTABLE_PDB_MAGIC = b"BSJB"

_FOREIGN_FORMATS = (
    (_PORTABLE_PDB_MAGIC, "a .NET Portable PDB (ECMA-335 metadata, not MSF)"),
    (_SMALL_MSF_MAGIC, "an MSF 2.00 container (Visual C++ 6 era)"),
)

# A stream size of 0xFFFFFFFF means "no stream present" (nil stream).
INVALID_STREAM_SIZE = 0xFFFFFFFF

_SUPERBLOCK = struct.Struct("<32sIIIIII")  # magic + 6 uint32


class PdbError(Exception):
    """Base for every error purepdb raises.

    Exists so a caller sweeping a directory can wrap one exception type. The
    parser must never leak `struct.error` or `IndexError` for a file it simply
    cannot read.
    """


class MsfError(PdbError):
    """Raised when the MSF container is malformed."""


class UnsupportedPdbError(PdbError):
    """Raised for a file that is a real debug-info file of a kind we don't read."""


def _ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


@dataclass
class SuperBlock:
    block_size: int
    free_block_map_block: int
    num_blocks: int
    num_directory_bytes: int
    unknown: int
    block_map_addr: int

    @classmethod
    def parse(cls, data: bytes) -> SuperBlock:
        if len(data) < _SUPERBLOCK.size:
            raise MsfError("file too small to contain an MSF superblock")
        (magic, bs, fpm, nblocks, ndir, unk, bmap) = _SUPERBLOCK.unpack_from(data, 0)
        if magic != BIG_MSF_MAGIC:
            for prefix, description in _FOREIGN_FORMATS:
                if data.startswith(prefix):
                    raise UnsupportedPdbError(f"this is {description}")
            raise MsfError("not an MSF 7.00 file (bad magic)")
        if bs not in (512, 1024, 2048, 4096):
            raise MsfError(f"unsupported block size {bs}")
        return cls(bs, fpm, nblocks, ndir, unk, bmap)


class MsfFile:
    """Random-access reader over the streams inside an MSF container."""

    def __init__(self, data: bytes):
        self._data = data
        self.super = SuperBlock.parse(data)
        expected = self.super.num_blocks * self.super.block_size
        if len(data) < expected:
            raise MsfError(
                f"file truncated: header claims {self.super.num_blocks} blocks "
                f"({expected} bytes) but only {len(data)} bytes present"
            )
        # stream_sizes[i] is None for a nil stream, else its byte length.
        # stream_blocks[i] is the ordered list of block indices for stream i.
        self.stream_sizes: list[int | None] = []
        self.stream_blocks: list[list[int]] = []
        self._read_directory()

    # -- block-level helpers ------------------------------------------------

    def _read_block(self, index: int) -> bytes:
        bs = self.super.block_size
        start = index * bs
        end = start + bs
        if end > len(self._data):
            raise MsfError(f"block {index} out of range")
        return self._data[start:end]

    def _read_blocks(self, indices: list[int], size: int) -> bytes:
        buf = b"".join(self._read_block(i) for i in indices)
        return buf[:size]

    # -- directory ----------------------------------------------------------

    def _read_directory(self) -> None:
        bs = self.super.block_size
        ndir = self.super.num_directory_bytes
        n_dir_blocks = _ceil_div(ndir, bs)

        # The block map (at block_map_addr) is an array of uint32 block
        # indices naming the directory's own blocks.
        block_map = self._read_block(self.super.block_map_addr)
        if n_dir_blocks * 4 > len(block_map):
            raise MsfError("stream directory block map does not fit in one block")
        dir_block_indices = list(struct.unpack_from(f"<{n_dir_blocks}I", block_map, 0))

        directory = self._read_blocks(dir_block_indices, ndir)
        self._parse_directory(directory)

    def _parse_directory(self, d: bytes) -> None:
        # Every length here is read from the file, so each one is checked
        # against what the directory actually holds. Without that, a corrupt
        # count reaches struct.unpack_from and raises `struct.error` -- past
        # the boundary this module promises to keep errors behind.
        bs = self.super.block_size
        off = 0
        if len(d) < 4:
            raise MsfError("stream directory holds no stream count")
        (num_streams,) = struct.unpack_from("<I", d, off)
        off += 4

        if num_streams > (len(d) - off) // 4:
            raise MsfError(
                f"stream directory claims {num_streams} streams, more than its "
                f"{len(d)} bytes can describe"
            )
        sizes = list(struct.unpack_from(f"<{num_streams}I", d, off))
        off += 4 * num_streams

        for index, size in enumerate(sizes):
            if size == INVALID_STREAM_SIZE:
                self.stream_sizes.append(None)
                self.stream_blocks.append([])
                continue
            n = _ceil_div(size, bs)
            if n > (len(d) - off) // 4:
                raise MsfError(
                    f"stream {index} claims {size} bytes ({n} blocks), past the "
                    f"end of the {len(d)}-byte stream directory"
                )
            blocks = list(struct.unpack_from(f"<{n}I", d, off))
            off += 4 * n
            self.stream_sizes.append(size)
            self.stream_blocks.append(blocks)

    # -- public API ---------------------------------------------------------

    @property
    def num_streams(self) -> int:
        return len(self.stream_sizes)

    def stream_size(self, index: int) -> int:
        size = self.stream_sizes[index]
        return 0 if size is None else size

    def is_valid_stream(self, index: int) -> bool:
        return 0 <= index < self.num_streams and self.stream_sizes[index] is not None

    def read_stream(self, index: int) -> bytes:
        """Return the full decoded contents of stream `index`."""
        if not (0 <= index < self.num_streams):
            raise MsfError(f"stream index {index} out of range (have {self.num_streams})")
        size = self.stream_sizes[index]
        if size is None:
            raise MsfError(f"stream {index} is a nil stream")
        return self._read_blocks(self.stream_blocks[index], size)

    @classmethod
    def open(cls, path: str) -> MsfFile:
        with open(path, "rb") as f:
            return cls(f.read())
