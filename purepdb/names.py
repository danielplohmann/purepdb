"""Named streams, and the `/names` string table they point at.

Two small structures, both prerequisites for anything that resolves a string
offset -- file names in the line tables, most immediately.

**The named stream map** sits at the end of the PDB Info stream (stream 1),
after the version/signature/age/GUID header. It is a string buffer followed by
a serialised hash table whose keys are offsets into that buffer and whose
values are stream indices. Only the occupied buckets are written, named by a
"present" bit vector, so the table cannot be skipped without walking it.

**The `/names` stream** is the global string table: a header, a block of
NUL-terminated strings, and a hash table for looking a string up by content.
purepdb only ever has an offset in hand, so the hash part is not needed --
`StringTable.get()` reads the string at the offset directly.

Format reference: https://llvm.org/docs/PDB/PdbStream.html,
https://llvm.org/docs/PDB/HashTable.html
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# The named stream map begins after Version, Signature, Age and the 16-byte GUID.
NAMED_STREAM_MAP_OFFSET = 28

STRING_TABLE_SIGNATURE = 0xEFFEEFFE
_SUPPORTED_HASH_VERSIONS = (1, 2)


def _read_bit_vector(data: bytes, pos: int) -> "tuple[list[int], int]":
    """A word count, then that many uint32s. Returns the set bit indices."""
    (word_count,) = struct.unpack_from("<I", data, pos)
    pos += 4
    words = struct.unpack_from(f"<{word_count}I", data, pos) if word_count else ()
    pos += 4 * word_count
    bits = [i * 32 + b
            for i, word in enumerate(words) if word
            for b in range(32) if word >> b & 1]
    return bits, pos


def parse_named_stream_map(data: bytes,
                           offset: int = NAMED_STREAM_MAP_OFFSET) -> dict[str, int]:
    """Map stream name -> stream index, from the tail of the PDB Info stream.

    Returns an empty mapping for a stream too short or too malformed to walk;
    the map is the last thing in the stream, so there is nothing after it that
    a partial parse would put out of step.
    """
    try:
        (byte_size,) = struct.unpack_from("<I", data, offset)
        pos = offset + 4
        strings = data[pos : pos + byte_size]
        if len(strings) < byte_size:
            return {}
        pos += byte_size

        (size, _capacity) = struct.unpack_from("<II", data, pos)
        pos += 8
        present, pos = _read_bit_vector(data, pos)
        _deleted, pos = _read_bit_vector(data, pos)
        if len(present) > size:
            return {}

        out: dict[str, int] = {}
        for _ in present:
            key, value = struct.unpack_from("<II", data, pos)
            pos += 8
            end = strings.find(b"\x00", key)
            if key >= len(strings) or end == -1:
                continue
            out[strings[key:end].decode("utf-8", errors="replace")] = value
        return out
    except struct.error:
        return {}


@dataclass
class StringTable:
    """The `/names` stream: strings addressed by byte offset."""

    strings: bytes

    @classmethod
    def parse(cls, data: bytes) -> "StringTable | None":
        """None when the stream is not a string table we recognise."""
        if len(data) < 12:
            return None
        signature, hash_version, byte_size = struct.unpack_from("<III", data, 0)
        if signature != STRING_TABLE_SIGNATURE:
            return None
        if hash_version not in _SUPPORTED_HASH_VERSIONS:
            return None
        strings = data[12 : 12 + byte_size]
        if len(strings) < byte_size:
            return None
        return cls(strings=strings)

    def get(self, offset: int) -> str | None:
        """The string at `offset`, or None if the offset names none."""
        if offset < 0 or offset >= len(self.strings):
            return None
        end = self.strings.find(b"\x00", offset)
        if end == -1:
            return None
        return self.strings[offset:end].decode("utf-8", errors="replace")
