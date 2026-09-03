"""A tiny cursor-based little-endian reader used by the stream parsers.

The `bytes` method shadows the builtin inside this class body, so the byte
annotations here name `builtins.bytes` explicitly. Renaming the method would
read better but is a public API change.
"""

from __future__ import annotations

import builtins
import struct


class Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: builtins.bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def _take(self, n: int) -> builtins.bytes:
        if self.pos + n > len(self.data):
            raise EOFError(f"read past end of buffer (need {n}, have {self.remaining()})")
        b = self.data[self.pos : self.pos + n]
        self.pos += n
        return b

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self._take(2))[0]

    def i16(self) -> int:
        return struct.unpack("<h", self._take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def bytes(self, n: int) -> builtins.bytes:
        return self._take(n)

    def cstring(self) -> str:
        """Read a NUL-terminated string, decoded as UTF-8 (lenient)."""
        end = self.data.find(b"\x00", self.pos)
        if end == -1:
            raise EOFError("unterminated C string")
        s = self.data[self.pos : end]
        self.pos = end + 1
        return s.decode("utf-8", errors="replace")

    def seek(self, pos: int) -> None:
        self.pos = pos
