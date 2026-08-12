"""OMAP address translation.

Microsoft's basic-block optimiser (BBT, the tool behind `/ORDER`-style
post-link reordering, applied to much of Windows itself) moves code around
*after* the linker has written the PDB. It does not rewrite the debug info.
Instead it appends two translation tables, and every symbol in the PDB keeps
the address it had in the pre-optimisation image.

That makes an OMAP-bearing PDB the one case where ignoring a stream produces
wrong numbers rather than missing ones: a `segment:offset` resolved against
the section table names an address in the *original* layout, which in the
shipped image is some unrelated instruction.

Two tables live in Optional Debug Header slots 3 and 4:

    slot 3  OmapToSrc     final image -> original image
    slot 4  OmapFromSrc   original image -> final image

Each is a dense array of `struct OMAP { uint32 rva; uint32 rvaTo; }` sorted by
`rva`. Translation is the algorithm Microsoft documents for the structure:
find the entry with the largest `rva` less than or equal to the address, then
add the difference to its `rvaTo`. An `rvaTo` of 0 marks a range that has no
counterpart -- code the optimiser dropped -- and translates to nothing.

Format reference: the OMAP structure and its translation rule are documented
at https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap
and the slot assignment at https://llvm.org/docs/PDB/DbiStream.html
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field


@dataclass
class OmapTable:
    """One OMAP table: source RVAs and where they moved to."""

    source: list[int] = field(default_factory=list)
    target: list[int] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.source)

    @classmethod
    def parse(cls, data: bytes) -> OmapTable:
        n = len(data) // 8
        if n == 0:
            return cls()
        pairs = struct.unpack_from(f"<{2 * n}I", data, 0)
        source = list(pairs[0::2])
        target = list(pairs[1::2])
        # The table is defined as sorted by source RVA, and the lookup is a
        # binary search that relies on it. Sorting a table that already is
        # costs one comparison pass; a table that is not would otherwise give
        # silently wrong answers.
        if any(source[i] > source[i + 1] for i in range(n - 1)):
            order = sorted(range(n), key=source.__getitem__)
            source = [source[i] for i in order]
            target = [target[i] for i in order]
        return cls(source=source, target=target)

    def lookup(self, rva: int) -> int | None:
        """Translate `rva` into the other image's address space.

        None when the address falls before the first entry, or inside a range
        the optimiser did not carry over (`rvaTo == 0`).
        """
        i = bisect.bisect_right(self.source, rva) - 1
        if i < 0:
            return None
        base = self.target[i]
        if base == 0:
            return None
        return base + (rva - self.source[i])
