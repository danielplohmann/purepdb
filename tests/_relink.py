"""Move code in a PE/PDB pair of our own, and describe the move in OMAP.

The support code behind `tools/relink_omap.py`, and used directly by
`tests/test_omap.py`. It lives here rather than in `tools/` so that both the
tool and the suite import it as first-party code, with no path juggling for the
type checker to trip over.

Every other OMAP test in this suite builds the table it reads, which means the
translation is checked against arithmetic chosen on both sides. What none of
them had was an image whose code has *actually moved*, with tables that say so,
so that a translated address can be checked against the bytes it names.

Microsoft's BBT is what normally produces that shape and was never released;
Syzygy's `relink` is the only public tool that writes an address map, and it
never writes Optional Debug Header slot 10 (see `tests/data/README.md`). So the
shape is produced here instead, from our own build, which is what makes it
usable at all.

What it does:

  * walks the functions purepdb finds that carry a code size, in address order,
    keeping the non-overlapping ones;
  * moves each body later in `.text` by a cumulative shift, inserting a gap
    every few functions, so the map has many distinct deltas rather than one;
  * writes the moved bytes into a copy of the image and grows `.text` to fit,
    filling the gaps with `0xCC` as a linker's padding would;
  * writes a copy of the PDB carrying the original section table in slot 10,
    the final one in slot 5, and both OMAP directions in slots 3 and 4.

The result **is not runnable**, like the fixtures it is built from: nothing
fixes up a relocation or a data directory, so a moved call target is not
followed. That is deliberate and sufficient -- the file exists to be parsed,
and the property under test is that a symbol's translated address names the
bytes the symbol describes.

Format reference: the OMAP structure and its translation rule are documented at
https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap and
the slot assignment at https://llvm.org/docs/PDB/DbiStream.html
"""

from __future__ import annotations

import struct

from purepdb import PDB
from purepdb.dbi import _HEADER as DBI_HEADER
from purepdb.msf import MsfFile
from tests._synth import build_msf

# The gap inserted into `.text` every `EVERY` functions. Chosen so the table has
# tens of distinct deltas rather than one, which is what makes a range lookup do
# any work; the exact values do not matter beyond that.
GAP = 0x10
EVERY = 8

PAD = 0xCC  # int3, which is what a linker leaves between function bodies

_SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")
assert _SECTION_HEADER.size == 40


def _pe_offsets(data: bytes) -> tuple[int, int, int]:
    """(section table offset, number of sections, optional header offset)."""
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    n_sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    return pe + 24 + opt_size, n_sections, pe + 24


def sections_of(data: bytes) -> list[dict]:
    table, count, _ = _pe_offsets(data)
    out = []
    for i in range(count):
        f = _SECTION_HEADER.unpack_from(data, table + i * _SECTION_HEADER.size)
        out.append({"index": i, "name": f[0].rstrip(b"\0").decode(),
                    "virtual_size": f[1], "virtual_address": f[2],
                    "raw_size": f[3], "raw_offset": f[4],
                    "characteristics": f[9]})
    return out


def plan_moves(pdb: PDB, text_rva: int, text_size: int) -> list[tuple[int, int, int]]:
    """(original rva, final rva, size) per moved body, in address order.

    Only bodies with a code size can be moved, because only they have an extent.
    Addresses without one -- a public with no procedure record -- are carried
    along by the range the map gives their enclosing function, which is why OMAP
    is a range lookup rather than a table of points.
    """
    sized = sorted(((f.rva, f.code_size) for f in pdb.functions()
                    if f.rva is not None and f.code_size
                    and text_rva <= f.rva < text_rva + text_size),
                   key=lambda t: t[0])
    kept, end = [], 0
    for rva, size in sized:
        if rva >= end:
            kept.append((rva, size))
            end = rva + size

    moves, shift = [], 0
    for i, (rva, size) in enumerate(kept):
        if i and i % EVERY == 0:
            shift += GAP
        moves.append((rva, rva + shift, size))
    return moves


def omap_stream(pairs: list[tuple[int, int]]) -> bytes:
    """`struct OMAP { uint32 rva; uint32 rvaTo; }[]`, sorted by rva."""
    return b"".join(struct.pack("<II", a, b) for a, b in sorted(pairs))


def section_stream(sections: list[dict]) -> bytes:
    return b"".join(
        _SECTION_HEADER.pack(s["name"].encode().ljust(8, b"\0"),
                             s["virtual_size"], s["virtual_address"],
                             s["raw_size"], s["raw_offset"], 0, 0, 0, 0,
                             s["characteristics"])
        for s in sections)


def relink_image(data: bytes, moves: list[tuple[int, int, int]]) -> tuple[bytes, int]:
    """A copy of the image with every body at its new rva, and `.text` grown."""
    out = bytearray(data)
    sections = sections_of(data)
    text = next(s for s in sections if s["name"] == ".text")
    growth = max(new - old for old, new, _ in moves)
    new_vsize = text["virtual_size"] + growth

    slack = min((s["virtual_address"] for s in sections
                 if s["virtual_address"] > text["virtual_address"]),
                default=text["virtual_address"] + new_vsize) \
        - text["virtual_address"]
    if new_vsize > slack:
        raise SystemExit(
            f"error: .text would grow to {new_vsize:#x}, past the {slack:#x} "
            f"bytes before the next section. Lower GAP or raise EVERY; moving "
            f"the later sections would mean fixing every data directory that "
            f"names one, which this tool deliberately does not do.")

    old = bytes(data[text["raw_offset"]:text["raw_offset"] + text["virtual_size"]])
    body = bytearray(bytes([PAD]) * new_vsize)
    for old_rva, new_rva, size in moves:
        o, n = old_rva - text["virtual_address"], new_rva - text["virtual_address"]
        body[n:n + size] = old[o:o + size]

    raw = min(text["raw_size"], len(body))
    out[text["raw_offset"]:text["raw_offset"] + raw] = body[:raw]

    table, _, _ = _pe_offsets(data)
    struct.pack_into("<I", out, table + text["index"] * _SECTION_HEADER.size + 8,
                     new_vsize)
    return bytes(out), new_vsize


def relink_pdb(data: bytes, original: list[dict], final: list[dict],
               moves: list[tuple[int, int, int]]) -> bytes:
    """A copy of the PDB with slot 10, slot 5 and both OMAP directions."""
    msf = MsfFile(data)
    streams = [msf.read_stream(i) if msf.is_valid_stream(i) else b""
               for i in range(msf.num_streams)]

    to_src = len(streams)      # slot 3: final -> original
    from_src = len(streams) + 1  # slot 4: original -> final
    orig_hdr = len(streams) + 2  # slot 10
    final_hdr = len(streams) + 3  # slot 5
    streams.append(omap_stream([(new, old) for old, new, _ in moves]))
    streams.append(omap_stream([(old, new) for old, new, _ in moves]))
    streams.append(section_stream(original))
    streams.append(section_stream(final))

    dbi = bytearray(streams[3])
    h = DBI_HEADER.unpack_from(dbi, 0)
    base = (DBI_HEADER.size + h[9] + h[10] + h[11] + h[12] + h[13] + h[16])
    for slot, index in ((3, to_src), (4, from_src), (5, final_hdr), (10, orig_hdr)):
        struct.pack_into("<H", dbi, base + slot * 2, index)
    streams[3] = bytes(dbi)
    return build_msf(streams)
