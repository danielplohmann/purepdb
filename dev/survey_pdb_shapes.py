#!/usr/bin/env python3
"""Sweep a corpus of PDBs for the Optional Debug Header shapes purepdb cares about.

Written to hunt for one shape in particular: **slot 10 present and slot 5
absent**, the case issue #39 described and issue #25 wants a fixture for. Across
the nineteen files measured so far it has never appeared, and the argument for
treating it as real rests on nothing but the code paths composing that way. One
example would change that; a few thousand files finding none would settle it the
other way.

**No images are needed.** The shape is a property of the PDB alone -- which
streams the Optional Debug Header names -- so this reads only the header and
never looks for a binary to pair with.

It is also cheap on purpose. `PDB.diagnose()` walks every module stream, which
is far more work than this needs; the shape is four slot lookups and a stream
size. On a large corpus that difference is the difference between minutes and
hours.

    python dev/survey_pdb_shapes.py ~/pdbs
    python dev/survey_pdb_shapes.py ~/pdbs --hits-only --json hits.json

Every failure mode of a corpus sweep is expected here rather than fatal: a
Portable PDB, a `vc140.pdb` with an empty DBI stream, a truncated download, a
file that is not a PDB at all. They are counted and named, not raised -- which
is the same contract `purepdb` gives any caller sweeping a directory.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import json
import mmap
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import struct

from purepdb import PdbError
from purepdb.dbi import _HEADER as DBI_HEADER
from purepdb.dbi import (
    DBG_OMAP_FROM_SRC,
    DBG_SECTION_HDR,
    DBG_SECTION_HDR_ORIG,
    DbiStream,
)
from purepdb.msf import BIG_MSF_MAGIC, MsfError, MsfFile

# The shape this exists to find.
WANTED = "slot 10, NO slot 5"


# Enough of a non-MSF file for purepdb to recognise and name the format.
_PEEK = 1 << 20

# The Optional Debug Header is an array of uint16 stream indices at the end of
# the DBI stream, after its other substreams. Slot 5 is the section headers,
# slot 10 the pre-BBT ones, slot 4 the original-to-final address map.
_SLOT_COUNT = 11


def _stream_range(msf: MsfFile, index: int, start: int, length: int) -> bytes:
    """`length` bytes at `start` of a stream, reading only the blocks they lie in.

    `PDB(...)` parses the whole DBI stream on construction -- the module list
    and a map over every section contribution -- which on a 426 MB PDB costs
    around 900 MB and several seconds. This needs seventy bytes of it. Reading
    by block keeps the sweep flat in the size of the file, which is the
    difference between scanning a corpus of huge PDBs and not.
    """
    bs = msf.super.block_size
    blocks = msf.stream_blocks[index]
    first, last = start // bs, (start + length - 1) // bs
    if last >= len(blocks):
        raise MsfError(f"stream {index} is shorter than {start + length} bytes")
    buf = b"".join(msf._read_block(b) for b in blocks[first:last + 1])
    offset = start - first * bs
    return buf[offset:offset + length]


def shape_of(msf: MsfFile) -> tuple[str, int]:
    """(shape name, omap entry count) from the Optional Debug Header alone."""
    dbi_index = 3
    if (not msf.is_valid_stream(dbi_index)
            or msf.stream_size(dbi_index) < DBI_HEADER.size):
        # Hand the diagnosis back to the library rather than inventing a worse
        # one. An empty DBI stream is a compiler-intermediate `vc140.pdb`, and
        # `DbiStream.parse` says so in a sentence that tells the reader what to
        # use instead. The stream is tiny in this case, so reading it is free.
        DbiStream.parse(msf.read_stream(dbi_index)
                        if msf.is_valid_stream(dbi_index) else b"")
        raise MsfError("no DBI stream to read a debug header from")

    header = DBI_HEADER.unpack(_stream_range(msf, dbi_index, 0, DBI_HEADER.size))
    # The six substreams that precede the Optional Debug Header, by their field
    # index in `DBI_HEADER`: ModInfo, SectionContribution, SectionMap,
    # SourceInfo, TypeServerMap, ECSubstream. Taken from the header definition
    # rather than from offsets worked out by hand -- the first version of this
    # guessed them, and every file came back with the wrong answer.
    optional = DBI_HEADER.size + sum(
        max(0, header[i]) for i in (9, 10, 11, 12, 13, 16))
    slots = struct.unpack(
        f"<{_SLOT_COUNT}H",
        _stream_range(msf, dbi_index, optional, _SLOT_COUNT * 2),
    )

    def present(slot: int) -> bool:
        index = slots[slot]
        return msf.is_valid_stream(index) and msf.stream_size(index) > 0

    slot5 = present(DBG_SECTION_HDR)
    slot10 = present(DBG_SECTION_HDR_ORIG)
    omap_index = slots[DBG_OMAP_FROM_SRC]
    omap_bytes = (msf.stream_size(omap_index)
                  if msf.is_valid_stream(omap_index) else 0)
    entries = omap_bytes // 8  # struct OMAP { uint32 rva; uint32 rvaTo; }

    if slot10 and not slot5:
        return WANTED, entries
    if entries and slot10:
        return "ordinary BBT (map + slot 10 + slot 5)", entries
    if entries:
        return "map, no slot 10", entries
    if slot10:
        return "slot 10, no map", entries
    return "no map, no slot 10", entries


@contextlib.contextmanager
def opened(path: Path):
    """An `MsfFile` over a memory-mapped file, so size costs address space not RAM.

    Only a file that really is an MSF container gets mapped. `MsfFile` takes
    `bytes`, and while it works on any sliceable buffer for a file it can read,
    the foreign-format detection calls `.startswith` -- which an mmap does not
    have, so a Portable PDB would come back as `AttributeError` rather than as
    the diagnosis it deserves. Reading a prefix for that path costs nothing,
    because the files it catches are the ones being rejected anyway.

    The map has to outlive every read, hence the context manager.
    """
    with open(path, "rb") as fh:
        if fh.read(len(BIG_MSF_MAGIC)) != BIG_MSF_MAGIC:
            fh.seek(0)
            yield MsfFile(fh.read(_PEEK))
            return
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            yield MsfFile(mapped)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpus", type=Path, help="directory, searched recursively")
    ap.add_argument("--glob", default="*.pdb", help="pattern (default *.pdb)")
    ap.add_argument("--hits-only", action="store_true",
                    help="print only files carrying the wanted shape")
    ap.add_argument("--json", type=Path, help="write the hits to this file")
    ap.add_argument("--limit", type=int, help="stop after this many files")
    args = ap.parse_args(argv[1:])

    files = sorted(args.corpus.rglob(args.glob))
    if args.limit:
        files = files[:args.limit]
    if not files:
        print(f"error: nothing matching {args.glob} under {args.corpus}",
              file=sys.stderr)
        return 1

    shapes: collections.Counter[str] = collections.Counter()
    rejected: collections.Counter[str] = collections.Counter()
    hits = []

    for path in files:
        try:
            with opened(path) as msf:
                shape, entries = shape_of(msf)
        except PdbError as exc:
            # Expected constantly on a real corpus; the reason is the useful part.
            rejected[type(exc).__name__] += 1
            continue
        except (OSError, ValueError) as exc:
            # ValueError covers an empty file, which cannot be mapped.
            rejected[f"{type(exc).__name__}: {exc}"] += 1
            continue

        shapes[shape] += 1
        if shape == WANTED:
            record = {"path": str(path), "omap_entries": entries}
            hits.append(record)
            print(f"HIT  {path}  ({entries} omap entries)")
        elif not args.hits_only:
            print(f"     {path}  {shape}"
                  + (f", {entries} entries" if entries else ""))

    print(f"\n{sum(shapes.values())} PDB(s) read, {sum(rejected.values())} not read")
    for shape, n in shapes.most_common():
        mark = "  <-- WANTED" if shape == WANTED else ""
        print(f"  {n:6d}  {shape}{mark}")
    for reason, n in rejected.most_common():
        print(f"  {n:6d}  skipped: {reason}")

    if args.json and hits:
        args.json.write_text(json.dumps(hits, indent=2))
        print(f"\nwrote {len(hits)} hit(s) to {args.json}")

    if not hits:
        print(f"\nno file carried '{WANTED}'. That is the result so far on every "
              f"corpus tried;\nsee docs/omap.md and issue 25.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
