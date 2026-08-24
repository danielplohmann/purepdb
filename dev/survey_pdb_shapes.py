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
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purepdb import PDB, PdbError
from purepdb.dbi import (
    DBG_OMAP_FROM_SRC,
    DBG_SECTION_HDR,
    DBG_SECTION_HDR_ORIG,
)

# The shape this exists to find.
WANTED = "slot 10, NO slot 5"


def shape_of(pdb: PDB) -> tuple[str, int]:
    """(shape name, omap entry count) from the Optional Debug Header alone."""
    def present(slot: int) -> bool:
        index = pdb.dbi.dbg_stream(slot)
        return pdb.msf.is_valid_stream(index) and pdb.msf.stream_size(index) > 0

    slot5 = present(DBG_SECTION_HDR)
    slot10 = present(DBG_SECTION_HDR_ORIG)
    omap_index = pdb.dbi.dbg_stream(DBG_OMAP_FROM_SRC)
    omap_bytes = (pdb.msf.stream_size(omap_index)
                  if pdb.msf.is_valid_stream(omap_index) else 0)
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
            pdb = PDB.open(str(path))
            shape, entries = shape_of(pdb)
        except PdbError as exc:
            # Expected constantly on a real corpus; the reason is the useful part.
            rejected[type(exc).__name__] += 1
            continue
        except OSError as exc:
            rejected[f"OSError: {exc.strerror}"] += 1
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
