#!/usr/bin/env python3
"""Regenerate or inspect a relinked PE/PDB pair.

A thin command line over `tests/_relink.py`, which is where the work and the
reasoning live. `tests/test_omap.py` builds the pair in memory rather than
reading one off disk, so nothing here has to be run for the suite to pass --
this exists to produce a pair to look at, or to point at another fixture.

    python tools/relink_omap.py tests/data/rustpe/rust_pe_symbols_msvc \\
        --out /tmp/relinked
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purepdb import PDB
from purepdb.msf import BIG_MSF_MAGIC
from tests._relink import plan_moves, relink_image, relink_pdb, sections_of


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("stem", help="path without extension; <stem>.exe and <stem>.pdb")
    ap.add_argument("--out", required=True, help="output stem")
    args = ap.parse_args(argv[1:])

    stem, out = Path(args.stem), Path(args.out)
    image = stem.with_suffix(".exe").read_bytes()
    pdb_bytes = stem.with_suffix(".pdb").read_bytes()
    if not image.startswith(b"MZ"):
        raise SystemExit(f"error: {stem}.exe is not a PE image")
    if not pdb_bytes.startswith(BIG_MSF_MAGIC):
        raise SystemExit(f"error: {stem}.pdb is not an MSF 7.00 container")

    pdb = PDB.from_bytes(pdb_bytes)
    if pdb.diagnose().omap_entries:
        raise SystemExit("error: that PDB already carries an address map")

    original = sections_of(image)
    text = next(s for s in original if s["name"] == ".text")
    moves = plan_moves(pdb, text["virtual_address"], text["virtual_size"])
    if not moves:
        raise SystemExit("error: no sized function bodies to move")

    new_image, new_vsize = relink_image(image, moves)
    final = [dict(s) for s in original]
    next(s for s in final if s["name"] == ".text")["virtual_size"] = new_vsize
    new_pdb = relink_pdb(pdb_bytes, original, final, moves)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".exe").write_bytes(new_image)
    out.with_suffix(".pdb").write_bytes(new_pdb)

    deltas = {new - old for old, new, _ in moves}
    print(f"{len(moves)} bodies moved, {len(deltas)} distinct deltas, "
          f"largest {max(deltas):#x}")
    print(f".text virtual size {text['virtual_size']:#x} -> {new_vsize:#x}")
    print(f"wrote {out.with_suffix('.exe')} and {out.with_suffix('.pdb')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
