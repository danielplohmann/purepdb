#!/usr/bin/env python3
"""Dump every listing purepdb produces for a PDB, as JSON, for diffing.

A performance change is only admissible when it changes nothing a caller can
see, and "the tests pass" is a weaker claim than that: the groundtruth tests
pin counts, not every field of every record. This writes the whole of each
public listing -- name, address, size, module, aliases, and so on -- so that
the output of two checkouts can be compared byte for byte:

    python tools/snapshot.py --root /path/to/main   big.pdb > before.json
    python tools/snapshot.py --root /path/to/branch big.pdb > after.json
    diff before.json after.json

`--root` names the checkout whose `purepdb` package is imported, so the same
script can be pointed at an unmodified tree; it defaults to the one this file
lives in. Dataclasses are serialised field by field, and properties that
carry a decision (`is_function`, `names`, `warnings`) are added beside them
because those are what a consumer reads.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path


def _plain(obj):
    """A JSON-ready copy of `obj`: dataclasses become dicts, bytes become hex."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out = {f.name: _plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
        for extra in ("is_function", "is_global", "names", "code_size",
                      "ordinal_name", "language_name", "machine_name",
                      "is_source", "warnings", "truncated_streams",
                      "managed_proc_records", "unmatched_proc_refs"):
            if extra not in out and hasattr(type(obj), extra):
                out[extra] = _plain(getattr(obj, extra))
        return out
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    return obj


def snapshot(pdb) -> dict:
    listings = {
        "info": None,
        "sections": pdb.sections,
        "derived_sections": pdb.derived_sections,
        "original_sections": pdb.original_sections,
        "named_streams": pdb.named_streams(),
        "functions": pdb.functions(),
        "functions_strict": pdb.functions(code_publics=False),
        "public_symbols": pdb.public_symbols(),
        "module_procs": pdb.module_procs(),
        "proc_refs": pdb.proc_refs(),
        "labels": pdb.labels(),
        "thunks": pdb.thunks(),
        "trampolines": pdb.trampolines(),
        "inline_sites": pdb.inline_sites(),
        "lines": list(pdb.lines()),
        "data_symbols": pdb.data_symbols(),
        "thread_locals": pdb.thread_locals(),
        "constants": pdb.constants(),
        "udts": pdb.udts(),
        "compile_info": pdb.compile_info(),
        "section_contributions": pdb.section_contributions(),
        "modules": pdb.dbi.modules,
        "diagnose": pdb.diagnose(),
    }
    try:
        listings["info"] = pdb.info()
    except Exception as exc:
        listings["info"] = f"error: {exc}"
    return {name: _plain(value) for name, value in listings.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("path", help="the PDB to snapshot")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent),
                        help="checkout whose purepdb package to import")
    parser.add_argument("--mmap", action="store_true",
                        help="open through a caller-owned memory map (PDB.from_bytes) "
                             "rather than PDB.open, which maps and owns the file")
    args = parser.parse_args(argv)

    sys.path.insert(0, args.root)
    import purepdb

    # A file the parser refuses is part of the record too: the error it
    # raises is what a caller sees, so the snapshot holds it, and a change
    # that turns a refusal into a listing (or the reverse) is a difference.
    try:
        if args.mmap:
            import mmap

            with open(args.path, "rb") as f, mmap.mmap(
                    f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                snap = snapshot(purepdb.PDB.from_bytes(m))
        else:
            pdb = purepdb.PDB.open(args.path)
            try:
                snap = snapshot(pdb)
            finally:
                # `close` is new: an unmodified --root tree has no mapping
                # to release, and no method.
                closer = getattr(pdb, "close", None)
                if closer is not None:
                    closer()
    except purepdb.PdbError as exc:
        snap = {"error": f"{type(exc).__name__}: {exc}"}
    snap["_purepdb"] = str(Path(purepdb.__file__).resolve())
    json.dump(snap, sys.stdout, indent=0, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
