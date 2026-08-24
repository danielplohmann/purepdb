#!/usr/bin/env python3
"""Read a corpus of real PDBs fully, and report what purepdb could not handle.

The shape sweep (`survey_pdb_shapes.py`) reads a header and moves on. This does
the opposite: it drives the whole parser over every file and reports the damage.
It is slower by orders of magnitude and it is the one that finds bugs -- a
corpus swept for one debug-header shape found none, and turned up a stream
directory whose block map spanned two blocks, which purepdb had been rejecting
outright.

What it reports, in rough order of how much it should worry you:

  refused        purepdb raised. Some of these are correct and expected -- a
                 Portable PDB, a compiler-intermediate vc140.pdb -- and the
                 reason is printed so the two can be told apart. An unexpected
                 reason here is a parser gap.
  warnings       what `diagnose()` says is missing and why, tallied by kind.
  malformed      records shorter than the kind they claim to be.
  truncations    record streams that stopped early.
  undecoded      record kinds seen in module streams that purepdb does not
                 decode, most frequent first. This is the map of what the
                 parser is not reading, measured against real files rather
                 than against the format documentation.

    python dev/audit_corpus.py ~/pdbs --glob '*'

Nothing is fetched and nothing is written. Point it at files you already have.
"""

from __future__ import annotations

import argparse
import collections
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purepdb import PDB, PdbError, codeview


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpus", type=Path)
    ap.add_argument("--glob", default="*.pdb")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--max-bytes", type=int, default=0,
                    help="skip files larger than this (0 = no limit); the whole "
                         "file is read, so a huge corpus can be bounded")
    args = ap.parse_args(argv[1:])

    files = sorted(args.corpus.rglob(args.glob))
    if args.limit:
        files = files[:args.limit]

    refused: collections.Counter[str] = collections.Counter()
    warned: collections.Counter[str] = collections.Counter()
    kinds: collections.Counter[int] = collections.Counter()
    read = malformed = truncated = 0
    escaped = []
    totals = collections.Counter()

    for path in files:
        if args.max_bytes and path.stat().st_size > args.max_bytes:
            refused[f"skipped: larger than {args.max_bytes} bytes"] += 1
            continue
        try:
            pdb = PDB.open(str(path))
            d = pdb.diagnose()
            # Force the lazy listings too, since a generator never consumed is
            # a walker never tested.
            totals["functions"] += len(pdb.functions())
            totals["publics"] += len(pdb.public_symbols())
            totals["labels"] += len(pdb.labels())
            totals["inline sites"] += len(pdb.inline_sites())
            totals["thread locals"] += len(pdb.thread_locals())
            totals["lines"] += sum(1 for _ in pdb.lines())
        except PdbError as exc:
            refused[f"{type(exc).__name__}: {str(exc)[:70]}"] += 1
            continue
        except Exception:
            escaped.append((path, traceback.format_exc(limit=3)))
            continue

        read += 1
        malformed += d.malformed_records
        truncated += d.truncated_streams
        for w in d.warnings:
            warned[w.split(";")[0].split("(")[0].strip()[:64]] += 1
        for kind, n in d.module_kinds.items():
            if codeview.kind_name(kind).startswith("0x"):
                kinds[kind] += n

    print(f"\n{read} read, {sum(refused.values())} refused, "
          f"{len(escaped)} leaked a non-PdbError")
    print(f"  {malformed} malformed record(s), {truncated} truncated stream(s)")
    for name, n in totals.most_common():
        print(f"  {n:>10,}  {name}")

    if refused:
        print("\nrefused:")
        for reason, n in refused.most_common():
            print(f"  {n:4d}  {reason}")
    if warned:
        print("\ndiagnose() warnings:")
        for w, n in warned.most_common(12):
            print(f"  {n:4d}  {w}")
    if kinds:
        print("\nundecoded record kinds in module streams:")
        for kind, n in kinds.most_common(15):
            print(f"  {n:>9,}  {kind:#06x}")

    if escaped:
        print(f"\n{len(escaped)} FILE(S) LEAKED A NON-PdbError -- these are bugs:")
        for path, tb in escaped[:5]:
            print(f"\n  {path}\n{tb}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
