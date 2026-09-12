#!/usr/bin/env python3
"""Time the public entry points over one or more PDBs.

Every figure in `docs/audit/perf.md` comes from this script, so that a
"3x faster" claim can be re-measured rather than believed. Wall time is what
a caller sweeping a directory waits for, and peak RSS is what stops the sweep
from running on a small machine -- both are reported, per file, per entry
point, along with the count each call returned so a speedup that quietly
returns fewer symbols is visible in the same table.

    python tools/bench.py tests/data/sqlite/x64/*.pdb --repeat 3
    python tools/bench.py big.pdb --profile 2>profile.txt
    python tools/bench.py big.pdb --json > before.json

`--profile` runs each entry point once more under cProfile and prints the top
40 functions by cumulative time to stderr, which is how the hot paths in the
perf notes were found. Peak RSS is from `resource.getrusage`, which reports
the process high-water mark: it only ever rises, so the per-operation column
is "the peak after this ran", not "what this alone cost".
"""

from __future__ import annotations

import argparse
import cProfile
import io
import json
import pstats
import resource
import sys
import time
from collections.abc import Callable, Sized
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purepdb import PDB

# Entry points, in the order they are timed. `open` is special-cased because
# the others need its result; each of the rest takes the PDB and returns
# something whose length is the count reported beside its time.
OPERATIONS: list[tuple[str, Callable[[PDB], object]]] = [
    ("functions", lambda p: p.functions()),
    ("public_symbols", lambda p: p.public_symbols()),
    ("diagnose", lambda p: p.diagnose()),
    ("lines", lambda p: list(p.lines())),
    ("inline_sites", lambda p: p.inline_sites()),
    ("labels", lambda p: p.labels()),
    ("data_symbols", lambda p: p.data_symbols()),
]


def _peak_rss_mb() -> float:
    # ru_maxrss is kilobytes on Linux and bytes on macOS; the platform check
    # keeps the column honest on both rather than silently off by 1024.
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        peak /= 1024
    return peak / 1024


def _count(result: object) -> int | None:
    if isinstance(result, PDB):
        return len(result.dbi.modules)
    if isinstance(result, Sized):
        return len(result)
    # `Diagnostics` has no length; its warning count is the useful number.
    warnings = getattr(result, "warnings", None)
    return len(warnings) if warnings is not None else None


def _timed(fn: Callable[[], object], repeat: int) -> tuple[float, object]:
    """Best of `repeat` runs, in seconds, and the last result."""
    best = float("inf")
    result: object = None
    for _ in range(repeat):
        t0 = time.perf_counter()
        result = fn()
        best = min(best, time.perf_counter() - t0)
    return best, result


def bench_file(path: str, repeat: int, profile: bool) -> dict:
    size = Path(path).stat().st_size
    rows: list[dict] = []

    t, pdb = _timed(lambda: PDB.open(path), repeat)
    assert isinstance(pdb, PDB)
    rows.append({"op": "open", "seconds": t, "count": _count(pdb),
                 "peak_rss_mb": _peak_rss_mb()})

    for name, op in OPERATIONS:
        # A fresh PDB per operation would be the purist choice, but the
        # per-instance caches (`/names`, IPI, the last module stream) are
        # part of what is being measured: a caller holds one PDB and asks it
        # several things, and that is the shape to time.
        t, result = _timed(lambda op=op: op(pdb), repeat)
        rows.append({"op": name, "seconds": t, "count": _count(result),
                     "peak_rss_mb": _peak_rss_mb()})

    prof_text = None
    if profile:
        prof = cProfile.Profile()
        prof.enable()
        fresh = PDB.open(path)
        for _name, op in OPERATIONS:
            op(fresh)
        prof.disable()
        buf = io.StringIO()
        pstats.Stats(prof, stream=buf).sort_stats("cumulative").print_stats(40)
        prof_text = buf.getvalue()

    return {"file": path, "bytes": size, "rows": rows, "profile": prof_text}


def _print_table(report: dict) -> None:
    print(f"{report['file']}  ({report['bytes'] / 1e6:.1f} MB)")
    print(f"  {'op':<16}{'seconds':>10}{'count':>10}{'peak RSS MB':>14}")
    for row in report["rows"]:
        count = "" if row["count"] is None else str(row["count"])
        print(f"  {row['op']:<16}{row['seconds']:>10.3f}{count:>10}"
              f"{row['peak_rss_mb']:>14.1f}")
    total = sum(row["seconds"] for row in report["rows"])
    print(f"  {'total':<16}{total:>10.3f}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="+", help="PDB files to time")
    parser.add_argument("--repeat", type=int, default=1,
                        help="runs per operation; the best is reported")
    parser.add_argument("--profile", action="store_true",
                        help="also print cProfile's top 40 by cumulative time to stderr")
    parser.add_argument("--json", action="store_true",
                        help="emit one JSON document instead of the table")
    args = parser.parse_args(argv)

    reports = []
    for path in args.paths:
        report = bench_file(path, args.repeat, args.profile)
        if report["profile"]:
            print(f"== profile: {path}", file=sys.stderr)
            print(report["profile"], file=sys.stderr)
        reports.append(report)
        if not args.json:
            _print_table(report)

    if args.json:
        for report in reports:
            report.pop("profile")
        json.dump(reports, sys.stdout, indent=1)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
