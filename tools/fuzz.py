#!/usr/bin/env python3
"""Fuzz the parse boundary: malformed input must not escape as an exception.

purepdb's contract is that a file it cannot read produces `PdbError` (or one of
its subclasses) or an empty result -- never a `struct.error`, `IndexError`,
`EOFError` or `KeyError` leaking from a stdlib call, and never a hang. That is
the property this checks, because it is the one a caller writes `except
PdbError` against.

Three input sources, because they reach different code:

  random      uniform bytes, which mostly die in the MSF superblock
  structured  a valid container whose interior fields are corrupted, which is
              what actually reaches the DBI and CodeView parsers
  mutation    real fixtures with bytes flipped, which keeps enough structure
              intact to get deep into the record walkers

Run directly for a quick pass, or with --iterations for a longer one:

    python tools/fuzz.py --iterations 20000 --seed 0
"""

from __future__ import annotations

import argparse
import random
import signal
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purepdb import PDB
from purepdb.msf import MsfError, PdbError

DATA = Path(__file__).resolve().parent.parent / "tests" / "data"

# What a caller is entitled to see. Everything else is a defect: it means a
# stdlib exception crossed the boundary instead of being turned into one of
# these or into an empty result.
ALLOWED = (PdbError, MsfError, RecursionError)

# A single input may not take longer than this. Anything slower is treated as a
# hang, since the shapes here are all a few tens of KB at most.
TIMEOUT_SECONDS = 10


class Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise Timeout


def exercise(data: bytes) -> list:
    """Drive every public entry point over one input, returning what they gave.

    The results are collected rather than discarded so that lazy work is really
    forced -- `lines()` is a generator, and never consuming it would leave the
    C13 walker untested.
    """
    pdb = PDB.from_bytes(data)
    seen = [
        pdb.sections,
        pdb.derived_sections,
        pdb.original_sections,
        pdb.functions(),
        pdb.public_symbols(),
        pdb.publics_stream(),
        pdb.module_procs(),
        pdb.data_symbols(),
        pdb.thread_locals(),
        pdb.constants(),
        pdb.udts(),
        pdb.compile_info(),
        pdb.thunks(),
        pdb.trampolines(),
        pdb.labels(),
        pdb.inline_sites(),
        pdb.section_contributions(),
        pdb.named_streams(),
        pdb.string_table(),
        pdb.id_table(),
        [pdb.resolve_proc_ref(ref) for ref in pdb.proc_refs()],
        list(pdb.lines()),
        pdb.diagnose().warnings,
        # Last: this is the one call a short PDB Info stream
        # rejects outright, and from the front of the list it
        # ended the sweep before the other entry points ran.
        pdb.info(),
    ]
    return seen


def corpus(max_bytes: int) -> list[bytes]:
    """Seed files to mutate, smallest first, up to `max_bytes` each.

    The sqlite fixtures are 3 MB and carry 70k line records, so a full parse of
    one is ~100x the cost of the rust fixtures. Capping the seed size keeps a
    default run to seconds; a nightly run raises the cap to include them.
    """
    paths = sorted(DATA.rglob("*.pdb"), key=lambda p: p.stat().st_size)
    return [p.read_bytes() for p in paths if p.stat().st_size <= max_bytes]


def gen_random(rng: random.Random, _seeds: list[bytes]) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 4096)))


def gen_structured(rng: random.Random, seeds: list[bytes]) -> bytes:
    """A real file with a burst of corruption in its first 8 KB.

    The header, stream directory and DBI substream sizes live there, so this is
    what produces absurd counts and offsets rather than an unreadable container.
    """
    if not seeds:
        return gen_random(rng, seeds)
    data = bytearray(rng.choice(seeds))
    for _ in range(rng.randrange(1, 24)):
        pos = rng.randrange(0, min(len(data), 8192))
        data[pos] = rng.getrandbits(8)
    return bytes(data)


def gen_mutation(rng: random.Random, seeds: list[bytes]) -> bytes:
    if not seeds:
        return gen_random(rng, seeds)
    data = bytearray(rng.choice(seeds))
    for _ in range(rng.randrange(1, 64)):
        data[rng.randrange(0, len(data))] = rng.getrandbits(8)
    return bytes(data)


GENERATORS = {"random": gen_random, "structured": gen_structured,
              "mutation": gen_mutation}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-failures", type=int, default=5,
                    help="stop after this many distinct defects")
    ap.add_argument("--max-seed-bytes", type=int, default=1 << 20,
                    help="skip seed fixtures larger than this (default 1 MiB)")
    ap.add_argument("--max-seconds", type=float, default=0.0,
                    help="stop once this much wall clock has gone (0: no limit)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    seeds = corpus(args.max_seed_bytes)
    if not seeds:
        print("no fixtures found; running with generated input only",
              file=sys.stderr)

    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _alarm)

    # A budget in seconds rather than in inputs, because the cost of an input
    # is set by the corpus: the same iteration count is a minute with the small
    # fixtures and hours with the 3 MB ones. Stopping early loses coverage but
    # not reproducibility -- generation is sequential from the seed, so
    # iteration i is the same input whether or not the run reached it.
    deadline = time.monotonic() + args.max_seconds if args.max_seconds > 0 else None

    failures: dict[str, tuple[int, bytes]] = {}
    ran = 0
    for i in range(args.iterations):
        if deadline is not None and time.monotonic() >= deadline:
            break
        ran = i + 1
        name = list(GENERATORS)[i % len(GENERATORS)]
        data = GENERATORS[name](rng, seeds)
        if hasattr(signal, "SIGALRM"):
            signal.alarm(TIMEOUT_SECONDS)
        try:
            exercise(data)
        except ALLOWED:
            pass
        except Timeout:
            key = f"{name}: TIMEOUT after {TIMEOUT_SECONDS}s"
            failures.setdefault(key, (i, data))
        except Exception:  # the point is to catch everything
            frame = traceback.extract_tb(sys.exc_info()[2])[-1]
            key = (f"{name}: {type(sys.exc_info()[1]).__name__} at "
                   f"{Path(frame.filename).name}:{frame.lineno}")
            failures.setdefault(key, (i, data))
            if len(failures) >= args.max_failures:
                break
        finally:
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)

    if not failures:
        short = f" of {args.iterations} (out of time)" if ran < args.iterations else ""
        print(f"ok: {ran} inputs{short}, seed {args.seed}, "
              f"no exception escaped {'/'.join(e.__name__ for e in ALLOWED)}")
        return 0

    print(f"FAIL: {len(failures)} distinct defect(s), seed {args.seed}\n",
          file=sys.stderr)
    out = Path("fuzz-failures")
    out.mkdir(exist_ok=True)
    for key, (i, data) in sorted(failures.items()):
        path = out / f"iter{i}.bin"
        path.write_bytes(data)
        print(f"  {key}\n    iteration {i}, input saved to {path}",
              file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
