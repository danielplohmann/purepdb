# Performance track — purepdb audit, 2026-09

Branch `perf/hot-paths`, rebased onto `audit/fixes-2026-09`. Every number
here is from `tools/bench.py` (wall seconds, best of `--repeat N` where
noted, CPython 3.11.15, 4-core Xeon @ 2.80 GHz, 15 GB) unless it says
otherwise. Peak RSS is the process high-water mark from `resource.getrusage`,
so the column only rises down a table.

Correctness gate for every commit: the test suite, `ruff check`, `ty check`,
`tools/fuzz.py` (2000 inputs), and `tools/snapshot.py` -- every public
listing dumped to JSON -- compared by sha256 against the unmodified base
tree on every fixture and every corpus file under 50 MB (432 files, the
deliberately corrupt ones included, where the recorded `PdbError` has to
match too), plus node.pdb once at the end. Before the rebase the base was
`main` at e978f3a; after it, `audit/fixes-2026-09` at 179673d.
Zero differences in either: 432 files against main, 439 files (the
corpus had grown) plus node.pdb against the fixes tree.

## Before / after

"before" is the base tree: `main` for the first block, the fixes branch for
the rebased measurements (the two bases differ only where the fixes branch
changed what is listed -- `inline_sites` counts on MSVC files,
`compile_info` -- so their timings are close but not identical).

### sqlite x64 fixture (3.1 MB) — main vs branch before the rebase, best of 3

| op | main | branch | speedup |
|---|---:|---:|---:|
| open | 0.017 | 0.017 | 1.0x |
| functions | 0.183 | 0.041 | 4.5x |
| public_symbols | 0.009 | 0.003 | 3x |
| diagnose | 0.499 | 0.082 | 6.1x |
| lines (70k) | 0.182 | 0.106 | 1.7x |
| inline_sites | 0.091 | 0.026 | 3.5x |
| labels | 0.074 | 0.015 | 4.9x |
| data_symbols | 0.079 | 0.014 | 5.6x |
| **all** | **1.135** | **0.303** | **3.7x** |
| peak RSS after lines (bench holds 70k `Line`s) | 71 MB | 50 MB | |

### Rebased branch vs `audit/fixes-2026-09`, best of 2

| file | op | fixes | branch | speedup |
|---|---|---:|---:|---:|
| sqlite x64 (3.1 MB) | functions | 0.182 | 0.033 | 5.5x |
| | diagnose | 0.550 | 0.068 | 8.1x |
| | lines | 0.196 | 0.123 | 1.6x |
| | inline_sites | 0.088 | 0.021 | 4.2x |
| | labels | 0.071 | 0.016 | 4.4x |
| | data_symbols | 0.078 | 0.014 | 5.6x |
| | **all** | **1.193** | **0.296** | **4.0x** |
| rustpe (0.8 MB, 3797 sites) | diagnose | 0.181 | 0.029 | 6.2x |
| | inline_sites | 0.057 | 0.029 | 2.0x |
| | **all** | **0.310** | **0.076** | **4.1x** |
| python314.pdb (20.7 MB, MSVC PGO, 51k sites) | open | 0.088 | 0.082 | |
| | functions (11595) | 1.774 | 0.267 | 6.6x |
| | public_symbols (14429) | 0.102 | 0.047 | 2.2x |
| | diagnose | 6.688 | 0.876 | 7.6x |
| | lines (190k) | 0.607 | 0.416 | 1.5x |
| | inline_sites (50997) | 1.647 | 0.754 | 2.2x |
| | labels | 0.762 | 0.130 | 5.9x |
| | data_symbols | 0.864 | 0.148 | 5.8x |
| | **all** | **12.534** | **2.720** | **4.6x** |
| | peak RSS | 173 MB | 133 MB | |
| ntkrnlmp.pdb (8.5 MB, 1782 modules, stripped) | functions (30598) | 0.641 | 0.445 | 1.4x |
| | public_symbols (39801) | 0.241 | 0.141 | 1.7x |
| | diagnose | 1.359 | 0.217 | 6.3x |
| | **all** | **2.670** | **0.995** | **2.7x** |

### node.pdb (354.6 MB, 3340 modules, 1.58 M inline sites), single runs

Main baseline (before any change) against the branch before the rebase:

| op | main | branch (pre-rebase) | speedup |
|---|---:|---:|---:|
| open | 1.385 | 0.652 | 2.1x |
| functions (75148) | 25.020 | 4.403 | 5.7x |
| public_symbols (139920) | 1.629 | 1.194 | 1.4x |
| diagnose | 112.618 | 22.684 | 5.0x |
| lines (1.04 M) | 4.623 | 2.523 | 1.8x |
| inline_sites (1.58 M) | 38.391 | 21.215 | 1.8x |
| labels (56664) | 9.271 | 1.595 | 5.8x |
| data_symbols (26225) | 10.634 | 1.739 | 6.1x |
| **all** | **203.572** | **59.846** | **3.4x** |
| peak RSS, end of run | 1596 MB | 1354 MB | |
| peak RSS after diagnose | 1364 MB | 666 MB | |

Rebased branch against `audit/fixes-2026-09` (whose `diagnose()` already
counts inline sites without building the listing):

| op | fixes | branch (rebased) | speedup |
|---|---:|---:|---:|
| open | 0.807 | 0.641 | 1.3x |
| functions (75148) | 21.572 | 3.501 | 6.2x |
| public_symbols (139920) | 1.574 | 1.056 | 1.5x |
| diagnose | 107.101 | 29.936 | 3.6x |
| lines (1.04 M) | 4.394 | 2.972 | 1.5x |
| inline_sites (1.58 M) | 38.093 | 19.634 | 1.9x |
| labels (56664) | 9.579 | 1.610 | 5.9x |
| data_symbols (26225) | 10.149 | 1.752 | 5.8x |
| **all** | **193.269** | **61.102** | **3.2x** |
| peak RSS after diagnose | 701 MB | 689 MB | |
| peak RSS, end of run | 1670 MB | 1404 MB | |

The four node runs were made with other work on the box (the fixes-tree
snapshot pass in parallel), so treat them as ±10%; the snapshot of every
listing on node.pdb is identical between the two trees.

### xul.pdb (1.93 GB, 627 modules, 11.07 M inline sites), single run, branch before the rebase

Run alone with `snap/xul.py` (open, functions, diagnose only; the listing
entry points would materialise eleven million objects). The coordinator's
figure for main was `purepdb diagnose` exceeding 600 s at 3.2 GB RSS; the
fixes branch's own `diagnose()` (which counts sites without building the
listing) was measured by that track at 7.2 GB. The rebased branch was not
re-run on xul in the time available.

| op | branch | peak RSS |
|---|---:|---:|
| open | 15.3 s | 2089 MB |
| functions (265345) | 31.4 s | 4287 MB |
| diagnose | 152.5 s | 7047 MB |

`open` is 1.9 GB read into `bytes` (the file itself), which is the floor
for RSS while `PDB.open` reads rather than maps; see "not done" below.

## What each commit did, and what it measured

In branch order (hashes after the rebase onto `audit/fixes-2026-09`):

1. `22b89a9` tools: `bench.py` and `snapshot.py`, the baseline above.
2. `6f2c4b8` `iter_records` with one `unpack_from` per header and a `kinds`
   filter. The walk was 73% of everything (cProfile on sqlite x64: 500k
   `iter_records` iterations, 1.7 M `Reader._take`). All ops 1.135 s -> 0.555 s.
3. `f21abde` `Reader.u16/u32` through `Struct.unpack_from` at the cursor.
   `parse_proc` x3522: 18.3 ms -> 11.7 ms.
4. `2be8127` `lines()`: file name once per checksum entry, section base once
   per segment (per-entry `to_rva` kept when an OMAP applies, since that is
   per address), `iter_unpack` for the entry array, `slots=True` on `Line`,
   `LineEntry`, `RawRecord`. 0.219 s -> 0.123 s.
5. `d551c8e` `codeview.survey_records`: one walk per module stream for the
   kind histogram, the malformed count (found by running every dispatched
   parser, as before) and the decoded procs/inline sites/sepcodes, so
   `diagnose()` no longer calls `module_procs()` and the inline listing on
   top of three counting walks; `functions()` takes procs and thunks from
   one walk. `proc_records` and `public_records` are records of the kind
   less the malformed ones of that kind, which is exactly what the
   extractors return. After the rebase the placement is
   `PDB._place_module_sites`, shared with `_inline_listing`, so the listing
   and the diagnostic agree by construction. diagnose 0.193 s -> 0.082 s.
6. `bade627` fixed-portion `Struct` per named record kind, name by one
   `find`. `parse_proc` x3522: 11.7 ms -> 4.5 ms.
7. `df5b129` `_read_blocks` takes contiguous block runs as one slice.
   Reading every stream of node.pdb: 0.70 s -> 0.51 s.
8. `65e7815` `parse_inline_site` with an integer cursor over the payload,
   the one-byte operand read inline. Was 60% of both `inline_sites()` and
   `diagnose()` on node (14.7 M `Reader.u8` calls). Re-applied on top of
   the fixes branch's version (S_INLINESITE2, the chunk rule, the fused
   opcode not moving the cursor) during the rebase.
9. `aa09816` `IdTable.parse` counts positionally without a `RawRecord` per
   record and without copying the stream.
10. `3b18608` `slots=True` on `InlineFunction`; id-table lookup hoisted.

## Dead ends and things measured but not done

- **mmap in `PDB.open`.** Done: `open` maps by default, `close()` / a
  context manager own the handle, `copy=True` is the old read.
  `tools/snapshot.py --mmap` still exercises the caller-owned
  `from_bytes` path.
- **`diagnose()` memory on xul.** Done: procs and `S_SEPCODE` chunks are
  collected first, then each site is placed as it is parsed so the
  millions of decoded sites are not held for the module. Re-measure with
  `tools/bench.py` / `tools/snapshot.py`; the correctness gate is sha256
  identity of snapshots.
- **Section contributions as a lighter representation.** Profiled on
  ntkrnlmp (59669 entries): `DbiStream.parse` is 0.11 s of a 0.995 s run,
  and `ContributionMap` sorts once. Not worth an API-visible change.
- **`iter_records` is now at the Python floor** (~0.4 µs per record without
  the profiler); a full walk of node's 6.5 M records is ~2.5 s and every
  listing that scans module streams pays one. The next step would be to
  serve several listings from one walk (a cache of decoded records per
  module), which changes memory behaviour and was not attempted.
- **`functions()` on ntkrnlmp is `module_of` bound** (30k bisects over 59k
  contributions plus `Function` construction); only 1.4x there.
- Whole-run timings on the 3 MB fixture move by ±10% between runs; the
  per-commit claims above are from microbenchmarks (`snap/micro.py`) where
  the whole-run figure was inside the noise.

## Reproducing

    .venv/bin/python tools/bench.py --root /path/to/base <pdb...> --repeat 3
    .venv/bin/python tools/bench.py <pdb...> --repeat 3
    .venv/bin/python tools/snapshot.py --root /path/to/base big.pdb | sha256sum
    .venv/bin/python tools/snapshot.py big.pdb | sha256sum
