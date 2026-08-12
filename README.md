# purepdb

A minimal, dependency-free pure-Python parser for Microsoft PDB debug-info
files. Purpose-built to answer one question well: **what are the functions in
this binary and where are their entry points?**

It is *not* a reimplementation of `llvm-pdbutil` — it is a thin vertical slice
through the same format stack, written from the published format
documentation. See [NOTICE](NOTICE) for provenance and prior art.

## Install

```bash
uv pip install -e '.[dev]'     # dev extra is just pytest
```

Runtime dependencies: none. Python 3.9+.

## Usage

```python
from purepdb import PDB

pdb = PDB.open("app.pdb")

for fn in pdb.functions():
    print(hex(fn.rva or 0), fn.name)
    # fn.segment, fn.offset, fn.code_size, fn.source, fn.aliases
```

`rva` is **image-relative**. Add the PE image base yourself if you need virtual
addresses.

`aliases` holds the other names at the same entry point. Linkers fold identical
bodies (`/OPT:ICF`, and rust-lld by default), so one address legitimately
carries several correct names; `fn.names` gives all of them with `fn.name`
first. On sqlite3 x86 that is 357 of 3620 functions, worst case 3 names.

CLI:

```
purepdb functions app.pdb    # name + entry-point RVA
purepdb publics   app.pdb
purepdb info      app.pdb
purepdb diagnose  app.pdb    # what the PDB contains, and why a listing is thin
```

## When a listing comes back short

Every failure mode this parser has on real files produces an *empty result*
rather than an exception, so `diagnose()` exists to tell them apart:

```
$ purepdb diagnose app.pdb
proc records       : 0
public records     : 7400
WARNING: no procedure records in 285 module streams (dominant kinds:
0x1167x110161, S_TRAMPOLINEx4610, ...); function names can only come from the
7400 public records. This is what /DEBUG:FASTLINK and some pre-2010 toolchains
produce
```

The CLI prints these warnings automatically after `functions` and `publics`.

## Two things worth knowing about publics

**They live in the symbol-record stream.** DBI's `PublicStreamIndex` names a
*hash* stream holding offsets, not records — scanning it for `S_PUB32` finds
nothing at all, silently. `purepdb.gsi` documents the layout; the publics stream
is used only for its address map, which supplies address ordering.

**The function flag is not reliable across linkers.** `link.exe` sets
`PUBLIC_FLAG_FUNCTION` on every code public (all 438 of sqlite3 x86's).
`rust-lld` leaves it clear on 143 of 280, including `mainCRTStartup` and
`__chkstk`. So a public also counts as a function when it resolves into an
executable section — worth 36% of the functions in a Rust PE.

**This means `functions()` deliberately returns more than the flag alone would.**
On the Rust fixture, 164 entries are public-sourced while only 142 publics carry
the function flag. The extra ones are real code — every one resolves inside
`.text`, verified against the image — but a consumer that previously filtered on
`PublicSymbol.is_function` will see entries it does not expect. Pass
`functions(code_publics=False)` for flag-only behaviour, and note that
`public_symbols()` is unfiltered either way, so `is_function` still means exactly
what the record says.

## Scope

**Supported:** MSF 7.00 container; PDB info stream; DBI stream (module list,
publics/symbol-record streams, optional debug header); CodeView `S_PUB32`,
`S_GPROC32`/`S_LPROC32` (and `_ID` variants), `S_GDATA32`/`S_LDATA32`; section-
header table for `segment:offset -> RVA`, with DBI's Section Map as the
fallback when that table is absent; OMAP address translation for images whose
code was moved after linking.

**Not supported:** TPI/IPI type decoding, line/source tables, demangling (names
come back raw). `/DEBUG:FASTLINK` PDBs yield publics only, and say so.

Where the section-header stream is missing, addresses are rebuilt from the
Section Map, which records segment sizes but no addresses. `diagnose()` says
when that happened, because the result is a reconstruction — taking the stream
away from each fixture leaves every function at the address it had before, but
it assumes the default `0x1000` section alignment.

## Tests

```bash
.venv/bin/python -m pytest -q
```

Two layers. Synthetic tests build MSF/PDB byte streams with a builder
independent of the reader, so they exercise a real serialise→parse round trip.
Golden tests run against real `link.exe` and `rust-lld` output in `tests/data/`
and cross-check against the companion PE image — section table, and the address
of every exported function after following its `jmp` thunk. The PE reader in
`tests/_pe.py` is stdlib-only and never consults the PDB, so agreement is
evidence rather than a shared assumption.

`tests/data/` is in the repository but excluded from the sdist and wheel, so
installing purepdb does not pull down 12 MB of binaries. Those tests skip when
the data is absent — clone the repo to run them.

The suite needs no external tool. Results are also cross-checked
record-by-record against `llvm-pdbutil` during development, where that toolchain
is available.
