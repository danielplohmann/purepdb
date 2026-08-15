# purepdb

A minimal, dependency-free pure-Python parser for Microsoft PDB debug-info
files. Purpose-built to answer one question well: **what are the functions in
this binary and where are their entry points?**

It is *not* a reimplementation of `llvm-pdbutil` — it is a thin vertical slice
through the same format stack, written from the published format
documentation. See [NOTICE](NOTICE) for provenance and prior art.

## Install

```bash
uv pip install -e . --group dev   # pytest, ruff and ty
```

Runtime dependencies: none. Python 3.11+.

## Usage

```python
from purepdb import PDB

pdb = PDB.open("app.pdb")

for fn in pdb.functions():
    print(hex(fn.rva or 0), fn.name)
    # fn.segment, fn.offset, fn.code_size, fn.source, fn.aliases, fn.module
```

`module` is the linker input the address came from — an `.obj` path, a library
member, or `Import:foo.dll` for an import thunk — taken from DBI's Section
Contribution table. It is what separates library code from application code
without guessing from the name: 3453 of sqlite3 x86's 3620 functions come from
`sqlite3.lo`, the rest from the CRT and from import thunks.

`rva` is **image-relative**. Add the PE image base yourself if you need virtual
addresses.

`source` is `"proc"`, `"public"` or `"thunk"`, naming the record the entry came
from. Incremental-link trampolines are *not* in this list — they carry no name,
so `pdb.trampolines()` reports them separately, as a code range plus the address
it jumps to.

`aliases` holds the other names at the same entry point. Linkers fold identical
bodies (`/OPT:ICF`, and rust-lld by default), so one address legitimately
carries several correct names; `fn.names` gives all of them with `fn.name`
first. On sqlite3 x86 that is 438 of 3620 functions, worst case 4 names.

`pdb.lines()` yields `(rva, file, line)` for every source line the PDB records —
70157 of them in sqlite3 x86, across 133 files. It is a generator; the file
names come from the `/names` stream, which `pdb.named_streams()` locates.

CLI — every listing in this README has a subcommand:

```
purepdb functions    app.pdb    # rva  source  size  aliases  name
purepdb publics      app.pdb    # seg  off  kind  name
purepdb data         app.pdb    # rva  scope  name
purepdb labels       app.pdb    # rva  name
purepdb thunks       app.pdb    # rva  size  ordinal  name
purepdb trampolines  app.pdb    # rva  size  -> target rva
purepdb inline       app.pdb    # rva  size  name <TAB> <- parent
purepdb lines        app.pdb    # rva  file:line
purepdb constants    app.pdb    # value  name
purepdb udts         app.pdb    # type-index  name
purepdb modules      app.pdb    # contributions  module
purepdb sections     app.pdb    # rva  size  executable  name
purepdb info         app.pdb    # version, signature, age and GUID
purepdb diagnose     app.pdb    # what the PDB contains, and why a listing is thin
```

`purepdb --help` lists them all. Output is one record per line with stable
leading columns; counts, warnings and the usage text go to stderr, so a
redirected stdout holds records and nothing else:

```bash
purepdb functions app.pdb | awk '$1 != "??????" {print $1}' | sort
```

A name can contain spaces — `std::rt::lang_start::closure$0<tuple$<> >` is one
name — so **the name is the last field on its line** and nothing follows it.
The one line carrying two names, an inline site and the function it was
inlined into, separates them with a tab, which a name cannot contain because
control characters in a name are escaped.

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

The CLI prints these warnings to stderr after every listing.

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

## Inlined functions

An inlined body has no entry point, so it has no procedure record and no public
— `functions()` cannot see it by construction. `pdb.inline_sites()` reports them
separately, each with its name, the code ranges it occupies inside its caller,
and which function that is:

```python
for site in pdb.inline_sites():
    print(hex(site.rva or 0), site.name, "inlined into", site.parent)
```

On the Rust fixture that is 3797 sites against 248 procedure records — fifteen
inlined bodies for every function with an entry point, and the largest naming
gap the parser had.

## Labels

`S_LABEL32` names a code address *inside* a function — an assembly label, an
exception continuation target, the address an interrupt returns to. It is not
an entry point, so like a trampoline it stays out of `functions()`: listing one
would count a body twice.

```python
for label in pdb.labels():
    print(hex(label.rva or 0), label.name)
```

sqlite3 x86 has 1412 of them and x64 1237, every one inside a function body
purepdb already found, and not one of those 586 distinct names appears in any
other listing.

Not every producer fills the record in: all 160 in the Rust fixture are twelve
bytes of fixed fields with an empty name and segment 0. The offset is real, but
segment 0 names no section, so nothing resolves. They are still reported,
because the count is what the file says; a caller wanting the useful ones
filters on `label.rva is not None`.

## What produced a module

`compile_info()` reports the `S_COMPILE3` of every module: the source language,
the target CPU, and the compiler's own version string.

```python
for c in pdb.compile_info():
    print(c.language_name, c.machine_name, c.compiler, c.module)
    # Rust  Pentium III  clang LLVM (rustc version 1.94.1 ...)  main...rcgu.o
```

The language is the useful part, because it is stated rather than inferred: a
consumer choosing a demangler, or asking whether a binary contains Rust at all,
would otherwise have to guess from the shape of the mangled names. Modules the
linker synthesises carry the record too and report `Link`.

One record per module is the common case, not the rule — an import library
arrives as a single module holding the records of every member, so 145 of
sqlite3 x64's records come from 67 modules.

## Thread-local variables

`__declspec(thread)` and `thread_local` variables are `S_GTHREAD32` /
`S_LTHREAD32` records, and `pdb.thread_locals()` reports them — deliberately
not `data_symbols()`, because the address means something different:

```python
for tl in pdb.thread_locals():
    print(hex(tl.template_rva or 0), tl.name, tl.is_global)
```

An ordinary data symbol's `segment:offset` is where the variable is. A
thread-local's is where its *initial value* is: a slot in the image's TLS
template, which every new thread's private copy is initialised from. The
variable itself lives at an address computed from the TEB at run time and is in
no section of the image, so there is nothing here to report as an `rva`. The
field is called `template_rva` for that reason — pairing one with a
`Function.rva` compares two different address spaces, and it should have to be
done on purpose.

The template address is genuinely useful for reading initial values out of the
image: the four variables in the `tls` fixture initialise to 7, 13, 11 and 17,
and those are the integers the PE holds at the four addresses reported.

`diagnose()` reports `thread_local_records`, so a `data_symbols()` listing that
omits a variable the caller knows is in the binary has an explanation rather
than being silently short.

## Scope

**Supported:** MSF 7.00 container; PDB info stream; DBI stream (module list,
section contributions, publics/symbol-record streams, optional debug header);
CodeView `S_PUB32`, `S_GPROC32`/`S_LPROC32` (and `_ID` variants),
`S_GDATA32`/`S_LDATA32`, `S_PROCREF`/`S_LPROCREF`, `S_CONSTANT`, `S_UDT`,
`S_COMPILE3`, `S_THUNK32`, `S_TRAMPOLINE`, `S_LABEL32`, `S_INLINESITE` with its
binary annotations; section-header table for `segment:offset -> RVA`, with
DBI's Section Map as the fallback when that table is absent; OMAP address
translation for images whose code was moved after linking; the named stream
map, the
`/names` string table and the C13 `DEBUG_S_LINES` / `DEBUG_S_FILECHECKSUMS`
subsections for `rva -> file:line`; the IPI id records that name an inlinee.

`S_GDATA32`/`S_LDATA32`, `S_GTHREAD32`/`S_LTHREAD32`,
`S_PROCREF`/`S_LPROCREF`, `S_CONSTANT`, `S_UDT`,
`S_THUNK32`, `S_TRAMPOLINE`, `S_INLINESITE` with its binary annotations;
section-header table for `segment:offset -> RVA`, with DBI's Section Map as the
fallback when that table is absent; OMAP address translation for images whose
code was moved after linking; the named stream map, the `/names` string table
and the C13 `DEBUG_S_LINES` / `DEBUG_S_FILECHECKSUMS` subsections for `rva ->
file:line`; the IPI id records that name an inlinee.

**Not supported:** TPI type decoding, column info, demangling (names come back
raw). The IPI stream is read only for the names inlined bodies refer to by id;
no type is decoded. `/DEBUG:FASTLINK` PDBs yield publics only, and say so.

Where the section-header stream is missing, addresses are rebuilt from the
Section Map, which records segment sizes but no addresses. `diagnose()` says
when that happened, because the result is a reconstruction — taking the stream
away from each fixture leaves every function at the address it had before, but
it assumes the default `0x1000` section alignment.

## Tests

```bash
.venv/bin/python -m pytest -q
```

```bash
make lint    # ruff, then ty
make fuzz    # malformed input must not escape as an exception
```

Two layers. Synthetic tests build MSF/PDB byte streams with a builder
independent of the reader, so they exercise a real serialise→parse round trip.
Golden tests run against real `link.exe` and `rust-lld` output in `tests/data/`,
32- and 64-bit, and cross-check against the companion PE image — section table,
and the address of every exported function after following its `jmp` thunk. The
PE reader in `tests/_pe.py` is stdlib-only and never consults the PDB, so
agreement is evidence rather than a shared assumption.

A third layer runs outside pytest. `tools/fuzz.py` drives every public entry
point over random, structurally-corrupted and bit-flipped input, and fails if
anything other than `PdbError` escapes -- the contract a caller writes
`except PdbError` against. GitHub Actions runs a short pass on every change
and a longer one nightly with a rotating seed; a failing input is saved and
uploaded as an artefact so it can be replayed.

## Releasing

Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
and [`CHANGELOG.md`](CHANGELOG.md) follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). What the version
number covers is stated at the top of that file: the API in `__all__`, not the
count of symbols a release happens to recover from a given PDB.

To cut a release:

1. Move the `Unreleased` entries under a new `## [x.y.z] - YYYY-MM-DD`
   heading, and update the link definitions at the bottom of the file.
2. Set the same version in `pyproject.toml`.
3. Tag it: `git tag -a vx.y.z -m 'purepdb x.y.z'` and push the tag.

Pushing the tag runs `.github/workflows/release.yml`, which builds the sdist
and wheel, checks their metadata with twine, **fails if the tag and the
packaged version disagree**, runs the suite against what it built, and
attaches the artefacts to the GitHub release for that tag — creating the
release with generated notes if it does not already exist.

Publishing to PyPI stays manual (`make publish`). Automating it needs either a
stored token or a Trusted Publisher configured against the repository, which
is a maintainer decision rather than something a workflow should assume.

`tests/data/` is in the repository but excluded from the sdist and wheel, so
installing purepdb does not pull down 12 MB of binaries. Those tests skip when
the data is absent — clone the repo to run them.

The suite needs no external tool. The cross-check against the reference
implementation therefore lives outside it, in `dev/validate_against_llvm.py`:

```bash
python dev/validate_against_llvm.py                  # tests/data/**/*.pdb
python dev/validate_against_llvm.py path/to/one.pdb   # or a private corpus
```

It compares purepdb against `llvm-pdbutil` **record by record**, not by total:
procedures, publics, labels, constants, UDTs, the section-contribution table
and the module each function is attributed to through it, every `file:line`
entry, and every inlined body with all of its code ranges. It exits non-zero on
any disagreement, printing the records that differ — and equally on a file it
could not open or a corpus with no PDBs in it, because a run that verified
nothing must not report success. It skips with a message when `llvm-pdbutil` is
not installed, so running it is never a requirement. A nightly GitHub Actions
job runs it with `--require-tool`, which turns a missing toolchain into a
failure rather than a silent pass.
