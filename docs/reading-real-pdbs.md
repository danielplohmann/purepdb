# Reading real PDBs

The format is documented. What real files *do* is not, and that is where the
time goes.

[LLVM's PDB documentation][llvm] covers the container and the streams well, and
`cvinfo.h` in [microsoft/microsoft-pdb][mspdb] is authoritative on record
layouts. Neither tells you that a field is unreliable across linkers, or that
the same symbol is described twice by two streams, or that a listing coming back
empty is the normal failure mode rather than a bug.

These are notes on that second category, accumulated while writing purepdb.
Every claim is measured against a file in [`tests/data/`](../tests/data/README.md),
so each one can be re-checked rather than believed.

## The publics stream holds no public symbols

DBI names two streams that look like symbol containers and are not:
`PublicStreamIndex` and `GlobalStreamIndex`. Both hold a **hash table** whose
entries are byte offsets into a third stream, `SymRecordStreamIndex`, which is
where the records actually live.

Scanning the publics stream for `S_PUB32` therefore finds **nothing at all** —
no exception, no partial result, just an empty list. That was purepdb's bug
until 0.2.0, and it returned zero publics on every real PDB while every test
passed.

The publics stream is still worth reading, for exactly one thing: its address
map, which gives the records an address-sorted ordering.

## The function flag is not reliable across linkers

`S_PUB32` carries `PUBLIC_FLAG_FUNCTION`. It cannot be trusted alone.

`link.exe` sets it on every code public. `rust-lld` does not. On the x64 Rust
fixture, 451 publics resolve into an executable section 285 times but only
**142 carry the flag**. Filtering on the flag drops `mainCRTStartup` and
`__chkstk`, and takes `functions()` from 399 entries to 256 — a loss of 36%.

So a public also counts as a function when it resolves into an executable
section, and `functions(code_publics=False)` exists for a caller who wants the
strict reading.

What decides the flag turns out to be neither the architecture nor the linker:
it is the **contributing object's COFF symbol type**. `rust-lld` sets it for
symbols that rustc and clang emit, and leaves it clear for symbols defined in
hand-written assembly, which declares no function type. The x64 fixture's
unflagged publics are all CRT-shim and import symbols for that reason.

## The same symbol is described twice

A module's own stream holds the symbols defined in it. The symbol-record stream
holds the set the globals hash indexes. A file-static symbol is in **both** — one
symbol described twice, not two symbols.

On sqlite3 x86, `data_symbols()` sees 633 records describing 481 symbols:

| source | records | distinct |
| --- | ---: | ---: |
| module streams | 438 | 438 |
| symbol-record stream | 195 | 188 |
| in both | — | 145 |
| **total** | **633** | **481** |

Note the second row. The globals stream repeats **six of its own** symbols, so
deduplicating only *across* the two streams still reports a symbol twice.

Deduplication has to key on name, segment, offset **and** record kind. Anything
less collapses symbols that are genuinely distinct — one `static int counter;`
per translation unit is the ordinary case — and a wrong answer is worse than an
untidy one.

## One address, several correct names

Linkers fold identical function bodies: MSVC's `/OPT:ICF`, and `rust-lld` by
default. So one entry point legitimately carries several names, and a parser
that keeps only one is discarding correct information.

On sqlite3 x86 that is **438 of 3620** functions, worst case four names. On the
x64 Rust fixture, 124 of 399.

A related trap: a *name* is not an identity. In the x64 Rust fixture
`core::fmt::impl$82::fmt<str$>` is **two different bodies at two addresses**.
Any join between two views of a PDB has to key on `(segment, offset)`, not on
the name — keying on the name silently compares one body against the other,
which is a mistake this project made and caught in a test that passed for the
wrong reason.

## Names come back as the file stores them

Decorated, mangled, or empty. Two consequences worth planning for:

**x86 publics are stdcall-decorated where exports are not.** `_NtCreateFile@44`
against `NtCreateFile`. Any comparison between a PDB's names and an image's
export table has to undecorate first, and has to assert how many names it
compared — otherwise it passes by comparing almost none. See
[`omap.md`](omap.md#one-trap-that-makes-the-check-pass-while-comparing-nothing).

**A name can hold anything**, including spaces and control characters.
`std::rt::lang_start::closure$0<tuple$<> >` is one name. Any line-oriented
output has to put the name last and escape what it prints, or a name with a
newline puts one record on two lines.

## Inlined bodies outnumber entry points

An inlined function has no entry point, so it has no procedure record and no
public. `functions()` cannot see it by construction — not as a limitation, but
because there is no address for it to have.

On the x64 Rust fixture that is **3797 inline sites against 248 procedure
records**: fifteen inlined bodies for every function with an entry point. In
Rust and modern C++ this is where most of the code goes, and a tool that reports
only entry points is describing a small fraction of what ran.

`S_INLINESITE` gives the ranges a body occupies inside its caller, and the name
comes from the IPI stream by item id.

## Some addresses are not variable addresses

Thread-local storage is the sharpest case. `S_GTHREAD32`/`S_LTHREAD32` carry a
`segment:offset` that looks like every other symbol's, and it addresses the
**TLS initialisation template** — the bytes each new thread's private copy starts
from. The variable itself lives at an address computed from the TEB at run time
and is in no section of the image at all.

So the number is a real RVA that is not comparable to a function's. purepdb
calls the field `template_rva` rather than `rva` for that reason: a caller
pairing one with a `Function.rva` has to type a different name, which is a
stronger guard than a docstring.

It is still worth having. Reading the initial values out of the image is exactly
what it is good for — the `tls/` fixture's four variables initialise to 7, 13, 11
and 17, and those are the bytes at those addresses.

## An address that will not resolve is often correct

`segment:offset` does not always name a section, and this is not an error:

- **Segment 0** is used for absolute symbols.
- **Segment `len(sections) + 1`** carries Control Flow Guard load-config
  metadata — `__guard_fids_table`, `__guard_flags`, `__safe_se_handler_count`.
  MSVC emits a handful per image. None are function-flagged.

A parser that "fixes" these into numbers is inventing addresses.

## When the section table is missing, addresses are a reconstruction

When the section-header stream (slot 5) is absent, DBI's Section Map describes
the same segments — but records **no addresses**. Every entry's `Offset` is 0 in
everything `link.exe` and `rust-lld` emit.

The layout has to be rebuilt by laying segments out the way the linker did, each
starting at the next multiple of the image's section alignment. The PDB does not
record that alignment anywhere, so the reconstruction assumes the PE default of
`0x1000`.

It works — clearing slot 5 in a byte copy of each fixture leaves every function
at the address it had before. But it is a reconstruction, not a reading, and a
consumer deserves to know which it got. `diagnose()` reports it.

## Empty is the normal failure mode

This is the one that shapes everything else. Almost every way a PDB can defeat
this parser produces an **empty result or a `None` address**, not an exception:

- `/DEBUG:FASTLINK` PDBs carry **no procedure records at all**. Publics still
  work. A caller reading `functions()` sees a short list and no reason.
- A compiler-intermediate `vc140.pdb` has an empty DBI stream — types, no
  symbols.
- A managed (.NET) PDB describes methods keyed by metadata token, with no
  `segment:offset` to resolve. A .NET *Portable* PDB is not even an MSF
  container.
- A truncated record stream simply stops, and the symbols past it are absent.

A parser sweeping a directory must not hand the caller a traceback for any of
these, which means the information about *why* has to go somewhere else.
purepdb's answer is `diagnose()`, which reports counts and a list of prose
warnings — and the rule that follows from it is that **a code path which can
silently yield nothing needs a matching diagnostic**, or the parser has a gap
with no way to see it.

## The producer will tell you what it is

`S_COMPILE3` states the source language, the target CPU and the compiler's own
version string, per module. That is worth knowing because the alternative is
guessing from the shape of the mangled names — a consumer choosing a demangler,
or asking whether a binary contains Rust at all, can simply read it.

One counterintuitive detail: **one record per module is the common case, not the
rule**. An import library arrives as a single DBI module carrying the records of
every member `.obj` in it. On sqlite3 x64, `Import:ucrtbased.dll` alone holds 25
of them, and 145 records come from 67 modules.

## References

- [LLVM PDB documentation][llvm] — the container and the streams
- [microsoft/microsoft-pdb][mspdb] — `cvinfo.h`, the record layouts
- [`tests/data/README.md`](../tests/data/README.md) — the fixtures every number
  above was measured on
- [`omap.md`](omap.md) — the one place a missing stream gives wrong answers
- [`validating.md`](validating.md) — how these claims were checked

[llvm]: https://llvm.org/docs/PDB/
[mspdb]: https://github.com/microsoft/microsoft-pdb
