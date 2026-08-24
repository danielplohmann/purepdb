# Groundtruth fixtures

Real compiler output, paired with the image the PDB describes. The pairing is
the point: `tests/_pe.py` reads the image with nothing but `struct` and never
consults the PDB, so when the two agree on a section table or an export address
that agreement is evidence rather than a shared assumption.

These files are in the repository but excluded from the sdist and wheel, so
installing purepdb does not pull down 12 MB of binaries. `test_groundtruth.py`
skips when they are absent.

| fixture | toolchain | what it covers |
|---|---|---|
| `sqlite/x86/sqlite3.{dll,pdb}` | MSVC `link.exe`, VS2019-era, x86 | 3539 procs, 685 publics, 277 exports, cdecl underscore-decorated aliases |
| `sqlite/x64/sqlite3.{dll,pdb}` | MSVC `link.exe`, VS2019-era, x64 | 3522 procs, 660 publics, 277 exports, C++ decorated aliases |
| `rustpe/rust_pe_symbols_msvc.{exe,pdb}` | `rust-lld`, rustc 1.97.1, x64 | 248 procs, 451 publics, EH funclets, and 143 code publics with the function flag *clear* |
| `rustpe32/rust_pe_symbols_i686.{exe,pdb}` | `rust-lld`, rustc 1.94.1, i686 | 2 procs, 5 publics, 13 inline sites, and 4 code publics with the flag clear — the `code_publics` rule at 32 bits |
| `rustpe32/rust_pe_symbols_i686_no_slot5.pdb` | `rustpe32/` with slot 5 cleared | same counts and RVAs as `rustpe32/`; Section Map fallback on a committed file (issue #25) |
| `tls/tls_symbols.{exe,pdb}` | clang + `lld-link` 22.1.8, x64 | 2 `S_GTHREAD32` and 4 `S_LTHREAD32` records — four thread-local variables, two of them counted twice because a static is in both streams; also 2 `S_CONSTANT` and 1 `S_UDT` |
| `syzygy/test_vtables_omap.dll{,.pdb}` | MSVC, then Syzygy `relink`, x86 | 1228 OMAP entries — the only real address map in the corpus; slot 10 absent, so the map is deliberately not applied. Apache-2.0, not our build |

The rustpe fixtures are the ones that pin the `code_publics` rule: `link.exe`
sets `PUBLIC_FLAG_FUNCTION` on every code public, `rust-lld` does not, and
without the executable-section fallback the x64 binary loses 36% of its
functions and the i686 one loses 4 of 6.

What decides the flag turned out not to be the architecture or the linker. It
is the contributing object's COFF symbol type: `rust-lld` sets the flag for
every symbol rustc and clang emit, and leaves it clear for symbols defined in
hand-written assembly, which declares no function type. The x64 fixture's
unflagged publics are all CRT-shim and import symbols for that reason. The
i686 fixture reproduces it deliberately and small enough to read in full —
`stubs.s` beside it is four assembly stubs and nothing else.

## Provenance

All are redistributable. All but one are our own builds or public-domain
sources; `syzygy/` is third-party material under the Apache License 2.0, and
`NOTICE` carries its attribution.

**sqlite3** — built with MSVC from sqlite's own sources, which are public domain.
Image bases `0x10000000` (x86) and `0x180000000` (x64).

**rust_pe_symbols_msvc** — our own build, regenerable from the `main.rs` beside
it. rustc 1.97.1 (`8bab26f4f`, 2026-07-14), release profile, `debuginfo=2`,
`CARGO_INCREMENTAL=0`:

```bash
cargo build --release --target x86_64-pc-windows-msvc
```

Built on Linux: `rust-lld` plus mingw-w64 import libraries and a small
locally-written CRT shim, so no Microsoft-licensed material is involved. **It is
not runnable** — the CRT symbols (`mainCRTStartup`, `__chkstk`, `floor`, …) are
stubs sufficient to link but not to execute. That is deliberate; the file exists
to be parsed and disassembled. The Rust function bodies come from the same
prebuilt std rlibs a Windows-hosted build would link, so the code under test is
representative.

**rust_pe_symbols_i686** — our own build, regenerable with the `build.sh` beside
it. rustc 1.94.1 (`e408947bf`, 2026-03-25), `-O -C debuginfo=2 -C panic=abort`,
linked by `rust-lld` with `/nodefaultlib`. It is `#![no_std] #![no_main]`, so it
links against no CRT and no import library at all, and `stubs.s` is assembled by
clang — no Microsoft-licensed material is involved. **It is not runnable**: the
stubs return constants. It exists to be parsed. `hash_round` and `mix_pair` are
`#[inline(always)]`, which is where its 13 inline sites come from.

**rust_pe_symbols_i686_no_slot5** — `rustpe32/rust_pe_symbols_i686.pdb` with
Optional Debug Header slot 5 cleared. The companion image is
`rustpe32/rust_pe_symbols_i686.exe`. No toolchain available here emits a PDB
without slot 5 at link time; this is the committed substitute for issue #25.

**tls_symbols** — our own build, regenerable with the `build.sh` beside it.
Homebrew clang and `lld-link` 22.1.8, `--target=x86_64-pc-windows-msvc -O1
-gcodeview`, linked `/nodefaultlib /entry:start /subsystem:console`. No Windows
host, no Windows SDK and no CRT are involved: `tls_stubs.c` writes out the four
things the CRT would normally supply for TLS — `_tls_index`, the two `.tls$`
range markers, and the `IMAGE_TLS_DIRECTORY64` that `lld-link` finds by the name
`_tls_used`. **It is not runnable**: `start` returns rather than exiting, and
nothing initialises TLS for a thread. It exists to be parsed.

It is the only fixture here carrying `S_GTHREAD32`/`S_LTHREAD32`, and it covers
three things at once. Both spellings — `__declspec(thread)` and C11
`_Thread_local`, which is what C++ `thread_local` lowers to for a
constant-initialised scalar — produce the same two record kinds. Both linkages
are present, so `is_global` is exercised in each direction. And the two statics
appear in their module's stream *and* in the symbol-record stream, so the file
has six records describing four variables and a listing that does not
deduplicate answers six.

The four variables initialise to 7, 13, 11 and 17, which is what makes the
addresses checkable: `test_threadlocals.py` reads those integers out of the PE
at the four `template_rva` values purepdb reports, through `tests/_pe.py`, which
never opens the PDB.

The enum and the named struct are there for the golden rows rather than for the
thread-local records. A fixture wired into a suite with a count of 0 asserts
nothing — the row passes just as well against an accessor stubbed to return an
empty list — so the file carries two enumerators and one struct tag to make the
`constants()` and `udts()` rows real. The `thunks()` row stays 0 and cannot be
made otherwise: the link is `/nodefaultlib` with no import library, so the image
has an empty import directory and there is no thunk to describe. That row is
kept as a guard against records appearing where the image has none, and says so.

The build runs in `/tmp/build/tls` rather than in place, because a PDB records
the absolute path of everything it was built from — `S_OBJNAME`, `S_ENVBLOCK`
and the `-cc1` line clang stores in `S_COMPILE3` — and a committed fixture
should not carry whoever's home directory. `-ffile-prefix-map` does not cover
`S_OBJNAME`, which is why the directory is moved rather than rewritten.

**test_vtables_omap** — **not our build.** Test data from Google's Syzygy
project, `syzygy/refinery/test_data/`, at upstream commit `8164b24` (the
archived repository's HEAD). Copyright 2014 Google Inc., Apache License 2.0;
see `NOTICE`. Redistributed unmodified.

```
test_vtables_omap.dll      sha256 b220abc2336a49ac391563b5c6a9ca9af81158a0ba7556728df43f3871869b6a
test_vtables_omap.dll.pdb  sha256 1bcc77e7c1829e9b3a607517a49f0125e0f48fa928881a667e1f96f82046b41a
```

It is here because it is the only file in the corpus carrying a real OMAP
table — 1228 entries, from Syzygy's `relink`, which is the one open-source
tool that writes one. Every other OMAP test builds the table itself.

**Its PDB and its image describe different layouts, and that is the point.**
The PDB is what the linker wrote; the image is what `relink` shipped after
instrumenting it. So the image has six sections to the PDB's five — it gained
`.syzygy` — and `.data` moved from `0x11000` to `0x13000`, `.rsrc` from
`0x14000` to `0x19000`. Slot 10 is absent, so purepdb does not apply the map
and says so in a warning; the RVAs it reports are pre-instrumentation
addresses. That makes this a real instance of the divergence issue #39
describes, in the map-without-slot-10 variant.

Two consequences for tests. The PE oracle cannot be pointed at it — the
section tables are *expected* to disagree, so it is in neither `CASES` nor
`NO_SECTION_HEADER_CASES` in `test_groundtruth.py`. And two of its publics,
`_IsProcessorFeaturePresent@4` and `_RtlUnwind@16`, resolve to `0xb18a` and
`0xb190`, inside the PDB's `.text` (which ends at `0xb196`) and past the
shipped one (which ends at `0xb157`). They are not errors; they are addresses
in a layout the image no longer has.

It still does **not** close the slot-10 gap — see below.

## Adding to this set

The shapes that once needed a fixture, and the one still open:

* **32-bit rust-lld** — `rustpe32/`, above.
* **No section-header stream** — `rustpe32/rust_pe_symbols_i686_no_slot5.pdb`,
  above, plus the runtime derivation in `test_sectionmap.py` on every other
  fixture.
* **OMAP tables** — a real one is committed: `syzygy/`, 1228 entries, above.
  What that does not reach is the slot-10 branch, so `test_omap.py` also
  re-serialises
  a real PDB with an address map and an original section table added, so the
  container, the DBI stream and every symbol record are real and only the
  tables are ours. A genuinely BBT-processed file remains the one shape no test
  here has seen; the section below records why, and issue #25 tracks it.
  Fetching one at test time is a possibility, but it belongs in `dev/` beside
  the llvm-pdbutil cross-check rather than in this directory — the suite is
  hermetic and `README.md` says so.

### On finding a slot-10 fixture

Recorded so the next person does not repeat the search. Two questions, and
running them together is what makes this look easier than it is: whether such
a file can be **obtained**, and whether it can be **committed here**.

Obtaining one is not the problem. Microsoft's symbol server serves
BBT-processed PDBs that carry slot 10 — an XP-era `ntdll.pdb` has 37118 OMAP
entries and an original section table, and purepdb reads it today. Committing
one is the problem, and note *which* problem: not that it is someone else's
build, since `syzygy/` is too, but that its licence does not permit
redistribution at all. Apache-2.0 material can be carried here with
attribution; proprietary vendor symbols cannot be carried on any terms.

That leaves producing one, and this is where it was taken as far as it goes.
The only open-source tool that writes OMAP is Google's Syzygy `relink`
(<https://github.com/google/syzygy>) — archived, Apache 2.0, with relinked
output committed in its own tree. That output *is* redistributable, and it is
now in this corpus as `syzygy/`, above.

It does not close the gap, because Syzygy writes slots 3 and 4 and never slot
10. Confirmed on the committed file: 1228 OMAP entries, no original section
table, no malformed records, no truncations. So it is a real test of OMAP
*parsing* and of the map-without-slot-10 warning, and no test at all of the
slot-10 branch — the one that changes an address.

**The slot-10 branch therefore stays synthetic here**, and nothing public
appears to write slot 10.

It is no longer unverified, though. `dev/validate_omap_against_windows.py`
checks purepdb's translation against Windows system binaries the developer
already has, fetching the matching PDBs from Microsoft's symbol server into an
untracked cache — so nothing is redistributed and nothing needs committing. The
oracle is the export table, which the linker wrote in the shipped image's own
address space and which owes nothing to the PDB.

Six pairs from a Windows XP and a Windows 7 installation, all six carrying
slot 10:

| pair | omap | exports compared | exact | via one thunk | near | far |
|---|---:|---:|---:|---:|---:|---:|
| winxp ntdll | 37061 | 1294 | 1292 | 0 | 1 | 1 |
| winxp kernel32 | 42229 | 915 | 910 | 0 | 2 | 3 |
| win7-x86 ntdll | 67696 | 2000 | 1994 | 4 | 1 | 1 |
| win7-x86 kernel32 | 60037 | 1273 | 851 | 7 | 233 | 182 |
| win7-x64 ntdll | 84434 | 1961 | 1961 | 0 | 0 | 0 |
| win7-x64 kernel32 | 70894 | 1287 | 870 | 139 | 166 | 112 |

`ntdll` agrees on 99.8% to 100% of its exports on all three targets, and **0 of
8730 exports match the untranslated address** — which is the counterfactual
that gives the rest its meaning. kernel32's residue is not disagreement about
addresses but about which address a name belongs to: Win7 exports it through
stubs, and the offsets cluster hard (146 at exactly +8 on x64, 175 at exactly
+13 on x86). A wrong translation does not produce the same delta 175 times.

Two things that fell out of running it. **Win7 is still BBT-processed** — the
era was an open question, and all six of its PDBs carry slot 10. And x86
publics are stdcall-decorated where exports are not, so the comparison has to
undecorate `_NtCreateFile@44` before the two sets intersect at all; without
that step the check silently compares almost nothing, which is the failure mode
it now guards against.

Keep fixtures small, and record the toolchain here — a fixture whose
provenance is unclear cannot stay in a public repository.

Prefer our own builds or public-domain sources. Third-party material is
acceptable only when its licence permits redistribution, and then only with
the licence named in this file, the attribution in `NOTICE`, and a recorded
hash: `syzygy/` is the one such fixture. A licence that does not permit
redistribution rules a file out however much it would demonstrate — a PDB from
a vendor symbol server is the case that keeps coming up, and the answer is no.
