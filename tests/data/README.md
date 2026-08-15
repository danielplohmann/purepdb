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
| `tls/tls_symbols.{exe,pdb}` | clang + `lld-link` 22.1.8, x64 | 2 `S_GTHREAD32` and 4 `S_LTHREAD32` records — four thread-local variables, two of them counted twice because a static is in both streams |

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

All are redistributable and none is third-party licensed material.

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

The build runs in `/tmp/build/tls` rather than in place, because a PDB records
the absolute path of everything it was built from — `S_OBJNAME`, `S_ENVBLOCK`
and the `-cc1` line clang stores in `S_COMPILE3` — and a committed fixture
should not carry whoever's home directory. `-ffile-prefix-map` does not cover
`S_OBJNAME`, which is why the directory is moved rather than rewritten.

## Adding to this set

The shapes that once needed a fixture are now covered, two of them without one:

* **32-bit rust-lld** — `rustpe32/`, above.
* **No section-header stream** — covered by deriving it. `test_sectionmap.py`
  clears Optional Debug Header slot 5 in a byte copy of each real PDB and
  requires every function to come back at the address it had before, resolved
  from the DBI Section Map instead. A PDB a toolchain genuinely emitted that
  way would still be worth having, to confirm such files look like these.
* **OMAP tables** — likewise derived. `test_omap.py` re-serialises a real PDB
  with an address map and an original section table added, so the container,
  the DBI stream and every symbol record are real and only the tables are
  ours. BBT is not publicly available, so a genuinely BBT-processed PDB from a
  vendor symbol server remains the one shape no test here has seen.

Keep fixtures small, keep them own builds or public-domain sources, and record
the toolchain here — a fixture whose provenance is unclear cannot stay in a
public repository.
