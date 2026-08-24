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

**rust_pe_symbols_i686_no_slot5** — `rustpe32/rust_pe_symbols_i686.pdb` with
Optional Debug Header slot 5 cleared. The companion image is
`rustpe32/rust_pe_symbols_i686.exe`. No toolchain available here emits a PDB
without slot 5 at link time; this is the committed substitute for issue #25.

## Adding to this set

The shapes that once needed a fixture, and the one still open:

* **32-bit rust-lld** — `rustpe32/`, above.
* **No section-header stream** — `rustpe32/rust_pe_symbols_i686_no_slot5.pdb`,
  above, plus the runtime derivation in `test_sectionmap.py` on every other
  fixture.
* **OMAP tables** — still derived, not committed. `test_omap.py` re-serialises
  a real PDB with an address map and an original section table added, so the
  container, the DBI stream and every symbol record are real and only the
  tables are ours. BBT is not publicly available, and a vendor symbol-server
  PDB is not redistributable, so a genuinely BBT-processed file remains the one
  shape no test here has seen. See issue #25: fetching one at test time belongs
  in `dev/`, beside the llvm-pdbutil cross-check, rather than in this directory.

Keep fixtures small, keep them own builds or public-domain sources, and record
the toolchain here — a fixture whose provenance is unclear cannot stay in a
public repository.
