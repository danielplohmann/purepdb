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

The rustpe fixture is the one that pins the `code_publics` rule: `link.exe` sets
`PUBLIC_FLAG_FUNCTION` on every code public, `rust-lld` does not, and without
the executable-section fallback this binary loses 36% of its functions.

## Provenance

Both are redistributable and neither is third-party licensed material.

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

## Adding to this set

Two shapes are still unrepresented and would be worth having, both as own
builds: a **32-bit rust-lld** PDB, and a PDB with **no section-header stream**
(Optional Debug Header slot 5 absent), which is the one documented path to
`Function.rva is None` that no fixture has yet exercised.

Keep fixtures small, keep them own builds or public-domain sources, and record
the toolchain here — a fixture whose provenance is unclear cannot stay in a
public repository.
