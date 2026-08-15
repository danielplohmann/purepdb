# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Because purepdb is a *parser*, one thing worth stating about what those version
numbers cover: the public API is the surface listed in `purepdb.__all__`. The
numbers a given release extracts from a given PDB are not part of it — recovering
more symbols from the same file is an `Added`, not a breaking change, even though
`len(pdb.functions())` moves. A release that made a previously-resolved address
resolve *differently* would be breaking, and would say so here.

## [Unreleased]

### Added

- A `diagnose()` warning for a BBT-processed PDB that carries the pre-BBT
  section table (Optional Debug Header slot 10) and no section headers (slot 5).
  Symbol RVAs are final, post-BBT addresses, while the only section table left
  to display is the pre-BBT one the map translates out of — two address spaces,
  both looking like RVAs, with nothing previously marking the mismatch.
- `PDB.compile_info()`: the S_COMPILE3 record of every module, naming the source
  language, the target CPU and the compiler's own version string. The language
  field states what a caller otherwise has to infer from the shape of the
  mangled names — a Rust module says `Rust`, and the linker's own contribution
  says `Link`. `purepdb.CompileInfo`.
- `S_LABEL32` decoding: named code addresses inside procedures — assembly
  labels, exception continuation targets, interrupt-return points. `PDB.labels()`,
  `Label`, `codeview.LabelSymbol`, and `Diagnostics.labels`. They are
  deliberately *not* merged into `functions()`, because a label is an address
  within a body that already has an entry point.
- `diagnose()` accounts for every record purepdb drops. `malformed_records`
  now covers each kind with a parser rather than only publics, procs and data;
  `Diagnostics.undecoded_constants` covers a constant whose numeric leaf is one
  purepdb does not decode, which loses the name with the value; and
  `Diagnostics.unplaced_inline_sites` covers a site whose annotations describe
  no code. Each has a warning, so no record can now go missing in silence.
- Thread-local variables: `S_GTHREAD32`/`S_LTHREAD32` are decoded and reported
  by `PDB.thread_locals()`, which is deliberately separate from
  `data_symbols()` rather than part of it. A thread-local's `segment:offset`
  addresses the TLS initialisation template, not the variable — which has no
  address in the image at all — so the field is `template_rva` rather than
  `rva`, and the two are not comparable. `ThreadLocal`, `ThreadLocalSymbol`.
- `Diagnostics.thread_local_records`, and a warning when a file has thread-local
  records — `data_symbols()` deliberately omits them, and a short listing with
  no explanation is the thing `diagnose()` exists to prevent.
- A `tls` fixture: a freestanding x64 PE and PDB carrying both thread-local
  record kinds, with the four template addresses cross-checked against the
  initial values in the image.

### Fixed

- `PDB.info()` rejects a PDB Info stream shorter than the 28-byte header it
  reads, with `MsfError`. The stream's length comes from the file, so it is a
  bound the file can lie about, and nothing checked it: below 12 bytes the
  read leaked `struct.error` out of the public API, and between 12 and 27 it
  did not raise at all — it returned a **short GUID**, which is the more
  serious half, since a truncated GUID is exactly what a caller would key a
  symbol-server lookup on.
- `PDB.info()` refuses a PDB Info stream older than VC70 with
  `UnsupportedPdbError` rather than reporting a GUID. That layout has none:
  the named-stream map begins where the GUID now sits, so the bytes reported
  were the map's own. `llvm-pdbutil` refuses such a file outright.
- `purepdb info` reports both of those instead of ending in a traceback: the
  Info stream is read after the file is opened, so guarding only `PDB.open()`
  left it uncovered.
- `diagnose()` says when the PDB Info stream cannot be read. The named-stream
  map lives in it, so `named_streams()` comes back empty and `/names` cannot
  be found — both silently, until now.
- `PDB.data_symbols()` reports each symbol once. A module's stream and the
  symbol-record stream both describe a file-static symbol, and the globals
  stream repeats a few of its own, so the listing counted 633 records as 633
  symbols on sqlite3 x86 where the file describes 481. A record is dropped
  only when name, segment, offset *and* kind all repeat; the surviving set is
  identical to what `llvm-pdbutil` prints across `dump --symbols` and
  `dump --globals`, deduplicated the same way.

## [0.3.0] - 2026-08-14

### Added

- OMAP address translation, so RVAs match images whose code was moved after
  linking by BBT. `PDB.omap`, `PDB.original_sections`.
- Section Map fallback: when the section-header stream is absent, addresses are
  rebuilt from DBI's Section Map rather than every RVA coming back `None`.
  `PDB.derived_sections`.
- Section contribution attribution — `Function.module` names the `.obj`, library
  member, or `Import:foo.dll` an address came from. `PDB.section_contributions()`,
  `PDB.module_of()`.
- `S_PROCREF`/`S_LPROCREF` decoding: every procedure indexed from one stream.
  `PDB.proc_refs()`, `PDB.resolve_proc_ref()`.
- `S_CONSTANT` and `S_UDT` decoding. `PDB.constants()`, `PDB.udts()`.
- Thunks and trampolines. `PDB.thunks()`, `PDB.trampolines()`; `S_THUNK32`
  records now reach `functions()` with `source="thunk"`.
- Line information: `rva -> file:line` via the `/names` string table and the C13
  subsections. `PDB.lines()`, `PDB.string_table()`, `PDB.named_streams()`.
- Inlined functions from `S_INLINESITE`, with names resolved through the IPI
  stream. `PDB.inline_sites()`, `PDB.id_table()`.
- Truncated and malformed record streams are reported rather than silently
  ending a listing. `Diagnostics.truncations`, `Diagnostics.malformed_records`.
- A 32-bit `rust-lld` fixture, which is what shows the `code_publics` rule is
  not an x86_64 accident.
- `tools/fuzz.py`, which drives every public entry point over malformed input
  and fails if anything but `PdbError` escapes.
- Continuous integration: tests on 3.11–3.14 plus macOS and Windows, ruff, ty,
  an sdist round-trip, and fuzzing on every change and nightly.
- `diagnose()` reports the globals' procedure index (`Diagnostics.proc_refs`)
  and warns when it disagrees with the module walk — the two describe the same
  set, so a disagreement means one is being read incompletely.
- `diagnose()` reports how much C13 line info a PDB carries
  (`Diagnostics.line_bytes`, `has_string_table`) and warns when the data is
  present but `/names` is not, which is the one way `lines()` yields nothing
  from a file that plainly has line info.
- `diagnose()` reports a module list that stopped at a record it could not read
  (`Diagnostics.module_list_stopped_at`), rather than a short list looking like
  a genuinely short one.

### Changed

- The truncation warning distinguishes a stream that abandoned readable bytes
  from one that merely ran out with fewer than four left. Only the first loses
  symbols; the second is padding or a file cut inside a header, and the two are
  indistinguishable. `codeview.Truncation.ragged_tail` carries the difference.
- The Section Map reconstruction now stands down for the original section table
  in slot 10, not only for slot 5. Addresses are unaffected — the resolver
  already preferred the real table — but `diagnose()` no longer reports a
  reconstruction on a file whose addresses came from the file.

- **Requires Python 3.11 or newer.** 3.9 and 3.10 are no longer supported;
  3.9 has been end-of-life since October 2025.
- Development tooling moved from the `dev` extra to a PEP 735 dependency group.
  Install it with `pip install -e . --group dev`, not `pip install -e '.[dev]'`.
- `PDB.to_rva()` is public; it was `_rva`, which is retained as an alias.

### Fixed

- An OMAP table present without the original section table no longer
  double-translates an already-final address into one no symbol occupies.
- A present-but-empty section-header stream is treated as absent, so the Section
  Map fallback runs instead of every RVA silently coming back `None`.
- A malformed stream directory raises `MsfError` instead of leaking
  `struct.error`, and an unterminated module name no longer raises `EOFError`
  out of `PDB.open()`.
- A short IPI record no longer raises `EOFError` out of `PDB.inline_sites()`.
- `Function.module` is populated for thunk-created functions, which previously
  depended on a redundant proc or public happening to share the address.

## [0.2.0] - 2026-08-11

The first release documented here. See the repository history for what it
contained; entries above describe changes made since it.

[Unreleased]: https://github.com/danielplohmann/purepdb/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/danielplohmann/purepdb/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/danielplohmann/purepdb/releases/tag/v0.2.0
