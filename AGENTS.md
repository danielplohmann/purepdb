# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. Read this
before making changes.

## Project Overview

purepdb is a **minimal, dependency-free pure-Python parser for Microsoft PDB
debug-info files**. It is purpose-built to answer one question well: *what are
the functions in this binary, and where are their entry points?*

It is deliberately **not** a reimplementation of `llvm-pdbutil`. It is a thin
vertical slice through the same format stack — MSF container, PDB info stream,
DBI, the symbol-record stream, CodeView records — written from the published
format documentation.

Key entry point: `purepdb.PDB` (`PDB.open(path)` / `PDB.from_bytes(data)`).

Three properties define the project and constrain almost every change:

1. **Zero runtime dependencies.** Stdlib only (`struct`, `bisect`, `pathlib`,
   `dataclasses`). This is the whole reason the project exists — see the *Prior
   art* section of [`NOTICE`](NOTICE), where every alternative is rejected for
   requiring a native toolchain or a dependency chain that breaks. Adding a
   runtime dependency would remove the project's reason to exist.
2. **Failure is an empty result, not an exception.** Every failure mode this
   parser has on real files yields an empty list or a `None` RVA. That is
   intentional — a caller sweeping a directory of binaries must not get a
   traceback — and it is why `PDB.diagnose()` exists to tell the cases apart.
3. **`PdbError` is the only exception a caller must handle.** Nothing else may
   cross the public boundary. `tools/fuzz.py` enforces this.

## Repository Layout

```
purepdb/            # the package (stdlib only, no runtime deps)
  msf.py            #   MSF 7.00 container: superblock, stream directory, PdbError/MsfError
  reader.py         #   tiny cursor-based little-endian reader used by every parser
  pdb.py            #   high-level API: PDB, Function, Line, InlineFunction, Diagnostics
  dbi.py            #   DBI stream (index 3): modules, section contributions, dbg header
  gsi.py            #   publics/globals hash streams (which hold NO records — see Gotchas)
  codeview.py       #   CodeView symbol records (S_PUB32, S_*PROC32, S_LABEL32,
                    #   S_COMPILE3, S_*THREAD32, S_THUNK32, S_INLINESITE, …)
  sections.py       #   IMAGE_SECTION_HEADER table + DBI Section Map fallback -> RVA
  omap.py           #   OMAP address translation for BBT-processed images
  names.py          #   named stream map + the `/names` string table
  c13.py            #   C13 subsections: DEBUG_S_LINES / DEBUG_S_FILECHECKSUMS
  ipi.py            #   IPI stream (index 4), read only for the names inlinees refer to by id
  __main__.py       #   CLI: 15 subcommands, dispatched from one table
docs/               # write-ups; every figure in them is measured (see below)
tests/              # pytest suite
  _synth.py         #   MSF/PDB byte-stream builders, independent of the reader
  _pe.py            #   stdlib-only PE reader; never consults the PDB (that is the point)
  _relink.py        #   moves code in a fixture and writes the OMAP that says so
  data/             #   groundtruth fixtures — in the repo, excluded from sdist/wheel
tools/fuzz.py       # the parse-boundary fuzzer; runs outside pytest
tools/relink_omap.py  # CLI over tests/_relink.py
dev/                # scratch, EXCEPT two validate_* scripts (see below)
.github/workflows/  # ci.yml, fuzz.yml, release.yml, validate.yml
```

`dev/` is a scratch directory with two tracked exceptions: `.gitignore` holds
`dev/*` plus a negation for `validate_against_llvm.py` and
`validate_omap_against_windows.py`, because a CI job has to be able to run the
first and the second is a documented check.

**Nothing else in `dev/` may be committed, and that matters here.**
`validate_omap_against_windows.py` caches PDBs fetched from Microsoft's symbol
server into `dev/symbols/`, which are not redistributable. The `dev/*` pattern
is what keeps them out of the repository; do not weaken it. Anything else you drop in `dev/` is ignored — which has
surprised people, so check `git status` rather than assuming a new file there
is staged. The directory is still excluded from the sdist.

`docs/` holds three documents whose claims are all measured against committed
fixtures: `omap.md`, `reading-real-pdbs.md` and `validating.md`. **A change that
moves a number they cite has to update them in the same commit** — a measured
figure that has quietly stopped being true is worse than no figure, and these
are the project's public claims. `docs/README.md` says what the numbers are
scoped to.

## Environment Setup

**No virtualenv is committed**, and the system interpreter is
`EXTERNALLY-MANAGED`, so create one first. The `README` and `.gitignore` both
assume it lives at `.venv/`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip     # --group needs pip 25.1+
.venv/bin/python -m pip install --group dev -e .
```

With uv, the equivalent is `uv sync --group dev`.

Development tooling is a **PEP 735 dependency group, not an extra** — an extra
is part of a package's public interface, which a test runner and a linter are
not. Use `--group dev`; `pip install -e '.[dev]'` does not work and has not
since 0.3.0.

The pinned tool versions in `[dependency-groups]` are the single source of
truth: the Makefile, CI and the release job all resolve them from there. Do not
add a second copy of a tool version anywhere.

## Commands

The `Makefile` takes `PYTHON` as a variable, so point it at the venv (or
activate it first and drop the override):

| Task | Command |
| ---- | ------- |
| Tests | `make test PYTHON=.venv/bin/python` (or `.venv/bin/python -m pytest -q`) |
| Lint + type check | `make lint PYTHON=.venv/bin/python` (`ruff check .` then `ty check`) |
| Fuzz (quick pass) | `make fuzz PYTHON=.venv/bin/python` (2000 inputs, seed 0) |
| Build sdist + wheel | `make package PYTHON=.venv/bin/python` |
| Publish (manual only) | `make publish` / `make publish-test` |
| CLI | `.venv/bin/purepdb <command> <file.pdb>` — `purepdb --help` lists all 15 |
| llvm cross-check | `.venv/bin/python dev/validate_against_llvm.py` (needs `llvm-pdbutil`; skips cleanly without it) |
| OMAP vs Windows | `.venv/bin/python dev/validate_omap_against_windows.py <dll-dir> --fetch` (needs Windows DLLs and network; nothing is redistributed) |

Expected state on a clean tree: **581 tests pass**, `ruff check` and `ty check`
both clean, and the fuzzer reports no escaped exception. Run tests, lint *and*
a quick fuzz pass before considering work complete.

## The Format Stack

Reading a PDB is a chain of indirections, and most bugs in this parser have
been *following the wrong link in the chain*. The order is:

1. **MSF container** (`msf.py`) — a block-based file system. The SuperBlock's
   `BlockMapAddr` points at a block of block indices; those blocks concatenated
   form the **stream directory**, which describes every stream. Only MSF 7.00
   ("big" MSF) is supported; MSF 2.00 and .NET Portable PDBs are recognised
   solely to name them in the error.
2. **Fixed stream indices** — 1 = PDB Info, 2 = TPI, 3 = DBI, 4 = IPI.
3. **DBI stream** (`dbi.py`) — the index of everything else: the module list
   (each with its own symbol substream), the Section Contribution substream,
   the Section Map, and the **Optional Debug Header**, whose slots name further
   streams (3 = OmapToSrc, 4 = OmapFromSrc, 5 = section headers, 10 = original
   section headers).
4. **Symbol records** (`codeview.py`) — length-prefixed `uint16 len; uint16
   kind; payload`. Unknown kinds are skipped by length so the stream stays in
   sync. Procedure records live in *module* substreams; publics live in the
   **symbol-record stream** named by DBI.
5. **Address resolution** (`sections.py`, `omap.py`) — records store a 1-based
   `segment` plus an `offset`. `rva = section[segment-1].virtual_address +
   offset`, from the slot-5 section-header table, falling back to a
   reconstruction from the Section Map, then optionally translated through OMAP.

`PDB.functions()` merges three sources, keyed by `(segment, offset)`: module
proc records (rich — they carry code size), publics (broad — CRT stubs and
folded entries with no proc record), and `S_THUNK32` records. Where several
describe one address, precedence for the `name` slot is **proc, then public,
then thunk**, and every other name lands in `aliases` rather than being
dropped, because folded bodies genuinely have several correct names.

## Key Concepts

- **MSF** — the block-based container a PDB file actually is.
- **Stream** — a logical byte range inside the MSF, stored as a list of
  possibly non-contiguous blocks.
- **segment:offset** — how every symbol stores its address. 1-based segment
  index into the section table plus a byte offset. Resolving it to an RVA is
  this parser's central job.
- **RVA** — image-relative virtual address. purepdb never adds the PE image
  base; callers do that themselves.
- **Proc record** — `S_GPROC32`/`S_LPROC32` (and `_ID` variants), in a module
  substream. Carries a name, `segment:offset` and a code size.
- **Public** — `S_PUB32`, in the symbol-record stream. Broad coverage, no code
  size, and a function flag that is **not reliable across linkers**.
- **Thunk / trampoline** — `S_THUNK32` is a *named* jump stub and reaches
  `functions()` with `source="thunk"`. `S_TRAMPOLINE` (incremental-link) carries
  no name, so it is reported separately by `PDB.trampolines()`.
- **Inline site** — `S_INLINESITE`. An inlined body has no entry point, so by
  construction it cannot appear in `functions()`; `PDB.inline_sites()` reports
  it with the code ranges it occupies inside its caller. Its name comes from the
  IPI stream by item id.
- **OMAP** — the two translation tables BBT appends when it moves code *after*
  the linker wrote the PDB. The one case where ignoring a stream yields **wrong
  numbers rather than missing ones**.
- **`/names`** — the global string table. Without it, line-table file-name
  offsets cannot be resolved and `lines()` yields nothing.
- **Label** — `S_LABEL32`. A named code address *inside* a procedure. Not an
  entry point, so like a trampoline it stays out of `functions()`.
- **Thread-local** — `S_GTHREAD32`/`S_LTHREAD32`, via `thread_locals()`. Its
  address field is called `template_rva`, not `rva`, and the distinction is
  load-bearing: see Gotchas.
- **Compile info** — `S_COMPILE3`, via `compile_info()`. States the source
  language rather than leaving a caller to infer it from mangled-name shape.
  One record per module is the common case, not the rule.
- **Diagnostics** — the report from `PDB.diagnose()` explaining *why* a listing
  came back the size it did, plus a `warnings` list of prose sentences.

## Code Conventions

- **Linter:** Ruff. `line-length = 100`, `target-version = "py311"`. Selected
  rules: `E, W, F, I, UP, B, C4, SIM, PIE, RUF`.
- **Do not run `ruff format`.** See Gotchas — this project does not use the
  formatter, and running it would rewrite 28 of 37 files.
- **Supported Python:** 3.11+ (`requires-python = ">=3.11"`). CI tests
  3.11–3.14 on Linux plus 3.11 on macOS and Windows.
- **Typing:** the package is fully typed and ships `py.typed`. `ty` checks it
  strictly; `[tool.ty.rules]` is deliberately empty so any future exemption has
  to be written down with a reason rather than passed as a CI flag.
- **Comments are prose, and they carry the *why*.** This codebase's comments
  explain format quirks, cite the documentation a structure came from, and
  record decisions with their rationale. That density is deliberate — match it.
  Prose comments wrap at 79 columns; the 100-column limit exists for format
  tables and `struct` definitions.
- **Every module docstring cites the format documentation it was written
  from.** A new module must do the same (see *Provenance* below).
- **`struct.Struct` definitions are field-annotated and size-asserted** (e.g.
  `assert _SECTION_HEADER.size == 40`). Keep that pattern.
- License: BSD-3-Clause.

## Testing

Three layers, each proving something the others cannot:

1. **Synthetic** — `tests/_synth.py` builds MSF/PDB byte streams with a builder
   **deliberately independent of the reader**, so the tests exercise a real
   serialise→parse round trip rather than a shared bug. Never rewrite these
   builders to use the parser's own code.
2. **Groundtruth** — `tests/test_groundtruth.py` runs against real `link.exe`
   and `rust-lld` output in `tests/data/`, 32- and 64-bit, and cross-checks
   against the companion PE image: the section table, and the address of every
   exported function after following its `jmp` thunk. **`tests/_pe.py` is
   stdlib-only and must never import or consult purepdb** — that independence
   is what makes agreement evidence rather than a shared assumption.
3. **Fuzzing** — `tools/fuzz.py`, outside pytest. It drives every public entry
   point over random, structurally-corrupted and bit-flipped input and fails if
   anything other than `PdbError`/`MsfError`/`RecursionError` escapes, or if a
   single input takes longer than 10 seconds. CI runs a short pass on every
   change and a longer nightly one with a rotating seed; a failing input is
   saved and uploaded as an artefact so it can be replayed.

Add or update tests for behavioural changes, matching the existing `test_*.py`
naming. `pytest` is configured with `filterwarnings = ["error"]`, so a warning
is a test failure — that is intentional for a project that ships no
dependencies to blame.

## Versioning & Releases

Semantic Versioning, with [`CHANGELOG.md`](CHANGELOG.md) in Keep a Changelog
format. **What the version covers is the API listed in `purepdb.__all__`** —
not the count of symbols a release happens to recover from a given PDB.
Recovering *more* symbols is an `Added`, even though `len(pdb.functions())`
moves; making a previously-resolved address resolve *differently* is breaking.

The version lives in **two** places that nothing else ties together:
`pyproject.toml` `[project].version` and `purepdb/__init__.__version__`.
`tests/test_version.py` asserts they agree. Bump both in one commit, or not at
all.

To cut a release (maintainer action — do not do this unprompted):

1. Move the `Unreleased` entries under a new `## [x.y.z] - YYYY-MM-DD` heading
   and update the link definitions at the bottom of the file.
2. Set the same version in `pyproject.toml` *and* `purepdb/__init__.py`.
3. `git tag -a vx.y.z -m 'purepdb x.y.z'` and push the tag.

Pushing the tag runs `release.yml`, which builds the artefacts, checks metadata
with twine, **fails if the tag and the packaged version disagree**, runs the
suite against what it built, and attaches the artefacts to the GitHub release.
Publishing to PyPI stays manual (`make publish`) — automating it needs a stored
token or a Trusted Publisher, which is a maintainer decision.

## Git Workflow

- Work on a **feature branch** and open a **PR** against `main`. Do not commit
  directly to `main`.
- **Never** run `git commit`, `git push`, or open a PR unless explicitly asked.
- Commit messages: lowercase, imperative, and they say *what changed and why*
  rather than naming the file — e.g. `resolve rva to file:line via /names and
  the C13 subsections`, `harden the parse boundary, and add the fuzzer that
  found the holes`. A colon-and-clause form is common for the larger ones.
  Automated bumps use `deps:` / `ci:` prefixes (dependabot config).
- PR titles are **not** CI-enforced here; there is no semantic-title workflow.
  Descriptive prose in the same voice as the commit messages is the convention.
- Update `CHANGELOG.md` under `## [Unreleased]` for any user-visible change.
- **Never write `#<number>` after a closing keyword, even to negate it.** GitHub
  reads `close #25` as an instruction and ignores the `does not` in front of it,
  so a commit message saying a change *does not* close an issue closes it on
  push. This has happened twice here, to the same issue. Write "issue 25" in
  prose when the sentence is about not closing something; a bare `#25` elsewhere
  in the message is fine and only links.
- Never commit secrets or keys. Do not force-push shared branches.

## Gotchas

Constraints an agent must respect to avoid breaking purepdb or its consumers.

### `ruff format` is not part of this project
`make lint` and CI run **`ruff check` and `ty check` only**. There is no
`ruff format --check` step anywhere, and the source is not formatter-clean:
running `ruff format .` reformats 28 of 37 files and produces an enormous
diff of unrelated churn. This is the opposite of the sibling `smda` repository,
so do not carry that habit across. Fix lint findings by hand.

### The publics stream holds no symbol records
DBI's `PublicStreamIndex` and `GlobalStreamIndex` name **hash** streams whose
entries are byte offsets into the symbol-record stream — they contain no
`S_PUB32` records at all. Scanning them for records returns nothing, silently,
with no exception. That was the bug that prompted 0.2.0. `PDB.public_symbols()`
reads the symbol-record stream and uses the publics stream only for the address
map that supplies address ordering. `gsi.py`'s docstring exists to prevent a
regression here; read it before touching anything in that area.

### The public function flag is unreliable — the fallback is not redundant
`link.exe` sets `PUBLIC_FLAG_FUNCTION` on every code public (all 438 of sqlite3
x86's). `rust-lld` leaves it clear on 143 of 280, including `mainCRTStartup`
and `__chkstk`. So a public also counts as a function when it resolves into an
**executable section**, which is worth 36% of the functions in the x64 Rust
fixture and 4 of 6 in the i686 one.

What decides the flag is neither the architecture nor the linker: it is the
contributing object's COFF symbol type. `rust-lld` sets it for symbols rustc
and clang emit and leaves it clear for symbols defined in hand-written
assembly, which declares no function type. Do not "simplify" `functions()` back
to a flag-only test. `code_publics=False` is the escape hatch for a caller who
wants the strict behaviour, and `public_symbols()` is unfiltered either way, so
`is_function` still means exactly what the record says.

### Empty results are the contract, so new parse paths need diagnostics
A stream this parser cannot read must produce an empty result, and
`Diagnostics` must be able to say why. A code path that can silently yield
nothing without a corresponding field and `warnings` sentence is incomplete —
that gap is precisely what `diagnose()` was built to close, and the
`Diagnostics.warnings` property is where the prose explanation belongs.

### `PdbError` is the whole exception surface
No `struct.error`, `IndexError`, `EOFError` or `KeyError` may escape a public
entry point, ever. `Reader` raises `EOFError` internally; it is the caller's job
to catch it and turn it into an empty result or a `PdbError`.

**When you add a public entry point, add it to `exercise()` in
`tools/fuzz.py`** — and note that the results there are collected rather than
discarded on purpose, because `lines()` is a generator and never consuming it
would leave the C13 walker untested.

### Pinned counts in the groundtruth tests are golden baselines
`tests/test_groundtruth.py` asserts exact numbers (procs, publics, functions,
aliases, sections) per fixture, because a parser reading the wrong stream
returns an empty list rather than raising — the numbers themselves are the
check. A change that moves them may well be correct, but it must be
**deliberate**: update the `CASES` table, say why in the PR, and record it in
`CHANGELOG.md` (a higher count is `Added`, not a fix).

### An RVA of `None` is often correct, not a bug
`to_rva()` returns `None` for segment 0 (absolute symbols) and for
segment `len(sections) + 1`, which carries Control Flow Guard load-config
metadata (`__guard_fids_table`, `__guard_flags`, `__safe_se_handler_count`).
MSVC emits a handful per image, none function-flagged. Do not "fix" these into
addresses.

### OMAP is the one place a missing stream gives wrong answers
Everywhere else, an unread stream costs coverage. With OMAP, a `segment:offset`
resolved against the section table names an address in the *pre-optimisation*
layout, which in the shipped image is some unrelated instruction. The two
halves must be present together — an address map without the original section
table in slot 10 must **not** be applied (it would double-translate an
already-final address), and an original section table without the map means
every RVA is in the wrong address space. `diagnose()` warns for both. BBT is
not publicly available, so no test here has seen a genuinely BBT-processed PDB
from a vendor symbol server; `test_omap.py` re-serialises a real PDB with the
tables added.

### Section Map addresses are a reconstruction, and say so
When the slot-5 section-header stream is absent, addresses are rebuilt from
DBI's Section Map, which records segment sizes but **no addresses** (every
entry's `Offset` is 0 in everything `link.exe` and `rust-lld` emit). The
reconstruction assumes the PE default `0x1000` section alignment, which the PDB
does not record anywhere. `diagnose()` reports `derived_sections` when this
happened. Keep that distinction visible — it is a reconstruction, not a
reading.

### Fixtures: 12 MB in the repo, zero in the wheel
`tests/data/` is excluded from both sdist and wheel targets, and the tests that
use it **skip** when it is absent. CI proves this by building an sdist and
running the suite from it. A fixture-dependent test that *fails* instead of
skipping breaks that job. New fixtures must be small and must have their toolchain and licence recorded
in `tests/data/README.md` — a fixture whose provenance is unclear cannot stay
in a public repository.

Prefer own builds or public-domain sources. **Third-party material is allowed
only when its licence permits redistribution**, and then only with the licence
named, the attribution in `NOTICE`, and a SHA-256 written down. `syzygy/` is
the one such fixture (Apache-2.0). The test that matters is the licence, not
the authorship: a Microsoft symbol-server PDB is ineligible because it permits
no redistribution at all, not because it is someone else's build — that was
proposed once and declined, and the distinction is worth keeping straight.

The current set is sqlite x86/x64, two rust-lld builds (one with slot 5
cleared), a purpose-built `tls/` fixture for thread-local records, and
`syzygy/` for a real OMAP table.

### Provenance is a legal boundary, not a formality
purepdb is an independent implementation written from **published format
documentation** (LLVM's PDB docs, Microsoft's MIT-licensed `microsoft-pdb`
sources for `cvinfo.h` constants and record layouts, the PE/COFF spec). It
contains no code copied or mechanically translated from another project, and
[`NOTICE`](NOTICE) says so.

If you extend purepdb by consulting another project's **source** rather than
the published format description, that is a materially different situation and
`NOTICE` has to change with it. Cite the documentation in the module docstring,
as every existing module does.

### Actions are pinned to commit SHAs on purpose
Every workflow pins its actions to a full commit SHA, which is what makes them
immutable; dependabot raises a PR when a pin moves. Do not replace a SHA with a
tag, and do not unpin a dev-tool version in `[dependency-groups]` — a tool that
moves on its own turns an unrelated pull request red.

### A thread-local's address is not a variable's address
`ThreadLocal.template_rva` is deliberately not called `rva`. A thread-local's
`segment:offset` addresses the **TLS initialisation template** — the bytes each
new thread's private copy starts from — while the variable itself lives at an
address computed from the TEB at run time and is in no section of the image at
all. The two numbers both look like RVAs and are not comparable. The differing
field name is the guard: pairing one with a `Function.rva` has to be typed on
purpose. Do not rename it to `rva` for consistency, and do not fold
`thread_locals()` into `data_symbols()`.

### `parse_record`'s dispatch and the truncation guard are one fact in two places
Every kind with a parser must be dispatched by `codeview.parse_record`, because
that is what `count_malformed_records` uses to ask whether a record is shorter
than its kind requires. A kind missing from it has its damaged records dropped
by the extractors and **counted by nothing**.

The dispatch is the table `_RECORD_PARSERS` at the foot of `codeview.py`, which
exports `DISPATCHED_KINDS`. `tests/test_truncation.py` holds the expected list
and `test_the_dispatch_and_this_list_agree` couples the two, so **adding a kind
to the dispatch without adding it to that list fails, and so does removing
one**.

The list is written out rather than derived on purpose: parametrizing over
`DISPATCHED_KINDS` was tried and is wrong, because a kind removed from the
dispatch takes its own test case with it — the suite reports one fewer passing
test and no failure. Do not "simplify" it back to a derived list.

### Reality check — common traps
- **`tests/_pe.py` must stay ignorant of purepdb.** Importing the package there
  to "share the section parsing" would destroy the only independent oracle in
  the suite.
- **TPI is out of scope.** No type is decoded. The IPI stream is read *only* for
  the names inlined bodies refer to by item id (`LF_FUNC_ID`, `LF_MFUNC_ID`,
  `LF_STRING_ID`). Do not start decoding the type graph as a side effect of
  something else.
- **Names come back raw**, and that is settled rather than pending. Demangling
  was declined in issue 30: `compile_info()` reports each module's source
  language, which is the part purepdb should own — a consumer then knows which
  demangler applies. Implementing one here would mean a dependency or a few
  thousand lines, against a `NOTICE` that rejects every alternative parser for
  its dependency chain. If it ever arrives it belongs in a separate package,
  consumed as an optional CLI extra, with the library still returning raw
  names. Do not add it incidentally.
- **`/DEBUG:FASTLINK` PDBs carry no procedure records at all.** Publics still
  work, and `diagnose()` says so. An empty proc list on such a file is correct
  behaviour, not a bug to chase.
- **Managed (.NET) code is out of scope.** `S_GMANPROC`/`S_LMANPROC` are keyed
  by metadata token rather than `segment:offset` and have no RVA to resolve;
  `diagnose()` detects this shape and says the PDB describes managed code.
  Portable PDBs are not MSF containers at all.
- **C11 line info is not parsed**, and no PDB from a supported toolchain carries
  any (all fixtures have `c11_byte_size == 0`).
- **Unknown record kinds must stay skippable by length.** The record walker
  keeps the stream in sync using `RecordLen`; a parser that assumes a payload
  size for an unrecognised kind desynchronises everything after it.
