"""Golden-file tests against real compiler-produced PDBs.

The synthetic tests prove internal consistency; these prove conformance to what
MSVC's `link.exe` and `rust-lld` actually emit. Two independent checks run here:

*Pinned counts* catch silent regressions. A parser that reads the wrong stream
returns an empty list rather than raising, so the numbers themselves have to be
asserted -- see `tests/test_publics.py` for why.

*The PE oracle* is the stronger check, because it does not consult the PDB at
all. `tests/_pe.py` reads the companion image and we require agreement on the
section table, and on the address of every exported function. Exports point at
`jmp rel32` thunks rather than at function bodies, so the thunk is followed
before comparing -- 272 of sqlite3's 277 exports are code and must land exactly
on a function purepdb found; the other 5 are exported variables and must not
appear as functions at all.

Fixtures live in `tests/data/`. They are in the repository but excluded from the
sdist and wheel, so an installed copy of purepdb does not carry 12 MB of
binaries; everything here skips when they are absent.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from purepdb import PDB
from tests._pe import PeImage, _rva_to_file_offset

DATA = Path(__file__).resolve().parent / "data"

# (pdb, image, machine, sections, procs, publics, functions, aliased)
CASES = [
    pytest.param("sqlite/x86/sqlite3.pdb", "sqlite/x86/sqlite3.dll",
                 0x014C, 8, 3539, 685, 3620, 438, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", "sqlite/x64/sqlite3.dll",
                 0x8664, 9, 3522, 660, 3601, 13, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb",
                 "rustpe/rust_pe_symbols_msvc.exe",
                 0x8664, 7, 248, 451, 399, 124, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb",
                 "rustpe32/rust_pe_symbols_i686.exe",
                 0x014C, 2, 2, 5, 6, 1, id="rustpe-i686"),
    pytest.param("tls/tls_symbols.pdb", "tls/tls_symbols.exe",
                 0x8664, 6, 2, 10, 2, 0, id="tls-x64"),
]

# The same i686 fixture with Optional Debug Header slot 5 cleared, so its
# addresses come from the DBI Section Map instead of a section-header table
# (issue #25). Every count and every RVA must match the original, which is
# what makes it a check rather than a second set of numbers -- but it has no
# section table of its own, so `test_section_table_matches_the_image` takes
# `CASES` alone while the other two take both.
NO_SECTION_HEADER_CASES = [
    pytest.param("rustpe32/rust_pe_symbols_i686_no_slot5.pdb",
                 "rustpe32/rust_pe_symbols_i686.exe",
                 0x014C, 2, 2, 5, 6, 1, id="rustpe-i686-no-slot5"),
]


def _load(pdb_rel, image_rel):
    pdb_path, image_path = DATA / pdb_rel, DATA / image_rel
    if not pdb_path.exists() or not image_path.exists():
        pytest.skip(f"groundtruth fixture missing: {pdb_rel} "
                    f"(present in the git repo, excluded from the sdist)")
    return PDB.open(str(pdb_path)), image_path.read_bytes()


@pytest.mark.parametrize(
    "pdb_rel,image_rel,machine,n_sections,n_procs,n_publics,n_functions,n_aliased",
    CASES + NO_SECTION_HEADER_CASES)
def test_counts_are_stable(pdb_rel, image_rel, machine, n_sections, n_procs,
                           n_publics, n_functions, n_aliased):
    pdb, _image = _load(pdb_rel, image_rel)
    assert pdb.dbi.machine == machine
    assert len(pdb.module_procs()) == n_procs
    assert len(pdb.public_symbols()) == n_publics, "publics must never be empty"
    fns = pdb.functions()
    assert len(fns) == n_functions
    assert sum(1 for f in fns if f.aliases) == n_aliased


@pytest.mark.parametrize(
    "pdb_rel,image_rel,machine,n_sections,n_procs,n_publics,n_functions,n_aliased",
    CASES)
def test_section_table_matches_the_image(pdb_rel, image_rel, machine,
                                         n_sections, n_procs, n_publics,
                                         n_functions, n_aliased):
    """The PDB's section-header stream must reproduce the PE's own table."""
    pdb, image_bytes = _load(pdb_rel, image_rel)
    image = PeImage.parse(image_bytes)
    assert image.machine == machine
    assert len(image.sections) == n_sections

    from_pdb = [(s.name, s.virtual_address, s.virtual_size)
                for s in pdb.sections]
    from_pe = [(s.name, s.virtual_address, s.virtual_size)
               for s in image.sections]
    assert from_pdb == from_pe


@pytest.mark.parametrize(
    "pdb_rel,image_rel,machine,n_sections,n_procs,n_publics,n_functions,n_aliased",
    CASES + NO_SECTION_HEADER_CASES)
def test_every_function_lands_in_executable_code(pdb_rel, image_rel, machine,
                                                 n_sections, n_procs,
                                                 n_publics, n_functions,
                                                 n_aliased):
    pdb, image_bytes = _load(pdb_rel, image_rel)
    image = PeImage.parse(image_bytes)
    for fn in pdb.functions():
        assert fn.rva is not None, f"{fn.name} has no RVA"
        section = image.section_of(fn.rva)
        assert section is not None, f"{fn.name} at {fn.rva:#x} is outside every section"
        assert section.executable, f"{fn.name} at {fn.rva:#x} is in {section.name}"


@pytest.mark.parametrize("pdb_rel,image_rel,n_code,n_data", [
    pytest.param("sqlite/x86/sqlite3.pdb", "sqlite/x86/sqlite3.dll",
                 272, 5, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", "sqlite/x64/sqlite3.dll",
                 272, 5, id="sqlite-x64"),
])
def test_exports_agree_with_the_image(pdb_rel, image_rel, n_code, n_data):
    """Follow each export thunk and require it to hit a function we found.

    This is the independent check: the expected addresses come from the image's
    export directory and its code bytes, never from the PDB.
    """
    pdb, image_bytes = _load(pdb_rel, image_rel)
    image = PeImage.parse(image_bytes)
    assert image.exports, "expected an export directory"

    rva_of = {}
    for fn in pdb.functions():
        for name in fn.names:
            rva_of.setdefault(name, fn.rva)

    code, data, mismatched = 0, 0, []
    for name, export_rva in image.exports.items():
        target = _follow_jmp(image_bytes, image, export_rva)
        if target is None:
            # Not a thunk: an exported variable. It must not be a function.
            data += 1
            assert name not in rva_of, f"{name} is data but appears as a function"
            continue
        code += 1
        if rva_of.get(name) != target:
            mismatched.append((name, hex(target), hex(rva_of.get(name) or 0)))

    assert not mismatched, f"export/PDB address disagreement: {mismatched[:5]}"
    assert (code, data) == (n_code, n_data)


def _follow_jmp(data: bytes, image: PeImage, rva: int) -> int | None:
    """Resolve a `jmp rel32` thunk to its target RVA, or None if not a thunk."""
    offset = _rva_to_file_offset(data, image, rva)
    if offset is None or data[offset] != 0xE9:
        return None
    (delta,) = struct.unpack_from("<i", data, offset + 1)
    return rva + 5 + delta


@pytest.mark.parametrize("pdb_rel,image_rel,strict,relaxed", [
    pytest.param("sqlite/x86/sqlite3.pdb", "sqlite/x86/sqlite3.dll",
                 3620, 3620, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", "sqlite/x64/sqlite3.dll",
                 3601, 3601, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb",
                 "rustpe/rust_pe_symbols_msvc.exe",
                 256, 399, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb",
                 "rustpe32/rust_pe_symbols_i686.exe",
                 2, 6, id="rustpe-i686"),
    pytest.param("tls/tls_symbols.pdb", "tls/tls_symbols.exe",
                 2, 2, id="tls-x64"),
])
def test_unflagged_code_publics_matter_only_for_rust_lld(pdb_rel, image_rel,
                                                        strict, relaxed):
    """Pin the toolchain difference that justifies the `code_publics` rule.

    `link.exe` sets PUBLIC_FLAG_FUNCTION on every code public, so the two
    modes agree on sqlite3. `rust-lld` leaves it clear on 143 of them, so
    trusting the flag alone loses 36% of that binary's functions -- and 4 of
    the i686 fixture's 6, which is what shows the rule is not an x86_64
    accident.
    """
    pdb, _image = _load(pdb_rel, image_rel)
    assert len(pdb.functions(code_publics=False)) == strict
    assert len(pdb.functions()) == relaxed


def test_the_code_publics_rule_is_not_an_x86_64_accident():
    """What leaves PUBLIC_FLAG_FUNCTION clear, on the fixture built to show it.

    The flag comes from the contributing object's COFF symbol type, not from
    the architecture and not from the linker: `rust-lld` sets it for every
    symbol rustc and clang emit, and leaves it clear for the ones the
    hand-written assembly stub defines, because assembly declares no function
    type. That is the same shape as the x86_64 fixture's CRT symbols, here at
    i686 and small enough to read in full.
    """
    pdb, image_bytes = _load("rustpe32/rust_pe_symbols_i686.pdb",
                             "rustpe32/rust_pe_symbols_i686.exe")
    image = PeImage.parse(image_bytes)

    unflagged = {p.name for p in pdb.public_symbols() if not p.is_function}
    assert unflagged == {"_platform_seed", "_platform_report",
                         "___chkstk", "_platform_ticks"}

    strict = {f.name for f in pdb.functions(code_publics=False)}
    assert strict == {"main::digest", "main::mainCRTStartup"}

    # All four are real code, and the relaxed rule is what recovers them.
    for fn in pdb.functions():
        if fn.name in strict:
            continue
        assert fn.name in unflagged
        section = image.section_of(fn.rva)
        assert section is not None and section.executable


def test_unflagged_code_publics_are_real_functions():
    """Spot-check the names the relaxed rule admits, against the image."""
    pdb, image_bytes = _load("rustpe/rust_pe_symbols_msvc.pdb",
                             "rustpe/rust_pe_symbols_msvc.exe")
    image = PeImage.parse(image_bytes)
    strict = {f.name for f in pdb.functions(code_publics=False)}
    added = {f.name: f for f in pdb.functions() if f.name not in strict}

    assert {"mainCRTStartup", "__chkstk", "__CxxFrameHandler3"} <= set(added)
    for fn in added.values():
        section = image.section_of(fn.rva)
        assert section is not None and section.executable


def test_publics_past_the_last_section_are_cfg_metadata():
    """A segment one past the last section is legitimate, not corruption.

    MSVC puts Control Flow Guard load-config symbols there. They must resolve to
    no RVA and must never reach `functions()`, which is what makes it safe for
    `to_rva()` to answer None instead of raising.
    """
    pdb, _image = _load("sqlite/x86/sqlite3.pdb", "sqlite/x86/sqlite3.dll")
    beyond = len(pdb.sections) + 1
    stray = [p for p in pdb.public_symbols() if p.segment == beyond]

    assert stray, "expected CFG metadata publics past the last section"
    assert {p.name for p in stray} >= {"___guard_fids_table", "___guard_flags"}
    for p in stray:
        assert not p.is_function
        assert pdb.to_rva(p.segment, p.offset) is None
    assert all(f.rva is not None for f in pdb.functions())


@pytest.mark.parametrize("pdb_rel,image_rel,local_kind", [
    pytest.param("sqlite/x86/sqlite3.pdb", "sqlite/x86/sqlite3.dll",
                 "S_BPREL32", id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", "sqlite/x64/sqlite3.dll",
                 "S_REGREL32", id="sqlite-x64"),
])
def test_local_variable_records_are_named_correctly(pdb_rel, image_rel, local_kind):
    """The dominant module record kind is locals, and must be named as such.

    x86 addresses locals off the frame pointer (S_BPREL32) and x64 off a
    register (S_REGREL32), so which name dominates is decided by the target
    rather than by us -- which is what makes this a check of the constants
    rather than of the histogram.
    """
    from purepdb import codeview

    pdb, _image = _load(pdb_rel, image_rel)
    kinds = pdb.diagnose().module_kinds
    dominant = max(kinds.items(), key=lambda kv: kv[1])[0]
    assert codeview.kind_name(dominant) == local_kind


def test_publics_carry_the_decorated_name():
    """On x86 cdecl the public keeps the leading underscore the proc drops.

    A concrete case for why folded/aliased names are worth keeping: the two
    spellings of one function come from two different record types.
    """
    pdb, _image = _load("sqlite/x86/sqlite3.pdb", "sqlite/x86/sqlite3.dll")
    by_name = {f.name: f for f in pdb.functions()}
    fn = by_name["sqlite3_strglob"]
    assert "_sqlite3_strglob" in fn.aliases
    assert fn.source == "proc"
