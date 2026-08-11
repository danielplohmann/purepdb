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
                 0x014C, 8, 3539, 685, 3620, 357, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", "sqlite/x64/sqlite3.dll",
                 0x8664, 9, 3522, 660, 3601, 13, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb",
                 "rustpe/rust_pe_symbols_msvc.exe",
                 0x8664, 7, 248, 451, 399, 124, id="rustpe-msvc"),
]


def _load(pdb_rel, image_rel):
    pdb_path, image_path = DATA / pdb_rel, DATA / image_rel
    if not pdb_path.exists() or not image_path.exists():
        pytest.skip(f"groundtruth fixture missing: {pdb_rel} "
                    f"(present in the git repo, excluded from the sdist)")
    return PDB.open(str(pdb_path)), image_path.read_bytes()


@pytest.mark.parametrize(
    "pdb_rel,image_rel,machine,n_sections,n_procs,n_publics,n_functions,n_aliased",
    CASES)
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
    CASES)
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
])
def test_unflagged_code_publics_matter_only_for_rust_lld(pdb_rel, image_rel,
                                                        strict, relaxed):
    """Pin the toolchain difference that justifies the `code_publics` rule.

    `link.exe` sets PUBLIC_FLAG_FUNCTION on every code public, so the two
    modes agree on sqlite3. `rust-lld` leaves it clear on 143 of them, so
    trusting the flag alone loses 36% of that binary's functions.
    """
    pdb, _image = _load(pdb_rel, image_rel)
    assert len(pdb.functions(code_publics=False)) == strict
    assert len(pdb.functions()) == relaxed


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
