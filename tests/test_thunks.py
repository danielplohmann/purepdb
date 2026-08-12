"""Thunks and trampolines: named and unnamed compiler-generated jump stubs.

`S_THUNK32` is code with a name, so it belongs in `functions()`. `S_TRAMPOLINE`
is code without one -- it gives a range and a jump target and nothing else --
so it gets its own listing rather than a synthesised name in the function list.
"""

import struct

import pytest

from purepdb import PDB, codeview
from tests._synth import (
    build_msf,
    dbi_stream,
    gproc32,
    make_record,
    module_info,
    module_sym_stream,
    pub32,
    publics_hash_stream,
    record_offsets,
    section_contributions,
    section_header,
    thunk32,
    trampoline,
)


def test_a_thunk_record_is_decoded():
    thunks = codeview.extract_thunks(thunk32("RoInitialize", 1, 0x1234, length=6))
    assert len(thunks) == 1
    t = thunks[0]
    assert (t.name, t.segment, t.offset, t.length) == ("RoInitialize", 1, 0x1234, 6)
    assert t.ordinal_name == "notype"


def test_a_thunk_scope_does_not_swallow_the_records_after_it():
    """S_THUNK32 opens a scope closed by S_END; the flat walk steps over both."""
    data = (thunk32("stub", 1, 0x10)
            + make_record(codeview.S_END, b"")
            + gproc32("real", 1, 0x20))
    assert [t.name for t in codeview.extract_thunks(data)] == ["stub"]
    assert [p.name for p in codeview.extract_procs(data)] == ["real"]


def test_a_trampoline_record_is_decoded():
    data = trampoline(thunk_segment=1, thunk_offset=0x10,
                      target_segment=2, target_offset=0x2000, size=5)
    tramps = codeview.extract_trampolines(data)
    assert len(tramps) == 1
    t = tramps[0]
    assert t.kind == codeview.TRAMP_INCREMENTAL
    assert (t.segment, t.offset) == (1, 0x10)
    assert (t.target_segment, t.target_offset) == (2, 0x2000)
    assert t.size == 5


@pytest.mark.parametrize("kind", [codeview.S_THUNK32, codeview.S_TRAMPOLINE])
def test_a_record_too_short_for_its_kind_is_skipped_not_raised(kind):
    """RecordLen is the record's own claim about its size; a short one hands a
    truncated payload to a parser expecting a whole one."""
    short = struct.pack("<HH", 2, kind)
    good_thunk = thunk32("t", 1, 0x10)
    good_tramp = trampoline(thunk_segment=1, thunk_offset=0,
                            target_segment=1, target_offset=0x10)

    assert [t.name for t in codeview.extract_thunks(short + good_thunk)] == ["t"]
    assert len(codeview.extract_trampolines(short + good_tramp)) == 1


def _pdb(module_records: bytes, publics=(), contributions=()):
    module_syms = module_sym_stream(module_records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6],
                   sec_contrib=(section_contributions(list(contributions))
                                if contributions else b"")),
        publics_hash_stream(record_offsets(list(publics))),
        module_syms,
        section_header(".text", 0x1000) + section_header(".data", 0x2000),
        b"".join(publics),
    ]
    return PDB.from_bytes(build_msf(streams))


def test_a_thunk_with_no_other_record_becomes_a_function():
    pdb = _pdb(thunk32("__imp_stub", 1, 0x40, length=6))
    fns = pdb.functions()
    assert [(f.name, f.rva, f.code_size, f.source) for f in fns] == [
        ("__imp_stub", 0x1040, 6, "thunk"),
    ]


def test_a_thunk_name_joins_an_address_that_is_already_known():
    """The x86 shape: the public is decorated, the thunk record is not."""
    pdb = _pdb(thunk32("RoInitialize", 1, 0x40),
               publics=[pub32("_RoInitialize@4", 1, 0x40)])
    fn = pdb.functions()[0]
    assert fn.name == "_RoInitialize@4"
    assert fn.aliases == ["RoInitialize"]
    assert fn.source == "public"


def test_a_proc_at_the_same_address_still_wins_the_name():
    pdb = _pdb(gproc32("real", 1, 0x40) + thunk32("stub", 1, 0x40))
    fn = pdb.functions()[0]
    assert (fn.name, fn.source, fn.aliases) == ("real", "proc", ["stub"])


def test_a_thunk_only_function_is_attributed_to_its_module():
    """A thunk with no proc or public at its address still resolves.

    Attribution used to depend on a redundant record happening to share the
    address -- which is precisely the import-thunk case it exists to cover,
    and precisely where no such record exists.
    """
    pdb = _pdb(thunk32("__imp_stub", 1, 0x040),
               contributions=[(1, 0x000, 0x100, 0)])
    assert [(f.name, f.source, f.module) for f in pdb.functions()] == [
        ("__imp_stub", "thunk", "main.obj"),
    ]


def test_trampolines_are_not_functions():
    pdb = _pdb(trampoline(thunk_segment=1, thunk_offset=0x40,
                          target_segment=1, target_offset=0x800))
    assert pdb.functions() == []
    assert len(pdb.trampolines()) == 1


def test_a_trampoline_resolves_both_ends_through_to_rva():
    pdb = _pdb(trampoline(thunk_segment=1, thunk_offset=0x40,
                          target_segment=2, target_offset=0x80))
    t = pdb.trampolines()[0]
    assert pdb.to_rva(t.segment, t.offset) == 0x1040
    assert pdb.to_rva(t.target_segment, t.target_offset) == 0x2080


# --- against real linker output ---------------------------------------------

def _open(rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    return PDB.open(str(path))


@pytest.mark.parametrize("rel,n_thunks,n_trampolines", [
    pytest.param("sqlite/x86/sqlite3.pdb", 81, 368, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 79, 348, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 0, 0, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 0, 0, id="rustpe-i686"),
])
def test_real_counts_are_stable(rel, n_thunks, n_trampolines):
    pdb = _open(rel)
    assert len(pdb.thunks()) == n_thunks
    assert len(pdb.trampolines()) == n_trampolines


@pytest.mark.parametrize("rel", ["sqlite/x86/sqlite3.pdb", "sqlite/x64/sqlite3.pdb"])
def test_every_thunk_lands_in_executable_code(rel):
    pdb = _open(rel)
    for t in pdb.thunks():
        rva = pdb.to_rva(t.segment, t.offset)
        assert rva is not None, f"{t.name} has no rva"
        assert pdb.sections[t.segment - 1].executable
        assert t.length > 0


@pytest.mark.parametrize("rel", ["sqlite/x86/sqlite3.pdb", "sqlite/x64/sqlite3.pdb"])
def test_every_thunk_name_reaches_the_function_list(rel):
    pdb = _open(rel)
    names = {n for f in pdb.functions() for n in f.names}
    assert {t.name for t in pdb.thunks()} <= names


def test_thunks_recover_the_undecorated_import_name_on_x86():
    """81 names that only the thunk records carry, at addresses already known."""
    pdb = _open("sqlite/x86/sqlite3.pdb")
    by_addr = {(f.segment, f.offset): f for f in pdb.functions()}
    thunks = pdb.thunks()
    assert thunks, "expected import thunks"

    for t in thunks:
        fn = by_addr[(t.segment, t.offset)]
        assert t.name in fn.aliases
        # The public is the x86 decoration of the same name: `_strrchr` for
        # cdecl, `_RoInitialize@4` for stdcall.
        decorated = f"_{t.name}"
        assert fn.name == decorated or fn.name.startswith(decorated + "@")


@pytest.mark.parametrize("rel", ["sqlite/x86/sqlite3.pdb", "sqlite/x64/sqlite3.pdb"])
def test_every_trampoline_jumps_to_a_function_we_found(rel):
    """The check that the target fields are being read the right way round."""
    pdb = _open(rel)
    entry_points = {(f.segment, f.offset) for f in pdb.functions()}
    tramps = pdb.trampolines()
    assert tramps, "expected incremental-link trampolines"

    for t in tramps:
        assert t.kind == codeview.TRAMP_INCREMENTAL
        assert t.size == 5, "a near jmp is 5 bytes"
        assert (t.target_segment, t.target_offset) in entry_points
        assert (t.segment, t.offset) not in entry_points
