"""S_PROCREF/S_LPROCREF: every procedure, indexed from one stream.

`module_procs()` finds procedures by walking every module stream -- 78 of them
on sqlite3 x86, 161 on the rust fixture. The globals index the same set, and
the records that index it live in the symbol-record stream purepdb already
reads for publics.

The globals *stream* itself holds no records, only a hash table of offsets into
the symbol-record stream, exactly like the publics stream. That is the trap
`purepdb.gsi` exists to document, and it applies here too.
"""

import struct

import pytest

from purepdb import PDB, codeview
from tests._synth import (
    build_msf,
    dbi_stream,
    gproc32,
    module_info,
    module_sym_stream,
    proc_ref,
    publics_hash_stream,
    section_header,
)


def test_a_proc_ref_is_decoded():
    refs = codeview.extract_proc_refs(
        proc_ref("main", module=1, sym_offset=0x40))
    assert len(refs) == 1
    ref = refs[0]
    assert (ref.name, ref.module_index, ref.sym_offset) == ("main", 0, 0x40)
    assert ref.is_global


def test_a_static_proc_ref_is_distinguished():
    ref = codeview.extract_proc_refs(
        proc_ref("helper", module=2, sym_offset=0, kind=codeview.S_LPROCREF))[0]
    assert not ref.is_global
    assert ref.module_index == 1


def _pdb(modules, symrecords=b""):
    """`modules` is a list of module record blobs; streams start at 5."""
    module_syms = [module_sym_stream(records) for records in modules]
    mods = b"".join(
        module_info(f"mod{i}.obj", f"mod{i}.lib", sym_stream=5 + i,
                    sym_byte_size=len(syms))
        for i, syms in enumerate(module_syms)
    )
    section_stream = 5 + len(module_syms)
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=section_stream + 1,
                   module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [section_stream]),
        publics_hash_stream([]),
        *module_syms,
        section_header(".text", 0x1000),
        symrecords,
    ]
    return PDB.from_bytes(build_msf(streams))


def test_proc_refs_reach_the_same_procedures_as_the_module_walk():
    records = gproc32("main", 1, 0x10) + gproc32("helper", 1, 0x40)
    offsets = [4, 4 + len(gproc32("main", 1, 0x10))]  # past the CV signature
    pdb = _pdb([records],
               symrecords=proc_ref("main", 1, offsets[0])
               + proc_ref("helper", 1, offsets[1], kind=codeview.S_LPROCREF))

    assert [r.name for r in pdb.proc_refs()] == ["main", "helper"]
    assert ({r.name for r in pdb.proc_refs()}
            == {p.name for p in pdb.module_procs()})


def test_a_proc_ref_resolves_to_the_record_it_points_at():
    records = gproc32("main", 1, 0x10) + gproc32("helper", 1, 0x40)
    offset = 4 + len(gproc32("main", 1, 0x10))
    pdb = _pdb([records], symrecords=proc_ref("helper", 1, offset))

    proc = pdb.resolve_proc_ref(pdb.proc_refs()[0])
    assert proc is not None
    assert (proc.name, proc.segment, proc.offset) == ("helper", 1, 0x40)


def test_a_ref_into_a_second_module_uses_that_module_stream():
    pdb = _pdb([gproc32("a", 1, 0x10), gproc32("b", 1, 0x20)],
               symrecords=proc_ref("b", module=2, sym_offset=4))
    proc = pdb.resolve_proc_ref(pdb.proc_refs()[0])
    assert proc is not None and proc.name == "b"


@pytest.mark.parametrize("module,sym_offset", [
    (99, 4),      # module index past the module list
    (0, 4),       # 1-based index of 0: names no module at all
    (1, 0x4000),  # offset past the end of the stream
    (1, 0),       # points at the CV signature, not a record
])
def test_an_unresolvable_ref_answers_none_rather_than_raising(module, sym_offset):
    pdb = _pdb([gproc32("a", 1, 0x10)],
               symrecords=proc_ref("x", module, sym_offset))
    assert pdb.resolve_proc_ref(pdb.proc_refs()[0]) is None


def test_a_ref_pointing_at_a_record_with_a_bad_length_answers_none():
    """`RecordLen` is the target record's own claim about its size. A length
    below the 2-byte minimum makes the payload slice empty, and parsing it used
    to raise EOFError out of `resolve_proc_ref`."""
    records = bytearray(module_sym_stream(gproc32("a", 1, 0x10)))
    struct.pack_into("<H", records, 4, 0)  # RecordLen = 0

    module_syms = bytes(records)
    mods = module_info("mod0.obj", "mod0.lib", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]), module_syms, section_header(".text", 0x1000),
        proc_ref("a", 1, 4),
    ]
    pdb = PDB.from_bytes(build_msf(streams))
    assert pdb.resolve_proc_ref(pdb.proc_refs()[0]) is None


def test_a_proc_ref_record_too_short_for_its_kind_is_skipped():
    pdb = _pdb([gproc32("a", 1, 0x10)],
               symrecords=struct.pack("<HH", 2, codeview.S_PROCREF)
               + proc_ref("good", 1, 4))
    assert [r.name for r in pdb.proc_refs()] == ["good"]


def test_a_ref_pointing_at_a_record_that_is_not_a_proc_answers_none():
    from tests._synth import gdata32

    records = gdata32("g_counter", 2, 0x10)
    pdb = _pdb([records], symrecords=proc_ref("g_counter", 1, 4))
    assert pdb.resolve_proc_ref(pdb.proc_refs()[0]) is None


def test_a_pdb_with_no_symbol_record_stream_has_no_refs():
    module_syms = module_sym_stream(gproc32("main", 1, 0x10))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=0xFFFF, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]), module_syms, section_header(".text", 0x1000),
    ]
    assert PDB.from_bytes(build_msf(streams)).proc_refs() == []


# --- against real linker output ---------------------------------------------

def _open(rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    return PDB.open(str(path))


FIXTURES = ["sqlite/x86/sqlite3.pdb", "sqlite/x64/sqlite3.pdb",
            "rustpe/rust_pe_symbols_msvc.pdb", "rustpe32/rust_pe_symbols_i686.pdb",
            "tls/tls_symbols.pdb"]


@pytest.mark.parametrize("rel,n_refs", [
    pytest.param("sqlite/x86/sqlite3.pdb", 3539, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 3522, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 248, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 2, id="rustpe-i686"),
    pytest.param("tls/tls_symbols.pdb", 2, id="tls-x64"),
])
def test_the_globals_index_every_procedure(rel, n_refs):
    pdb = _open(rel)
    assert len(pdb.proc_refs()) == n_refs == len(pdb.module_procs())


@pytest.mark.parametrize("rel", FIXTURES)
def test_every_ref_resolves_to_the_proc_of_the_same_name(rel):
    """The check that `sym_offset` is being applied to the right bytes.

    It is an offset into the module stream *including* the 4-byte CodeView
    signature, so an off-by-four lands in the middle of a record and the names
    stop matching.
    """
    pdb = _open(rel)
    refs = pdb.proc_refs()
    assert refs

    for ref in refs:
        proc = pdb.resolve_proc_ref(ref)
        assert proc is not None, f"{ref.name} did not resolve"
        assert proc.name == ref.name


@pytest.mark.parametrize("rel", FIXTURES)
def test_the_two_paths_find_the_same_addresses(rel):
    """Whole-set agreement between the one-stream index and the module walk."""
    pdb = _open(rel)
    from_refs = sorted(
        (p.segment, p.offset, p.name)
        for p in (pdb.resolve_proc_ref(r) for r in pdb.proc_refs())
        if p is not None
    )
    from_walk = sorted((p.segment, p.offset, p.name) for p in pdb.module_procs())
    assert from_refs == from_walk


@pytest.mark.parametrize("rel", FIXTURES)
def test_refs_name_the_module_that_defined_the_procedure(rel):
    pdb = _open(rel)
    for ref in pdb.proc_refs():
        assert 0 <= ref.module_index < len(pdb.dbi.modules)


# --- diagnose() reports the index, and says when it disagrees ---------------

@pytest.mark.parametrize("rel", FIXTURES)
def test_the_two_counts_agree_on_every_fixture(rel):
    """The agreement is the integrity signal, so it belongs in diagnose()."""
    d = _open(rel).diagnose()
    assert d.proc_refs == d.proc_records
    assert not any("globals index" in w for w in d.warnings)


def test_a_ref_pointing_at_nothing_readable_is_a_disagreement():
    """One proc in the module stream, two refs in the globals index.

    A PDB is not malformed for this, so it is a warning rather than an error --
    but the second ref names a procedure at an offset with no record at it, so
    the module walk really is reading less than the file describes.
    """
    pdb = _pdb([gproc32("main", 1, 0x10)],
               symrecords=proc_ref("main", module=1, sym_offset=4)
               + proc_ref("ghost", module=1, sym_offset=0x40))

    d = pdb.diagnose()
    assert (d.proc_refs, d.proc_records) == (2, 1)
    assert (d.unresolvable_proc_refs, d.unmatched_proc_refs) == (1, 1)
    warning = next(w for w in d.warnings if "globals index" in w)
    assert "1 of the 2 procedures" in warning
    assert "could not be read" in warning


def test_refs_onto_managed_methods_are_not_a_disagreement():
    """The shape 16 of 39 real PDBs have: a managed file indexes every method
    it describes, and purepdb reports none of them as native procedures. The
    warning about managed code says so; a second one saying the module walk is
    short does not, and contradicts the first."""
    from tests._synth import manproc

    pdb = _pdb([manproc("Program.Main", token=0x06000001)],
               symrecords=proc_ref("Program.Main", module=1, sym_offset=4))

    d = pdb.diagnose()
    assert (d.proc_refs, d.proc_records) == (1, 0)
    assert d.proc_ref_targets == {codeview.S_GMANPROC: 1}
    assert d.unmatched_proc_refs == 0
    assert not any("globals index" in w for w in d.warnings)
    assert any("managed" in w for w in d.warnings)


def test_refs_onto_import_thunks_are_not_a_disagreement():
    """The other shape the corpus has: a driver PDB whose imports carry
    S_THUNK32 rather than S_GPROC32. `functions()` reports them, so nothing is
    missing to warn about."""
    from tests._synth import thunk32

    records = gproc32("main", 1, 0x10) + thunk32("DbgPrint", 1, 0x40)
    pdb = _pdb([records],
               symrecords=proc_ref("main", module=1, sym_offset=4)
               + proc_ref("DbgPrint", module=1,
                          sym_offset=4 + len(gproc32("main", 1, 0x10))))

    d = pdb.diagnose()
    assert (d.proc_refs, d.proc_records) == (2, 1)
    assert d.proc_ref_targets == {codeview.S_GPROC32: 1, codeview.S_THUNK32: 1}
    assert d.unmatched_proc_refs == 0
    assert not any("globals index" in w for w in d.warnings)
    assert "DbgPrint" in {f.name for f in pdb.functions()}


def test_a_ref_onto_a_kind_nothing_accounts_for_names_that_kind():
    """The case the warning is for, and the one the corpus never produced."""
    from tests._synth import gdata32

    pdb = _pdb([gdata32("g_counter", 2, 0x10)],
               symrecords=proc_ref("g_counter", module=1, sym_offset=4))

    d = pdb.diagnose()
    assert d.unmatched_proc_refs == 1
    warning = next(w for w in d.warnings if "globals index" in w)
    assert "S_GDATA32" in warning


def _count_stream_reads(pdb):
    """Every stream index `diagnose()` reads, in order."""
    reads: list[int] = []
    inner = pdb.msf.read_stream

    def counting(index):
        reads.append(index)
        return inner(index)

    pdb.msf.read_stream = counting  # type: ignore[method-assign]
    pdb.diagnose()
    return reads


def test_resolving_refs_costs_one_read_per_module_however_they_are_ordered():
    """The stream cache holds one stream, so resolving refs in the order the
    file happens to store them is a read per ref rather than per module. On the
    393 MB file in the corpus, whose refs revisit modules throughout, that is
    106s against 0.9s -- the difference between a diagnostic and one nobody
    waits for. Measured as what the refs add over the same file without them,
    since `diagnose()` reads each module stream a few times regardless."""
    modules = [gproc32("a", 1, 0x10), gproc32("b", 1, 0x20)]
    alternating = b"".join([
        proc_ref("a", module=1, sym_offset=4),
        proc_ref("b", module=2, sym_offset=4),
        proc_ref("a", module=1, sym_offset=4),
        proc_ref("b", module=2, sym_offset=4),
    ])

    without = _count_stream_reads(_pdb(modules))
    with_refs = _count_stream_reads(_pdb(modules, symrecords=alternating))

    # Streams 5 and 6 are the two module streams. Four refs that alternate
    # between them add one read each, not one per ref.
    assert [with_refs.count(i) - without.count(i) for i in (5, 6)] == [1, 1]


def test_a_pdb_with_no_refs_at_all_is_not_a_disagreement():
    """Plenty of PDBs index nothing; only a non-empty index is comparable."""
    pdb = _pdb([gproc32("main", 1, 0x10)])
    d = pdb.diagnose()
    assert d.proc_refs == 0
    assert not any("globals index" in w for w in d.warnings)
