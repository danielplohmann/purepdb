"""OMAP translation: the one failure mode that produces wrong numbers.

Every other gap in this parser yields a missing answer -- an empty list, an
rva of None -- which `diagnose()` explains. A BBT-processed image is different:
the symbols carry pre-optimisation addresses, so skipping the address map
returns plausible RVAs that point at unrelated instructions.

No toolchain available here produces a BBT-processed PDB, so the evidence comes
in two layers: PDBs built from scratch with an original section table in slot
10 and an address map in slot 4, and -- at the end of this file -- a real
linker-produced PDB re-serialised with those two streams added, so that the
container, the DBI stream and every symbol record are the genuine article and
only the tables are ours.
"""

import struct

import pytest

from purepdb import PDB
from purepdb.omap import OmapTable
from tests._synth import (
    build_msf,
    dbi_stream,
    gproc32,
    label32,
    module_info,
    module_sym_stream,
    omap_stream,
    pub32,
    publics_hash_stream,
    record_offsets,
    section_header,
)

# --- the table itself -------------------------------------------------------

def test_lookup_interpolates_within_a_range():
    """Microsoft's rule: find the largest rva <= address, then add the delta."""
    table = OmapTable.parse(omap_stream([(0x1000, 0x5000), (0x2000, 0x3000)]))
    assert table.lookup(0x1000) == 0x5000
    assert table.lookup(0x1040) == 0x5040
    assert table.lookup(0x1FFF) == 0x5FFF
    assert table.lookup(0x2000) == 0x3000
    assert table.lookup(0x2010) == 0x3010


def test_an_identity_map_changes_nothing():
    table = OmapTable.parse(omap_stream([(0x1000, 0x1000)]))
    assert table.lookup(0x1234) == 0x1234


def test_addresses_below_the_first_entry_do_not_translate():
    table = OmapTable.parse(omap_stream([(0x1000, 0x5000)]))
    assert table.lookup(0x0FFF) is None
    assert table.lookup(0) is None


def test_a_zero_target_marks_a_gap():
    """rvaTo == 0 means the optimiser dropped the range; it has no address."""
    table = OmapTable.parse(omap_stream([
        (0x1000, 0x5000), (0x1100, 0), (0x1200, 0x5100),
    ]))
    assert table.lookup(0x10FF) == 0x50FF
    assert table.lookup(0x1100) is None
    assert table.lookup(0x11FF) is None
    assert table.lookup(0x1200) == 0x5100


def test_an_empty_table_translates_nothing():
    table = OmapTable.parse(b"")
    assert len(table) == 0
    assert table.lookup(0x1000) is None


def test_a_trailing_partial_entry_is_ignored():
    data = omap_stream([(0x1000, 0x5000)]) + b"\x01\x02\x03"
    table = OmapTable.parse(data)
    assert len(table) == 1
    assert table.lookup(0x1000) == 0x5000


def test_an_unsorted_table_is_still_answered_correctly():
    """The format defines the array as sorted; a file that is not must not
    silently return the wrong entry."""
    table = OmapTable.parse(omap_stream([(0x2000, 0x3000), (0x1000, 0x5000)]))
    assert table.lookup(0x1010) == 0x5010
    assert table.lookup(0x2010) == 0x3010


# --- end to end -------------------------------------------------------------

def _pdb(*, procs=(), publics=(), original_sections=(), final_sections=(),
         omap=None, section_headers=True):
    """A PDB whose symbols are addressed against `original_sections`.

    `section_headers=False` leaves slot 5 unnamed, which is the shape a
    BBT-processed PDB has when the only section table it carries is the
    pre-BBT one.
    """
    module_records = b"".join(procs)
    symrecords = b"".join(publics)
    module_syms = module_sym_stream(module_records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    dbg = [0xFFFF] * 11
    if section_headers:
        dbg[5] = 6
    if omap is not None:
        dbg[4] = 8
    # Slot 10 is named whenever an original table is supplied, and not only
    # alongside a map. Tying the two together made `original_sections=` silently
    # do nothing without `omap=`: the stream was written and never referenced,
    # so the table a test asked for was invisible and the case it meant to build
    # was not the case it got.
    if original_sections:
        dbg[10] = 9
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=dbg),
        publics_hash_stream(record_offsets(list(publics))),
        module_syms,
        b"".join(final_sections),
        symrecords,
        omap_stream(omap) if omap is not None else b"",
        b"".join(original_sections),
    ]
    return PDB.from_bytes(build_msf(streams))


# The optimiser moved .text: what the PDB calls 0x1000 ships at 0x8000, and
# the two functions came out in the opposite order.
ORIGINAL = [section_header(".text", 0x1000, 0x2000)]
FINAL = [section_header(".text", 0x8000, 0x2000)]
MOVED = [(0x1000, 0x8100), (0x1100, 0x8000)]


def test_rvas_are_translated_to_the_shipped_layout():
    pdb = _pdb(procs=[gproc32("first", 1, 0x000), gproc32("second", 1, 0x100)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=MOVED)

    by_name = {f.name: f for f in pdb.functions()}
    assert by_name["first"].rva == 0x8100
    assert by_name["second"].rva == 0x8000
    # segment:offset stays as the record spells it -- only the rva moves.
    assert by_name["first"].offset == 0x000


def test_a_label_is_translated_like_any_other_address():
    """`labels()` resolves through `to_rva`, so it must go through the map too.

    An untranslated label would point into the pre-optimisation layout, where
    on a BBT-processed image nothing lives. The module records here are a
    procedure and a label inside it.
    """
    pdb = _pdb(procs=[gproc32("host", 1, 0x000, code_size=0x80),
                      label32("host_retry", 1, 0x010)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=MOVED)

    label = pdb.labels()[0]
    assert label.offset == 0x010, "segment:offset stays as the record spells it"
    assert label.rva == 0x8110
    assert pdb.functions()[0].rva == 0x8100, "and the body it sits in moved too"
    assert "host_retry" not in {f.name for f in pdb.functions()}


def test_functions_are_sorted_by_the_translated_address():
    pdb = _pdb(procs=[gproc32("first", 1, 0x000), gproc32("second", 1, 0x100)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=MOVED)
    assert [f.name for f in pdb.functions()] == ["second", "first"]


def test_without_omap_the_untranslated_address_is_reported():
    """The regression this guards: the same PDB minus the address map."""
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)], final_sections=ORIGINAL)
    assert pdb.functions()[0].rva == 0x1000
    assert pdb.omap is None


def test_an_empty_address_map_leaves_addresses_alone():
    """A slot that names a stream with no entries maps nothing.

    The table is then present but empty, so a `is None` guard would let every
    address be looked up in it and come back None -- losing every rva in the
    file rather than the none it actually relocates.
    """
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=[])

    assert len(pdb.omap) == 0
    assert pdb.functions()[0].rva == 0x1000


def test_an_address_map_without_the_original_table_is_not_applied():
    """Slot 4 present, slot 10 absent: nothing to translate out of.

    The map converts the pre-BBT layout into the shipped one, so it only
    applies to an address resolved against the pre-BBT table. Resolving
    against the shipped headers and then translating anyway moved every
    address by the difference between the two layouts -- a wrong answer
    rather than a missing one, which is the failure this module exists
    to prevent.
    """
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)],
               final_sections=FINAL, omap=MOVED)

    assert pdb.original_sections == []
    assert pdb.functions()[0].rva == 0x8000, "the header address, untranslated"
    assert any("slot 10" in w and "not applied" in w
               for w in pdb.diagnose().warnings)


def test_eliminated_code_gets_no_rva_rather_than_a_wrong_one():
    pdb = _pdb(procs=[gproc32("kept", 1, 0x000), gproc32("dropped", 1, 0x100)],
               original_sections=ORIGINAL, final_sections=FINAL,
               omap=[(0x1000, 0x8000), (0x1100, 0)])

    by_name = {f.name: f for f in pdb.functions()}
    assert by_name["kept"].rva == 0x8000
    assert by_name["dropped"].rva is None


def test_publics_are_translated_too():
    pdb = _pdb(publics=[pub32("_start", 1, 0x100)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=MOVED)
    assert [(f.name, f.rva) for f in pdb.functions()] == [("_start", 0x8000)]


def test_code_publics_are_judged_against_the_original_section_table():
    """`code_publics` asks whether a segment is executable. The segment index
    in the record belongs to the original table, so that is the one to ask."""
    original = [section_header(".text", 0x1000, 0x2000),
                section_header(".data", 0x3000, 0x1000)]
    # In the shipped image the order is reversed, so consulting this table
    # would call the data public code and drop the real function.
    final = [section_header(".data", 0x8000, 0x1000),
             section_header(".text", 0x9000, 0x2000)]
    pdb = _pdb(publics=[pub32("code", 1, 0x000, flags=0),
                        pub32("data", 2, 0x000, flags=0)],
               original_sections=original, final_sections=final,
               omap=[(0x1000, 0x9000), (0x3000, 0x8000)])

    assert [(f.name, f.rva) for f in pdb.functions()] == [("code", 0x9000)]


def test_diagnose_reports_the_address_map():
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)],
               publics=[pub32("first", 1, 0x000)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=MOVED)
    d = pdb.diagnose()
    assert d.omap_entries == 2
    assert d.has_original_sections
    assert d.warnings == []


def test_a_bbt_pdb_without_slot_5_reports_the_two_address_spaces():
    """Slot 10 and the map present, slot 5 absent: the divergence in #39.

    Symbols resolve against the pre-BBT table and are then translated, so every
    rva is final. `sections` is slot 5 alone and comes back empty, which leaves
    `original_sections` as the only table a caller can display -- and that one
    is the space the map translates *out of*. Both numbers look like RVAs and
    nothing marked the mismatch.
    """
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=MOVED,
               section_headers=False)

    # The two answers really are in different spaces: the function ships at
    # 0x8100, and the only visible section table still says .text is at 0x1000.
    assert pdb.functions()[0].rva == 0x8100
    assert pdb.sections == []
    assert pdb.original_sections[0].virtual_address == 0x1000

    d = pdb.diagnose()
    assert d.omap_entries == 2
    assert d.has_original_sections
    assert not d.has_section_headers
    assert any("not comparable" in w for w in d.warnings), d.warnings


def test_a_bbt_pdb_with_both_tables_is_not_warned_about():
    """The ordinary BBT shape, which is fine: symbols resolve through slot 10
    plus the map and `sections` returns slot 5, both final addresses."""
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)],
               original_sections=ORIGINAL, final_sections=FINAL, omap=MOVED)

    assert pdb.sections[0].virtual_address == 0x8000
    assert not any("not comparable" in w for w in pdb.diagnose().warnings)


def test_no_address_space_warning_without_an_address_map():
    """Slot 10 and no slot 5, but no map: a different problem with its own
    warning, and this one must not also fire.

    The state is asserted before the absence is, because an absence test whose
    setup silently failed passes for the wrong reason -- which is exactly what
    this test did while slot 10 was only ever named alongside a map.
    """
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)],
               original_sections=ORIGINAL, section_headers=False)
    d = pdb.diagnose()

    assert (d.has_original_sections, d.omap_entries, d.has_section_headers) \
        == (True, 0, False)
    assert any("pre-optimisation address space" in w for w in d.warnings)
    assert not any("not comparable" in w for w in d.warnings)


def test_no_address_space_warning_without_the_pre_bbt_table():
    """A map and no slot 5, but no slot 10 either.

    Nothing was resolved against the pre-BBT table, so the map is not applied
    and the addresses are not post-BBT -- there are no two spaces to confuse.
    That case has its own warning; this one must not fire.
    """
    pdb = _pdb(procs=[gproc32("first", 1, 0x000)], omap=MOVED,
               section_headers=False)
    d = pdb.diagnose()

    assert (d.has_original_sections, d.omap_entries, d.has_section_headers) \
        == (False, 2, False)
    assert any("slot 10" in w and "not applied" in w for w in d.warnings)
    assert not any("not comparable" in w for w in d.warnings)


def test_original_sections_without_an_address_map_are_warned_about():
    """Slot 10 present, slot 4 missing: the rvas cannot be trusted, so say so."""
    module_syms = module_sym_stream(gproc32("first", 1, 0x000))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    dbg = [0xFFFF] * 11
    dbg[5] = 6
    dbg[10] = 8
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=dbg),
        publics_hash_stream([]), module_syms,
        b"".join(FINAL), pub32("first", 1, 0x000), b"".join(ORIGINAL),
    ]
    pdb = PDB.from_bytes(build_msf(streams))

    assert pdb.functions()[0].rva == 0x1000
    assert any("pre-optimisation address space" in w
               for w in pdb.diagnose().warnings)


def test_the_original_section_table_alone_still_resolves_addresses():
    """Slot 5 absent but slot 10 present: symbol addresses are expressed
    against slot 10 anyway, so they resolve -- and `diagnose()` must not claim
    otherwise, which is a warning that would be flatly false."""
    module_syms = module_sym_stream(gproc32("first", 1, 0x000))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    dbg = [0xFFFF] * 11
    dbg[4], dbg[10] = 8, 9  # address map and original sections, no slot 5
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=dbg),
        publics_hash_stream([]), module_syms, b"",
        pub32("first", 1, 0x000), omap_stream(MOVED), b"".join(ORIGINAL),
    ]
    pdb = PDB.from_bytes(build_msf(streams))

    assert pdb.sections == []
    assert pdb.functions()[0].rva == 0x8100
    assert not any("every rva is None" in w for w in pdb.diagnose().warnings)


def test_the_section_map_rebuild_stands_down_for_the_original_table():
    """Slot 10 present, slot 5 absent, and a Section Map sitting there too.

    Either real table makes the rebuild unnecessary, and reporting a
    reconstruction on a file whose addresses came from a real table is a false
    statement about where the numbers came from.
    """
    from tests._synth import section_map

    module_syms = module_sym_stream(gproc32("first", 1, 0x000))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    dbg = [0xFFFF] * 11
    dbg[4], dbg[10] = 8, 9  # address map and original sections, no slot 5
    sec_map = section_map([(0x1 | 0x4, 1, 0x2000), (0x200, 0, 0xFFFFFFFF)])
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=dbg, sec_map=sec_map),
        publics_hash_stream([]), module_syms, b"",
        pub32("first", 1, 0x000), omap_stream(MOVED), b"".join(ORIGINAL),
    ]
    pdb = PDB.from_bytes(build_msf(streams))

    assert pdb.dbi.section_map, "the map is present, it is just not needed"
    assert pdb.derived_sections == []
    assert pdb.diagnose().derived_sections == 0
    assert pdb.functions()[0].rva == 0x8100  # unchanged by standing down


def test_cli_diagnose_mentions_the_address_map(tmp_path, capsys):
    from purepdb.__main__ import main

    module_syms = module_sym_stream(gproc32("first", 1, 0x000))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    dbg = [0xFFFF] * 11
    dbg[5], dbg[4], dbg[10] = 6, 8, 9
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=dbg),
        publics_hash_stream([]), module_syms, b"".join(FINAL),
        pub32("first", 1, 0x000), omap_stream(MOVED), b"".join(ORIGINAL),
    ]
    path = tmp_path / "bbt.pdb"
    path.write_bytes(build_msf(streams))
    assert main(["purepdb", "diagnose", str(path)]) == 0
    assert "omap entries       : 2" in capsys.readouterr().out


@pytest.mark.parametrize("rel", [
    "sqlite/x86/sqlite3.pdb",
    "sqlite/x64/sqlite3.pdb",
    "rustpe/rust_pe_symbols_msvc.pdb", "rustpe32/rust_pe_symbols_i686.pdb",
    "tls/tls_symbols.pdb",
])
def test_ordinary_pdbs_carry_no_address_map(rel):
    """None of the fixtures is BBT-processed, so nothing may change for them."""
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    pdb = PDB.open(str(path))
    assert pdb.omap is None
    assert pdb.original_sections == []


def _with_omap(data: bytes, delta: int, *, section_headers: bool = True) -> bytes:
    """A real PDB, re-serialised with an address map and an original section
    table added.

    No toolchain available here produces a BBT-processed PDB, and the issue
    suggests exactly this as the practical substitute: synthetic tables inside
    a file that is otherwise real linker output, so the container, the DBI
    stream and every symbol record are the genuine article.

    `section_headers=False` also clears slot 5, which is the shape in #39. The
    real table is read out of `data` before the slot is cleared, so it is still
    the file's own layout that lands in slot 10.
    """
    from purepdb.dbi import _HEADER
    from purepdb.msf import MsfFile

    msf = MsfFile(data)
    streams = [msf.read_stream(i) if msf.is_valid_stream(i) else b""
               for i in range(msf.num_streams)]

    original = PDB.from_bytes(data)
    sections = b"".join(
        section_header(s.name, s.virtual_address, s.virtual_size,
                       characteristics=s.characteristics)
        for s in original.sections
    )
    omap_index, orig_index = len(streams), len(streams) + 1
    streams.append(omap_stream([(0, delta)]))
    streams.append(sections)

    dbi = bytearray(streams[3])
    header = _HEADER.unpack_from(dbi, 0)
    base = (_HEADER.size + header[9] + header[10] + header[11] + header[12]
            + header[13] + header[16])
    struct.pack_into("<H", dbi, base + 4 * 2, omap_index)
    struct.pack_into("<H", dbi, base + 10 * 2, orig_index)
    if not section_headers:
        struct.pack_into("<H", dbi, base + 5 * 2, 0xFFFF)
    streams[3] = bytes(dbi)

    return build_msf(streams)


def test_a_real_pdb_with_an_address_map_translates_every_function():
    """End to end on real linker output: every address moves by the map."""
    from pathlib import Path

    path = (Path(__file__).resolve().parent / "data" / "rustpe"
            / "rust_pe_symbols_msvc.pdb")
    if not path.exists():
        pytest.skip("groundtruth fixture missing: rustpe")
    data = path.read_bytes()

    delta = 0x0010_0000
    original = PDB.from_bytes(data)
    translated = PDB.from_bytes(_with_omap(data, delta))

    assert translated.omap is not None
    assert len(translated.omap) == 1
    assert translated.original_sections == original.sections

    before = {(f.segment, f.offset): f.rva for f in original.functions()}
    after = {(f.segment, f.offset): f.rva for f in translated.functions()}
    assert before, "expected functions to translate"
    assert all(rva is not None for rva in before.values())
    assert after == {key: rva + delta for key, rva in before.items()
                     if rva is not None}
    assert translated.diagnose().omap_entries == 1


def test_a_real_pdb_without_slot_5_reports_the_two_address_spaces():
    """The same, with slot 5 taken away: #39 in a real container.

    The synthetic cases above build the table shape from scratch; this one
    reaches it from real linker output, so the divergence is measured between a
    function's actual address and the file's actual section table rather than
    between two tables of our own.
    """
    from pathlib import Path

    path = (Path(__file__).resolve().parent / "data" / "rustpe"
            / "rust_pe_symbols_msvc.pdb")
    if not path.exists():
        pytest.skip("groundtruth fixture missing: rustpe")
    data = path.read_bytes()

    delta = 0x0010_0000
    original = PDB.from_bytes(data)
    stripped = PDB.from_bytes(_with_omap(data, delta, section_headers=False))

    # Every rva is final, and the only table left to show is the space the map
    # translated out of -- a whole `delta` away from where the symbols are.
    assert stripped.sections == []
    assert stripped.derived_sections == []
    assert stripped.original_sections == original.sections
    before = {(f.segment, f.offset): f.rva for f in original.functions()}
    assert before, "expected functions to translate"
    assert {(f.segment, f.offset): f.rva for f in stripped.functions()} == \
        {key: rva + delta for key, rva in before.items() if rva is not None}

    d = stripped.diagnose()
    assert (d.has_original_sections, d.omap_entries, d.has_section_headers) \
        == (True, 1, False)
    assert any("not comparable" in w for w in d.warnings), d.warnings
