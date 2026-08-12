"""Inlined functions: bodies the compiler pasted into other functions.

An inlined body has no entry point, so it has no procedure record and no
public, and `functions()` cannot see it by construction. On the rust fixture
there are fifteen inline sites for every procedure record.

Two things have to be right for one to be recoverable: the name, which exists
only in the IPI stream and is referenced by item id, and the code it occupies,
which is a compressed annotation stream giving offsets from the start of the
enclosing procedure.
"""

import struct

import pytest

from purepdb import PDB, codeview
from purepdb.ipi import IdTable
from tests._synth import (
    build_msf,
    dbi_stream,
    gproc32,
    inline_site,
    ipi_stream,
    module_info,
    module_sym_stream,
    publics_hash_stream,
    section_header,
)

# --- the id stream ----------------------------------------------------------

def test_item_ids_are_positional():
    """Record n is index_begin + n, whether or not it is a kind we decode."""
    table = IdTable.parse(ipi_stream([
        ("func", "first"), ("other", None), ("func", "third"),
    ]))
    assert table is not None
    assert table.get(0x1000) == "first"
    assert table.get(0x1001) is None, "an undecoded kind still consumes an index"
    assert table.get(0x1002) == "third"


def test_member_function_and_string_ids_are_named_too():
    table = IdTable.parse(ipi_stream([
        ("mfunc", "method"), ("string", "C:\\src\\main.rs"),
    ]))
    assert table.get(0x1000) == "method"
    assert table.get(0x1001) == "C:\\src\\main.rs"


def test_a_stream_too_small_or_mislabelled_is_rejected():
    assert IdTable.parse(b"") is None
    assert IdTable.parse(b"\x00" * 40) is None
    # A header claiming to be larger than the stream.
    broken = bytearray(ipi_stream([("func", "x")]))
    struct.pack_into("<I", broken, 4, 0xFFFF)
    assert IdTable.parse(bytes(broken)) is None


def test_an_id_record_too_short_for_its_kind_is_skipped_not_raised():
    """Two fixed uint32s are read before the name.

    A record whose payload does not hold them used to raise EOFError out
    of `IdTable.parse`, and so out of the public `PDB.inline_sites()`.
    """
    good = ipi_stream([("func", "helper")])
    short = struct.pack("<HH", 6, 0x1601) + b"\x01\x00\x00\x00"
    data = bytearray(good[:56] + short + good[56:])
    struct.pack_into("<I", data, 16, len(good) - 56 + len(short))

    table = IdTable.parse(bytes(data))
    assert table is not None
    assert table.get(0x1000) is None, "the short record still consumes an index"
    assert table.get(0x1001) == "helper"


def test_an_unknown_item_id_answers_none():
    table = IdTable.parse(ipi_stream([("func", "only")]))
    assert table.get(0x9999) is None


# --- binary annotations -----------------------------------------------------

def _ranges(annotations: bytes):
    payload = struct.pack("<III", 0, 0, 0x1000) + annotations
    return codeview.parse_inline_site(payload).ranges


def test_a_single_range():
    # ChangeCodeOffsetAndLineOffset(+4), ChangeCodeLength(3).
    assert _ranges(bytes([0x0B, 0x04, 0x04, 0x03])) == [(4, 3)]


def test_a_length_moves_the_cursor_past_the_range_it_closes():
    """The next offset delta is measured from the end of the last range, not
    from its start. Getting this wrong shifts every range after the first."""
    annotations = bytes([0x03, 0x80, 0xE1,   # ChangeCodeOffset(225)
                         0x04, 0x05,         # ChangeCodeLength(5)   -> 225..230
                         0x0B, 0x04,         # +4 from 230           -> 234
                         0x04, 0x0C])        # ChangeCodeLength(12)  -> 234..246
    assert _ranges(annotations) == [(225, 5), (234, 12)]


@pytest.mark.parametrize("encoded,value", [
    (bytes([0x7F]), 0x7F),                          # one byte
    (bytes([0x80, 0xE1]), 0xE1),                    # two bytes
    (bytes([0xC0, 0x00, 0x12, 0x34]), 0x1234),      # four bytes
])
def test_compressed_operands_of_every_width(encoded, value):
    assert _ranges(bytes([0x03]) + encoded + bytes([0x04, 0x00])) == [(value, 0)]


def test_the_invalid_opcode_ends_the_walk():
    annotations = bytes([0x0B, 0x04, 0x04, 0x03, 0x00, 0x00, 0x00])
    assert _ranges(annotations) == [(4, 3)]


def test_an_undecodable_operand_keeps_what_was_read():
    """The 4th compression encoding is undefined, and operand widths are what
    keep the stream in step -- so stop, but do not throw away the ranges."""
    annotations = bytes([0x0B, 0x04, 0x04, 0x03, 0x03, 0xFF])
    assert _ranges(annotations) == [(4, 3)]


def test_a_rebase_opcode_ends_the_walk_rather_than_guessing():
    """CHANGE_CODE_OFFSET_BASE rebases the cursor instead of advancing it.

    Nothing in the corpus emits it, so the rebase is unverified -- and every
    range after it would be measured from a base we never applied. The ranges
    found before it are real and are kept.
    """
    annotations = bytes([0x0B, 0x04, 0x04, 0x03,   # -> range (4, 3)
                         0x02, 0x40,               # ChangeCodeOffsetBase(0x40)
                         0x04, 0x08])              # would have closed a range
    assert _ranges(annotations) == [(4, 3)]


def test_a_truncated_annotation_stream_does_not_raise():
    assert _ranges(bytes([0x03])) == []
    assert _ranges(b"") == []


def test_length_and_offset_in_one_opcode():
    # ChangeCodeLengthAndCodeOffset takes two operands: length, then offset.
    assert _ranges(bytes([0x0C, 0x08, 0x10])) == [(0x10, 8)]


# --- end to end -------------------------------------------------------------

def _pdb(*, module_records, ipi=b""):
    module_syms = module_sym_stream(module_records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=6, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [8]),
        ipi,
        module_syms,
        publics_hash_stream([]),
        b"",
        section_header(".text", 0x1000, 0x10000),
    ]
    return PDB.from_bytes(build_msf(streams))


def _proc_with_sites(sites: bytes, code_size=0x100, offset=0x40):
    """A procedure whose scope contains `sites`, closed by S_END."""
    from tests._synth import make_record

    proc = gproc32("outer", 1, offset, code_size=code_size)
    end = make_record(codeview.S_END, b"")
    # The proc's End field is the offset of that S_END in the stream as stored:
    # 4 for the signature, plus the proc and everything inside it.
    end_offset = 4 + len(proc) + len(sites)
    patched = proc[:8] + struct.pack("<I", end_offset) + proc[12:]
    return patched + sites + end


def test_an_inline_site_is_named_and_placed():
    sites = inline_site(inlinee=0x1000, annotations=bytes([0x0B, 0x04, 0x04, 0x03]))
    pdb = _pdb(module_records=_proc_with_sites(sites),
               ipi=ipi_stream([("func", "helper")]))

    found = pdb.inline_sites()
    assert len(found) == 1
    site = found[0]
    assert site.name == "helper"
    assert site.parent == "outer"
    # Offsets are relative to the procedure, which starts at 0x40.
    assert site.ranges == [(0x44, 3)]
    assert site.offset == 0x44
    assert site.rva == 0x1044
    assert site.code_size == 3


def test_several_sites_in_one_procedure():
    sites = (inline_site(inlinee=0x1000, annotations=bytes([0x0B, 0x04, 0x04, 0x03]))
             + inline_site(inlinee=0x1001, annotations=bytes([0x03, 0x20, 0x04, 0x08])))
    pdb = _pdb(module_records=_proc_with_sites(sites),
               ipi=ipi_stream([("func", "first"), ("func", "second")]))
    assert [(s.name, s.ranges) for s in pdb.inline_sites()] == [
        ("first", [(0x44, 3)]), ("second", [(0x60, 8)]),
    ]


def test_a_site_outside_any_procedure_scope_is_skipped():
    """A record past the procedure's End belongs to nothing we can place."""
    from tests._synth import make_record

    proc = gproc32("outer", 1, 0x40)
    patched = proc[:8] + struct.pack("<I", 4 + len(proc)) + proc[12:]
    stray = inline_site(inlinee=0x1000, annotations=bytes([0x0B, 0x04, 0x04, 0x03]))
    pdb = _pdb(module_records=patched + make_record(codeview.S_END, b"") + stray,
               ipi=ipi_stream([("func", "helper")]))
    assert pdb.inline_sites() == []


def test_sites_are_located_even_without_an_id_stream():
    """No IPI means no names, which is not a reason to lose the addresses."""
    sites = inline_site(inlinee=0x1000, annotations=bytes([0x0B, 0x04, 0x04, 0x03]))
    pdb = _pdb(module_records=_proc_with_sites(sites))
    found = pdb.inline_sites()
    assert len(found) == 1
    assert found[0].name == ""
    assert found[0].rva == 0x1044


def test_a_record_too_short_for_its_kind_is_skipped_not_raised():
    """RecordLen is the record's own claim; a short one hands a truncated
    payload to a parser expecting the three fixed uint32s."""
    short = struct.pack("<HH", 2, codeview.S_INLINESITE)
    good = inline_site(inlinee=0x1000, annotations=bytes([0x0B, 0x04, 0x04, 0x03]))
    assert len(codeview.extract_inline_sites(short + good)) == 1

    pdb = _pdb(module_records=_proc_with_sites(short + good),
               ipi=ipi_stream([("func", "helper")]))
    assert [s.name for s in pdb.inline_sites()] == ["helper"]


def test_a_site_covering_no_code_is_not_reported():
    sites = inline_site(inlinee=0x1000, annotations=b"")
    pdb = _pdb(module_records=_proc_with_sites(sites),
               ipi=ipi_stream([("func", "helper")]))
    assert pdb.inline_sites() == []


def test_inlined_bodies_stay_out_of_the_function_list():
    sites = inline_site(inlinee=0x1000, annotations=bytes([0x0B, 0x04, 0x04, 0x03]))
    pdb = _pdb(module_records=_proc_with_sites(sites),
               ipi=ipi_stream([("func", "helper")]))
    assert [f.name for f in pdb.functions()] == ["outer"]


# --- against real compiler output -------------------------------------------

def _open(rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    return PDB.open(str(path))


def test_the_rust_fixture_is_where_the_coverage_gap_is():
    pdb = _open("rustpe/rust_pe_symbols_msvc.pdb")
    sites = pdb.inline_sites()

    assert len(sites) == 3797
    assert len(pdb.module_procs()) == 248
    assert pdb.diagnose().inline_sites == 3797
    assert all(s.name for s in sites), "every inlinee must resolve to a name"
    assert len({s.name for s in sites}) == 485
    assert {"drop_glue", "call_once", "black_box"} <= {s.name for s in sites}


def test_every_inlined_range_lies_inside_its_parent_procedure():
    """The check that the annotation cursor is being tracked correctly.

    Offsets are relative to the enclosing procedure, so an error in the walk
    puts a range outside the function that contains it.
    """
    pdb = _open("rustpe/rust_pe_symbols_msvc.pdb")

    checked = 0
    for site in pdb.inline_sites():
        start, end = site.parent_offset, site.parent_offset + site.parent_code_size
        for offset, length in site.ranges:
            assert start <= offset and offset + length <= end, (
                f"{site.name} at {offset:#x}+{length:#x} is outside "
                f"{site.parent} [{start:#x},{end:#x})")
            checked += 1
    assert checked == 5281


def test_every_inlined_range_lands_in_executable_code():
    pdb = _open("rustpe/rust_pe_symbols_msvc.pdb")
    for site in pdb.inline_sites():
        section = pdb.sections[site.segment - 1]
        assert section.executable
        for offset, length in site.ranges:
            assert offset < section.virtual_size
            assert offset + length <= section.virtual_size


def test_inline_sites_are_recovered_at_32_bits():
    """The i686 fixture, where `hash_round` and `mix_pair` are inlined.

    Nothing else in the corpus carries inline sites on a 32-bit target, so
    without this the annotation walk is only ever exercised at x86_64.
    """
    pdb = _open("rustpe32/rust_pe_symbols_i686.pdb")
    sites = pdb.inline_sites()

    assert len(sites) == 13
    assert pdb.diagnose().inline_sites == 13
    assert sum(len(s.ranges) for s in sites) == 60
    assert {s.name for s in sites} >= {"hash_round", "mix_pair"}
    for site in sites:
        start = site.parent_offset
        end = start + site.parent_code_size
        for offset, length in site.ranges:
            assert start <= offset and offset + length <= end, site.name


@pytest.mark.parametrize("rel", ["sqlite/x86/sqlite3.pdb", "sqlite/x64/sqlite3.pdb"])
def test_a_pdb_without_inlining_reports_none(rel):
    pdb = _open(rel)
    assert pdb.inline_sites() == []
    assert pdb.diagnose().inline_sites == 0
    assert pdb.id_table() is not None, "the id stream is there, just unreferenced"


def test_an_opcode_outside_the_defined_range_ends_the_walk():
    """Operand widths are what split the stream into instructions, so an
    unknown opcode makes everything after it unreadable. Consuming one operand
    and carrying on resynchronises on whatever follows and invents ranges:
    `0e 63 04 03` used to come back as [(0, 3)]."""
    assert _ranges(bytes([0x0E, 0x63, 0x04, 0x03])) == []

    # What comes before an unknown opcode is still real and is kept.
    assert _ranges(bytes([0x0B, 0x04, 0x04, 0x03, 0x0E, 0x63, 0x04, 0x03])) == [(4, 3)]
