"""Named streams, the `/names` string table, and RVA -> file:line.

Two layers, in the order the issue splits them. The named stream map at the end
of the PDB Info stream is what makes `/names` findable, `/names` is what turns a
string offset into a path, and the C13 subsections at the tail of each module
stream are what tie a path and a line number to an address.
"""

import struct

import pytest

from purepdb import PDB, c13
from purepdb.names import StringTable, parse_named_stream_map
from tests._synth import (
    build_msf,
    dbi_stream,
    file_checksums,
    gproc32,
    line_entries,
    module_info,
    module_sym_stream,
    names_stream,
    pdb_info_stream,
    publics_hash_stream,
    section_header,
    subsection,
)

# --- named stream map -------------------------------------------------------

def test_the_named_stream_map_is_read():
    data = pdb_info_stream({"/names": 5, "/LinkInfo": 8})
    assert parse_named_stream_map(data) == {"/names": 5, "/LinkInfo": 8}


def test_an_empty_map_is_not_an_error():
    assert parse_named_stream_map(pdb_info_stream({})) == {}


def test_a_truncated_map_yields_nothing_rather_than_raising():
    data = pdb_info_stream({"/names": 5})
    assert parse_named_stream_map(data[:-4]) == {}
    assert parse_named_stream_map(b"\x00" * 28) == {}


# --- /names -----------------------------------------------------------------

def test_the_string_table_reads_by_offset():
    raw, offsets = names_stream(["", "main.c", "other.c"])
    table = StringTable.parse(raw)
    assert table is not None
    assert table.get(offsets["main.c"]) == "main.c"
    assert table.get(offsets["other.c"]) == "other.c"


def test_an_offset_past_the_strings_answers_none():
    raw, _ = names_stream(["", "main.c"])
    table = StringTable.parse(raw)
    assert table.get(9999) is None
    assert table.get(-1) is None


def test_a_stream_that_is_not_a_string_table_is_rejected():
    assert StringTable.parse(b"") is None
    assert StringTable.parse(struct.pack("<III", 0xDEADBEEF, 1, 0)) is None
    # A signature we know with a hash version we do not.
    assert StringTable.parse(struct.pack("<III", 0xEFFEEFFE, 99, 0)) is None


# --- C13 subsections --------------------------------------------------------

def test_subsections_are_walked_by_length():
    data = (subsection(c13.DEBUG_S_FILECHECKSUMS, b"\x01\x02\x03")
            + subsection(c13.DEBUG_S_LINES, b"\x04" * 8))
    kinds = [(s.kind, len(s.payload)) for s in c13.iter_subsections(data)]
    assert kinds == [(c13.DEBUG_S_FILECHECKSUMS, 3), (c13.DEBUG_S_LINES, 8)]


def test_a_length_past_the_end_stops_the_walk():
    data = subsection(c13.DEBUG_S_LINES, b"\x00" * 4) + struct.pack("<II", 0xF2, 0x1000)
    assert len(list(c13.iter_subsections(data))) == 1


def test_a_subsection_marked_ignore_is_stepped_over():
    """`cvinfo.h`: "if this bit is set in a subsection type then ignore the
    subsection contents". Masking it off instead would turn a deliberately
    excluded DEBUG_S_LINES block into a live one."""
    ignored = subsection(c13.DEBUG_S_LINES | c13.DEBUG_S_IGNORE, b"\x00" * 4)
    live = subsection(c13.DEBUG_S_FILECHECKSUMS, b"\x01" * 4)

    assert list(c13.iter_subsections(ignored)) == []
    # ...and the walk still advances over it to reach what follows.
    assert [s.kind for s in c13.iter_subsections(ignored + live)] == [
        c13.DEBUG_S_FILECHECKSUMS
    ]


def test_lines_from_an_ignored_subsection_are_not_reported():
    raw_names, offsets = names_stream(["", "main.c"])
    checksums, entry_offsets = file_checksums([(offsets["main.c"], b"")])
    region = (subsection(c13.DEBUG_S_FILECHECKSUMS, checksums)
              + subsection(c13.DEBUG_S_LINES | c13.DEBUG_S_IGNORE,
                           line_entries(segment=1, base_offset=0x10,
                                        file_entry=entry_offsets[0],
                                        entries=[(0, 7, True)])))
    pdb = _pdb(c13_region=region, raw_names=raw_names)
    assert list(pdb.lines()) == []


def test_file_checksum_entries_are_keyed_by_their_own_offset():
    """A line block names a file by the byte offset of its checksum entry."""
    payload, offsets = file_checksums([(0x10, b""), (0x40, b"\xaa" * 16)])
    table = c13.parse_file_checksums(payload)
    assert table[offsets[0]] == 0x10
    assert table[offsets[1]] == 0x40


def test_line_entries_unpack_the_packed_word():
    payload = line_entries(segment=1, base_offset=0x100, file_entry=0,
                           entries=[(0x00, 10, True), (0x20, 4000, False)])
    lines = c13.parse_lines(payload)
    assert [(e.offset, e.line, e.is_statement) for e in lines] == [
        (0x100, 10, True), (0x120, 4000, False),
    ]
    assert all(e.segment == 1 for e in lines)


def test_a_block_claiming_more_lines_than_it_holds_is_dropped():
    payload = line_entries(segment=1, base_offset=0, file_entry=0,
                           entries=[(0, 1, True)])
    # Say there are 50 lines in a block that holds one.
    broken = payload[:16] + struct.pack("<I", 50) + payload[20:]
    assert c13.parse_lines(broken) == []


def test_a_zero_block_size_does_not_spin():
    payload = line_entries(segment=1, base_offset=0, file_entry=0,
                           entries=[(0, 1, True)])
    broken = payload[:20] + struct.pack("<I", 0) + payload[24:]
    assert len(c13.parse_lines(broken)) == 1


# --- end to end -------------------------------------------------------------

def _pdb(*, c13_region=b"", raw_names=b"", name_streams=None):
    symbols = gproc32("main", 1, 0x10)
    module_stream = module_sym_stream(symbols) + c13_region
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=4 + len(symbols),
                       c13_byte_size=len(c13_region))
    streams = [
        b"",
        pdb_info_stream({"/names": 7} if name_streams is None else name_streams),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=8, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]),
        module_stream,
        section_header(".text", 0x1000, 0x10000),
        raw_names,
        b"",
    ]
    return PDB.from_bytes(build_msf(streams))


def test_lines_resolve_to_file_and_rva():
    raw_names, offsets = names_stream(["", "main.c"])
    checksums, entry_offsets = file_checksums([(offsets["main.c"], b"")])
    region = (subsection(c13.DEBUG_S_FILECHECKSUMS, checksums)
              + subsection(c13.DEBUG_S_LINES,
                           line_entries(segment=1, base_offset=0x10,
                                        file_entry=entry_offsets[0],
                                        entries=[(0, 7, True), (0x10, 8, True)])))
    pdb = _pdb(c13_region=region, raw_names=raw_names)

    assert [(line.rva, line.file, line.line) for line in pdb.lines()] == [
        (0x1010, "main.c", 7), (0x1020, "main.c", 8),
    ]


def test_lines_are_empty_without_a_names_stream():
    """No file names to resolve against is an ordinary shape, not an error."""
    raw_names, offsets = names_stream(["", "main.c"])
    checksums, entry_offsets = file_checksums([(offsets["main.c"], b"")])
    region = (subsection(c13.DEBUG_S_FILECHECKSUMS, checksums)
              + subsection(c13.DEBUG_S_LINES,
                           line_entries(segment=1, base_offset=0x10,
                                        file_entry=entry_offsets[0],
                                        entries=[(0, 7, True)])))
    pdb = _pdb(c13_region=region, raw_names=raw_names,
               name_streams={"/LinkInfo": 8})

    assert pdb.string_table() is None
    assert list(pdb.lines()) == []


def test_lines_are_empty_without_c13_data():
    pdb = _pdb(raw_names=names_stream(["", "main.c"])[0])
    assert list(pdb.lines()) == []


def test_a_line_block_naming_an_unknown_file_is_skipped():
    raw_names, offsets = names_stream(["", "main.c"])
    checksums, _ = file_checksums([(offsets["main.c"], b"")])
    region = (subsection(c13.DEBUG_S_FILECHECKSUMS, checksums)
              + subsection(c13.DEBUG_S_LINES,
                           line_entries(segment=1, base_offset=0, file_entry=0x999,
                                        entries=[(0, 7, True)])))
    pdb = _pdb(c13_region=region, raw_names=raw_names)
    assert list(pdb.lines()) == []


def test_the_marker_line_numbers_are_reported_but_flagged():
    raw_names, offsets = names_stream(["", "main.c"])
    checksums, entry_offsets = file_checksums([(offsets["main.c"], b"")])
    region = (subsection(c13.DEBUG_S_FILECHECKSUMS, checksums)
              + subsection(c13.DEBUG_S_LINES,
                           line_entries(segment=1, base_offset=0,
                                        file_entry=entry_offsets[0],
                                        entries=[(0, 12, True),
                                                 (0x8, c13.LINE_COMPILER_GENERATED, True)])))
    pdb = _pdb(c13_region=region, raw_names=raw_names)
    lines = list(pdb.lines())
    assert [line.is_source for line in lines] == [True, False]


# --- against real linker output ---------------------------------------------

def _open(rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    return PDB.open(str(path))


@pytest.mark.parametrize("rel,names_index", [
    pytest.param("sqlite/x86/sqlite3.pdb", 5, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 5, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 21, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 14, id="rustpe-i686"),
])
def test_real_pdbs_expose_names_through_the_map(rel, names_index):
    pdb = _open(rel)
    streams = pdb.named_streams()
    assert streams.get("/names") == names_index
    assert "/LinkInfo" in streams
    assert pdb.string_table() is not None


@pytest.mark.parametrize("rel,n_lines,n_files,n_markers", [
    pytest.param("sqlite/x86/sqlite3.pdb", 70157, 133, 3, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 69834, 124, 3, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 1807, 73, 0, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 7, 1, 0, id="rustpe-i686"),
])
def test_real_line_counts_are_stable(rel, n_lines, n_files, n_markers):
    pdb = _open(rel)
    lines = list(pdb.lines())
    assert len(lines) == n_lines
    assert len({line.file for line in lines}) == n_files
    assert sum(1 for line in lines if not line.is_source) == n_markers
    assert all(line.rva is not None for line in lines)


@pytest.mark.parametrize("rel", [
    "sqlite/x86/sqlite3.pdb", "sqlite/x64/sqlite3.pdb",
    "rustpe/rust_pe_symbols_msvc.pdb", "rustpe32/rust_pe_symbols_i686.pdb",
])
def test_every_line_lands_in_the_section_it_names(rel):
    pdb = _open(rel)
    for line in pdb.lines():
        section = pdb.sections[line.segment - 1]
        assert section.virtual_address <= line.rva
        assert line.rva < section.virtual_address + section.virtual_size


def test_known_triples_in_sqlite():
    """Pin a handful of (rva, file, line) against the layout the PDB records.

    These are the first entries of `rtree.c`'s first line block, which
    `llvm-pdbutil dump -l` reports at the same addresses.
    """
    pdb = _open("sqlite/x86/sqlite3.pdb")
    rtree = [line for line in pdb.lines() if line.file.endswith("rtree.c")]
    assert rtree

    first = [(line.rva, line.line) for line in rtree[:5]]
    assert first == [(0x303D0, 2224), (0x303E0, 2225), (0x303E6, 2226),
                     (0x303ED, 2227), (0x303F9, 2228)]


def test_a_functions_entry_point_has_a_line_at_the_same_address():
    """The two paths meet: an entry point purepdb found is where a line starts."""
    pdb = _open("sqlite/x86/sqlite3.pdb")
    line_at = {(line.segment, line.offset) for line in pdb.lines()}
    procs = [f for f in pdb.functions() if f.source == "proc"]
    covered = sum(1 for f in procs if (f.segment, f.offset) in line_at)
    assert covered > len(procs) // 2, (
        f"only {covered} of {len(procs)} proc entry points start a line")
