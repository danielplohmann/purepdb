"""DBI's Section Map, and the RVA fallback it makes possible.

Without the section-header stream (Optional Debug Header slot 5) there was no
way to turn `segment:offset` into an address, and every `Function.rva` came
back None. The Section Map describes the same segments -- flags and length, in
image order -- but records no addresses at all: `Offset` is 0 for every entry
in every fixture. So the layout has to be rebuilt.

The rule that rebuilds it is checked here against the three fixtures, which
carry both the Section Map *and* the real section headers: the reconstruction
must reproduce the real addresses exactly. That is the evidence, since no
fixture actually lacks slot 5 -- see issue #9 -- except
``rustpe32/rust_pe_symbols_i686_no_slot5.pdb``, which is checked the same way
via ``test_groundtruth.py``.
"""

import struct

import pytest

from purepdb import PDB
from purepdb.sections import (
    SEG_EXECUTE,
    SEG_IS_ABSOLUTE,
    SEG_READ,
    SEG_WRITE,
    parse_section_map,
    sections_from_map,
)
from tests._synth import (
    build_msf,
    dbi_stream,
    gproc32,
    module_info,
    module_sym_stream,
    pub32,
    publics_hash_stream,
    record_offsets,
    section_header,
    section_map,
)


def test_the_substream_is_parsed():
    data = section_map([
        (SEG_READ | SEG_EXECUTE, 1, 0x1000),
        (SEG_READ | SEG_WRITE, 2, 0x800),
        (SEG_IS_ABSOLUTE, 0, 0xFFFFFFFF),
    ])
    entries = parse_section_map(data)
    assert [(e.frame, e.length) for e in entries] == [
        (1, 0x1000), (2, 0x800), (0, 0xFFFFFFFF),
    ]
    assert entries[0].executable
    assert not entries[1].executable
    assert entries[2].is_absolute


def test_a_count_larger_than_the_substream_does_not_read_past_it():
    data = section_map([(SEG_READ, 1, 0x1000)])
    truncated = struct.pack("<HH", 9, 9) + data[4:]
    assert len(parse_section_map(truncated)) == 1


def test_an_empty_substream_yields_nothing():
    assert parse_section_map(b"") == []
    assert parse_section_map(b"\x00\x00") == []


def test_segments_are_laid_out_at_the_alignment_boundary():
    entries = parse_section_map(section_map([
        (SEG_READ | SEG_EXECUTE, 1, 0x1800),   # spans two pages
        (SEG_READ, 2, 0x10),                   # spans one
        (SEG_READ | SEG_WRITE, 3, 0x1000),     # exactly one
        (SEG_IS_ABSOLUTE, 0, 0xFFFFFFFF),
    ]))
    sections = sections_from_map(entries)

    assert [(s.name, s.virtual_address, s.virtual_size) for s in sections] == [
        ("seg1", 0x1000, 0x1800),
        ("seg2", 0x3000, 0x10),
        ("seg3", 0x4000, 0x1000),
    ]
    assert sections[0].executable
    assert not sections[2].executable


def test_non_contiguous_frames_are_refused_rather_than_shifted():
    """A symbol's segment is resolved by position in the rebuilt list.

    A map whose real segments are not numbered 1..n would put every section
    after the gap at the wrong index, so every address past it would resolve
    to a plausible but wrong value. No reconstruction is the honest answer.
    """
    entries = parse_section_map(section_map([
        (SEG_READ | SEG_EXECUTE, 1, 0x1000),
        (SEG_READ, 3, 0x1000),                 # frame 2 is missing
        (SEG_IS_ABSOLUTE, 0, 0xFFFFFFFF),
    ]))
    assert sections_from_map(entries) == []


def test_the_absolute_segment_is_not_laid_out():
    """Its length is 0xFFFFFFFF; treating it as a segment would consume the
    whole address space."""
    entries = parse_section_map(section_map([
        (SEG_IS_ABSOLUTE, 0, 0xFFFFFFFF),
        (SEG_READ, 1, 0x1000),
    ]))
    assert [s.virtual_address for s in sections_from_map(entries)] == [0x1000]


def _pdb(*, sections=(), sec_map=b"", records=(), publics=()):
    module_syms = module_sym_stream(b"".join(records))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + ([6] if sections else [0xFFFF]),
                   sec_map=sec_map),
        publics_hash_stream(record_offsets(list(publics))),
        module_syms,
        b"".join(sections),
        b"".join(publics),
    ]
    return PDB.from_bytes(build_msf(streams))


MAP = section_map([
    (SEG_READ | SEG_EXECUTE, 1, 0x1500),
    (SEG_READ | SEG_WRITE, 2, 0x200),
    (SEG_IS_ABSOLUTE, 0, 0xFFFFFFFF),
])


def test_addresses_resolve_without_the_section_header_stream():
    pdb = _pdb(sec_map=MAP, records=[gproc32("main", 1, 0x40)])

    assert pdb.sections == [], "the image's own headers are still absent"
    assert [s.virtual_address for s in pdb.derived_sections] == [0x1000, 0x3000]
    assert pdb.functions()[0].rva == 0x1040


def test_the_section_header_stream_still_wins_when_present():
    pdb = _pdb(sections=[section_header(".text", 0x400000)], sec_map=MAP,
               records=[gproc32("main", 1, 0x40)])
    assert pdb.derived_sections == [], "no need to reconstruct what we have"
    assert pdb.functions()[0].rva == 0x400040


def test_code_publics_are_recognised_through_the_rebuilt_table():
    """The executable flag survives the rebuild, so the `code_publics` rule
    still works on a PDB with no section headers."""
    pdb = _pdb(sec_map=MAP, publics=[pub32("fn", 1, 0x10, flags=0),
                                     pub32("var", 2, 0x10, flags=0)])
    assert [(f.name, f.rva) for f in pdb.functions()] == [("fn", 0x1010)]


def test_a_present_but_empty_section_header_stream_is_treated_as_absent():
    """Slot 5 can name a stream that exists and holds nothing.

    That parses into a table which is perfectly valid and describes no
    sections, so it resolves nothing -- and it used to suppress this
    fallback, leaving every rva None while `diagnose()` reported a
    section-header table that was there.
    """
    module_syms = module_sym_stream(gproc32("main", 1, 0x40))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6], sec_map=MAP),
        publics_hash_stream([]), module_syms, b"", b"",
    ]
    pdb = PDB.from_bytes(build_msf(streams))

    d = pdb.diagnose()
    assert not d.has_section_headers
    assert d.derived_sections == 2
    assert pdb.functions()[0].rva == 0x1040
    assert any("Section Map" in w for w in d.warnings)


def test_with_neither_source_every_rva_is_still_none():
    pdb = _pdb(records=[gproc32("main", 1, 0x40)])
    assert pdb.functions()[0].rva is None
    assert any("cannot be resolved" in w for w in pdb.diagnose().warnings)


def test_diagnose_says_the_addresses_are_reconstructed():
    pdb = _pdb(sec_map=MAP, records=[gproc32("main", 1, 0x40)],
               publics=[pub32("main", 1, 0x40)])
    d = pdb.diagnose()

    assert not d.has_section_headers
    assert d.derived_sections == 2
    warning = "\n".join(d.warnings)
    assert "rebuilt from DBI's Section Map" in warning
    assert "reconstruction" in warning


def test_cli_diagnose_reports_the_rebuilt_segments(tmp_path, capsys):
    from purepdb.__main__ import main

    module_syms = module_sym_stream(gproc32("main", 1, 0x40))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 6, sec_map=MAP),
        publics_hash_stream([]), module_syms, b"", pub32("main", 1, 0x40),
    ]
    path = tmp_path / "nosections.pdb"
    path.write_bytes(build_msf(streams))
    assert main(["purepdb", "diagnose", str(path)]) == 0
    assert "derived segments   : 2" in capsys.readouterr().out


# --- against real linker output ---------------------------------------------

def _without_section_headers(data: bytes) -> bytes:
    """The same PDB with Optional Debug Header slot 5 cleared.

    No fixture actually lacks the section-header stream (issue #9), and this is
    the next best thing: take one that has it and take it away, so the fallback
    runs against real linker output rather than against a builder of our own.
    The slot is a uint16 at a computed offset in the DBI stream, which the MSF
    block list maps back to a file offset.
    """
    from purepdb.dbi import _HEADER, DBG_SECTION_HDR
    from purepdb.msf import MsfFile

    msf = MsfFile(data)
    header = _HEADER.unpack_from(msf.read_stream(3), 0)
    (modinfo, seccontrib, secmap, srcinfo, tsmap) = header[9:14]
    ec = header[16]
    offset = (_HEADER.size + modinfo + seccontrib + secmap + srcinfo + tsmap
              + ec + DBG_SECTION_HDR * 2)

    block_size = msf.super.block_size
    block = msf.stream_blocks[3][offset // block_size]
    file_offset = block * block_size + offset % block_size

    out = bytearray(data)
    assert struct.unpack_from("<H", out, file_offset)[0] == \
        PDB.from_bytes(data).dbi.section_header_stream, "located the wrong slot"
    struct.pack_into("<H", out, file_offset, 0xFFFF)
    return bytes(out)


@pytest.mark.parametrize("rel", [
    "sqlite/x86/sqlite3.pdb", "sqlite/x64/sqlite3.pdb",
    "rustpe/rust_pe_symbols_msvc.pdb", "rustpe32/rust_pe_symbols_i686.pdb",
    "tls/tls_symbols.pdb",
])
def test_real_pdbs_keep_every_address_without_the_section_headers(rel):
    """The end-to-end check the fallback exists for.

    Every function must come back at the address it had before, resolved
    entirely from the Section Map -- not merely a plausible address, the same
    one. This is what a fixture missing slot 5 would test; taking the slot away
    from a real PDB tests it without one.
    """
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    data = path.read_bytes()

    original = PDB.from_bytes(data)
    stripped = PDB.from_bytes(_without_section_headers(data))

    assert not stripped.diagnose().has_section_headers
    assert stripped.sections == []
    assert len(stripped.derived_sections) == len(original.sections)

    assert original.functions(), "the fixture must have functions to compare"
    before = {(f.segment, f.offset): f.rva for f in original.functions()}
    after = {(f.segment, f.offset): f.rva for f in stripped.functions()}
    assert before == after
    assert all(rva is not None for rva in after.values())


@pytest.mark.parametrize("rel", [
    "rustpe32/rust_pe_symbols_i686_no_slot5.pdb",
])
def test_fixture_without_section_headers_keeps_every_address(rel):
    """The committed rustpe32 fixture (issue #25)."""
    from pathlib import Path

    data_dir = Path(__file__).resolve().parent / "data"
    path = data_dir / rel
    source = data_dir / "rustpe32/rust_pe_symbols_i686.pdb"
    if not path.exists() or not source.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")

    original = PDB.from_bytes(source.read_bytes())
    stripped = PDB.open(str(path))

    assert not stripped.diagnose().has_section_headers
    assert stripped.sections == []
    assert len(stripped.derived_sections) == len(original.sections)

    assert original.functions(), "the fixture must have functions to compare"
    before = {(f.segment, f.offset): f.rva for f in original.functions()}
    after = {(f.segment, f.offset): f.rva for f in stripped.functions()}
    assert before == after
    assert all(rva is not None for rva in after.values())


@pytest.mark.parametrize("rel,n_entries", [
    pytest.param("sqlite/x86/sqlite3.pdb", 9, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 10, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 8, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 3, id="rustpe-i686"),
    pytest.param("tls/tls_symbols.pdb", 6, id="tls-x64"),
])
def test_the_rebuild_reproduces_the_real_section_table(rel, n_entries):
    """The evidence for the fallback, taken from files that do not need it.

    Every fixture carries both the Section Map and the real section headers,
    so the reconstruction can be checked against the answer. It has to match
    exactly -- address and size, segment for segment.
    """
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    pdb = PDB.open(str(path))

    entries = pdb.dbi.section_map
    assert len(entries) == n_entries
    assert entries[-1].is_absolute, "the map ends with the absolute segment"
    assert all(e.offset == 0 for e in entries), (
        "the Section Map records no addresses; that is why they are rebuilt")

    rebuilt = sections_from_map(entries)
    real = pdb.sections
    assert len(rebuilt) == len(real)
    for got, want in zip(rebuilt, real, strict=True):
        assert got.virtual_address == want.virtual_address, want.name
        assert got.virtual_size == want.virtual_size, want.name
        assert got.executable == want.executable, want.name
