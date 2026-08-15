"""S_CONSTANT and S_UDT: naming material already in the symbol-record stream.

Both were skipped. Neither needs a stream purepdb was not already reading, and
between them they carry a few hundred names per fixture -- enumerators, `const`
values, and the type names a consumer would otherwise have to demangle out of
symbols.
"""

import struct

import pytest

from purepdb import PDB, codeview
from purepdb.reader import Reader
from tests._synth import (
    build_msf,
    constant,
    dbi_stream,
    module_info,
    module_sym_stream,
    pub32,
    publics_hash_stream,
    section_header,
    udt,
)


@pytest.mark.parametrize("value", [
    0, 1, 0x7FFF,               # inline, below LF_NUMERIC
    0x8000, 0xFFFF,             # LF_USHORT
    -1, -0x8000,                # LF_CHAR / LF_SHORT
    0x1_0000, 0xFFFF_FFFF,      # LF_ULONG
    -0x8000_0000,               # LF_LONG
    0x8000_0000_0000_0000,      # LF_UQUADWORD
    -0x8000_0000_0000_0000,     # LF_QUADWORD
])
def test_numeric_leaves_round_trip(value):
    from tests._synth import numeric_leaf

    r = Reader(numeric_leaf(value))
    assert codeview.parse_numeric(r) == value
    assert r.eof(), "the whole leaf must be consumed"


def test_an_unknown_leaf_leaves_the_reader_where_it_started():
    """LF_REAL64 is not decoded. Its length is what is unknown, so the reader
    must not advance past a value it cannot size."""
    r = Reader(struct.pack("<Hd", 0x8006, 1.5))
    assert codeview.parse_numeric(r) is None
    assert r.pos == 0


def test_a_constant_is_decoded():
    c = codeview.extract_constants(constant("MAX_PATH", 260, type_index=0x74))
    assert len(c) == 1
    assert (c[0].name, c[0].value, c[0].type_index) == ("MAX_PATH", 260, 0x74)


def test_a_udt_is_decoded():
    u = codeview.extract_udts(udt("SYSTEM_INFO", type_index=0x1666))
    assert [(x.name, x.type_index) for x in u] == [("SYSTEM_INFO", 0x1666)]


def test_a_constant_with_an_undecodable_value_is_skipped_not_guessed():
    """The name follows the value, so an unsized value hides the name too."""
    real64 = struct.pack("<Hd", 0x8006, 1.5)
    data = (constant("BEFORE", 1)
            + constant("PI", 0, raw_value=real64)
            + constant("AFTER", 2))

    assert [c.name for c in codeview.extract_constants(data)] == ["BEFORE", "AFTER"]


def test_an_undecodable_constant_does_not_desynchronise_the_stream():
    """Each record's payload is bounded by its own length field, so a leaf we
    cannot read costs one record rather than everything after it."""
    real64 = struct.pack("<Hd", 0x8006, 1.5)
    data = constant("PI", 0, raw_value=real64) + udt("Widget") + pub32("f", 1, 0x10)

    assert codeview.extract_constants(data) == []
    assert [u.name for u in codeview.extract_udts(data)] == ["Widget"]
    assert [p.name for p in codeview.extract_publics(data)] == ["f"]


@pytest.mark.parametrize("kind", [codeview.S_CONSTANT, codeview.S_UDT])
@pytest.mark.parametrize("payload_len", [0, 4])
def test_a_record_too_short_for_its_kind_is_skipped_not_raised(kind, payload_len):
    """RecordLen is the record's own claim about its size. A short one hands a
    truncated payload to a parser expecting a whole one."""
    payload = b"\x41" * payload_len
    payload += b"\x00" * (-(4 + payload_len) % 4)
    short = struct.pack("<HH", 2 + len(payload), kind) + payload

    assert codeview.extract_constants(short + constant("K", 1)) == \
        codeview.extract_constants(constant("K", 1))
    assert codeview.extract_udts(short + udt("T")) == codeview.extract_udts(udt("T"))


def _pdb(symrecords: bytes):
    module_syms = module_sym_stream(b"")
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]),
        module_syms,
        section_header(".text", 0x1000),
        symrecords,
    ]
    return PDB.from_bytes(build_msf(streams))


def test_end_to_end_through_the_pdb_api():
    pdb = _pdb(constant("SEEK_END", 2) + udt("FILE") + constant("BUFSIZ", 512))
    assert [(c.name, c.value) for c in pdb.constants()] == [
        ("SEEK_END", 2), ("BUFSIZ", 512),
    ]
    assert [u.name for u in pdb.udts()] == ["FILE"]


def test_a_pdb_with_no_symbol_record_stream_answers_empty():
    module_syms = module_sym_stream(b"")
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=0xFFFF, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]), module_syms, section_header(".text", 0x1000),
    ]
    pdb = PDB.from_bytes(build_msf(streams))
    assert pdb.constants() == []
    assert pdb.udts() == []


# --- against real linker output ---------------------------------------------

@pytest.mark.parametrize("rel,n_constants,n_udts", [
    pytest.param("sqlite/x86/sqlite3.pdb", 295, 274, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 295, 287, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 33, 81, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 9, 32, id="rustpe-i686"),
    pytest.param("tls/tls_symbols.pdb", 0, 0, id="tls-x64"),
])
def test_real_counts_are_stable(rel, n_constants, n_udts):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    pdb = PDB.open(str(path))

    constants, udts = pdb.constants(), pdb.udts()
    assert len(constants) == n_constants
    assert len(udts) == n_udts
    assert all(c.name for c in constants), "a nameless constant means a bad leaf size"
    assert all(u.name for u in udts)


def test_a_wide_value_from_a_real_pdb_is_decoded():
    """The rust fixture is the only fixture with a value past 16 bits: five
    LF_UQUADWORD enum discriminants, one of which is 1 << 63."""
    from pathlib import Path

    path = (Path(__file__).resolve().parent / "data" / "rustpe"
            / "rust_pe_symbols_msvc.pdb")
    if not path.exists():
        pytest.skip("groundtruth fixture missing: rustpe")

    values = {c.value for c in PDB.open(str(path)).constants()}
    assert 0x8000_0000_0000_0000 in values


def test_an_undecodable_constant_is_counted_and_explained():
    """Skipping it silently is the failure this parser must not have.

    It is not malformed -- the record is exactly what it claims to be -- so
    `malformed_records` cannot cover it, and the name is lost with the value.
    """
    real64 = struct.pack("<Hd", 0x8006, 1.5)
    data = constant("PI", 0, raw_value=real64) + constant("MAX", 7)
    assert codeview.count_undecoded_constants(data) == 1

    pdb = _pdb(data)
    d = pdb.diagnose()
    assert [c.name for c in pdb.constants()] == ["MAX"]
    assert d.undecoded_constants == 1
    assert d.malformed_records == 0, "the record is not short, only unreadable"
    assert any("numeric leaf purepdb does not decode" in w for w in d.warnings)
