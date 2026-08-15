"""Data symbols, and the two streams that both describe them.

A module's stream holds the data symbols defined in it; the symbol-record
stream holds the set the globals hash indexes. A file-static symbol is in
both, so reporting every record makes one symbol look like two -- 633 records
for 481 symbols on sqlite3 x86.
"""

import struct
from pathlib import Path

import pytest

from purepdb import PDB, codeview
from tests._synth import (
    build_msf,
    dbi_stream,
    gdata32,
    module_info,
    module_sym_stream,
    publics_hash_stream,
    section_header,
)

S_LDATA32 = 0x110C


def _pdb(*, module_records=b"", symrecords=b"", second_module=b""):
    """A PDB whose modules and symbol-record stream hold what is given."""
    first = module_sym_stream(module_records)
    second = module_sym_stream(second_module)
    mods = (module_info("main.obj", "main.obj", sym_stream=5,
                        sym_byte_size=len(first))
            + module_info("other.obj", "other.obj", sym_stream=8,
                          sym_byte_size=len(second)))
    return PDB.from_bytes(build_msf([
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]),
        first,
        section_header(".text", 0x1000) + section_header(".data", 0x2000),
        symrecords,
        second,
    ]))


def _keys(pdb):
    return [(d.name, d.segment, d.offset, d.kind) for d in pdb.data_symbols()]


def test_a_symbol_in_both_streams_is_reported_once():
    """The same record, field for field, reached by two routes."""
    both = gdata32("g_cache", 2, 0x100)
    pdb = _pdb(module_records=both, symrecords=both)

    assert _keys(pdb) == [("g_cache", 2, 0x100, codeview.S_GDATA32)]


def test_two_symbols_at_one_address_are_both_kept():
    """A name is part of what identifies a symbol, so two names at one address
    are two symbols -- the shape a union or an aliased export produces."""
    pdb = _pdb(module_records=gdata32("first", 2, 0x100) + gdata32("second", 2, 0x100))

    assert [name for name, *_ in _keys(pdb)] == ["first", "second"]


def test_one_name_at_two_addresses_is_two_symbols():
    """Two translation units, one `static int counter;` each."""
    pdb = _pdb(module_records=gdata32("counter", 2, 0x100, kind=S_LDATA32),
               second_module=gdata32("counter", 2, 0x200, kind=S_LDATA32))

    assert [offset for _n, _s, offset, _k in _keys(pdb)] == [0x100, 0x200]


def test_the_same_name_and_address_with_different_kinds_are_both_kept():
    """The conservative half of the key.

    Nothing in the corpus disagrees on kind, so this cannot be checked against
    a real file -- but collapsing a global and a static that happen to share a
    name and an address would be a wrong answer, not a tidier one.
    """
    pdb = _pdb(module_records=gdata32("shared", 2, 0x100, kind=S_LDATA32),
               symrecords=gdata32("shared", 2, 0x100))

    assert [kind for *_rest, kind in _keys(pdb)] == [S_LDATA32,
                                                     codeview.S_GDATA32]


def test_module_order_is_kept_and_the_globals_come_last():
    pdb = _pdb(module_records=gdata32("from_main", 2, 0x100),
               second_module=gdata32("from_other", 2, 0x200),
               symrecords=gdata32("from_globals", 2, 0x300))

    assert [name for name, *_ in _keys(pdb)] == [
        "from_main", "from_other", "from_globals",
    ]


def test_a_pdb_with_no_symbol_record_stream_still_reports_module_data():
    first = module_sym_stream(gdata32("g_only", 2, 0x100))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(first))
    pdb = PDB.from_bytes(build_msf([
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=0xFFFF, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]),
        first,
        section_header(".text", 0x1000) + section_header(".data", 0x2000),
    ]))

    assert [name for name, *_ in _keys(pdb)] == ["g_only"]


def test_a_data_symbol_resolves_to_an_rva():
    pdb = _pdb(module_records=gdata32("g_cache", 2, 0x100))
    symbol = pdb.data_symbols()[0]

    assert pdb.to_rva(symbol.segment, symbol.offset) == 0x2100
    assert symbol.is_global


# --- against real linker output ---------------------------------------------

# (pdb, records both streams hold, symbols they describe)
CASES = [
    pytest.param("sqlite/x86/sqlite3.pdb", 633, 481, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 540, 403, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 2, 1, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 0, 0, id="rustpe-i686"),
]


def _open(rel):
    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    return PDB.open(str(path))


@pytest.mark.parametrize("rel,n_records,n_symbols", CASES)
def test_real_counts_are_stable(rel, n_records, n_symbols):
    """Both numbers, so a regression that stopped deduplicating would fail.

    `n_records` is what the two streams hold between them, and matches what
    `llvm-pdbutil` prints across `dump --symbols` and `dump --globals`.
    """
    pdb = _open(rel)
    raw = codeview.extract_data(b"".join(
        pdb.module_symbol_bytes(mod) for mod in pdb.dbi.modules))
    idx = pdb.dbi.symrecord_stream_index
    if pdb.msf.is_valid_stream(idx):
        raw += codeview.extract_data(pdb.msf.read_stream(idx))

    assert len(raw) == n_records
    assert len(pdb.data_symbols()) == n_symbols


@pytest.mark.parametrize("rel,n_records,n_symbols", CASES)
def test_no_symbol_is_reported_twice(rel, n_records, n_symbols):
    pdb = _open(rel)
    keys = _keys(pdb)
    assert len(keys) == len(set(keys))


def test_every_removed_record_is_accounted_for():
    """Where the 152 sightings sqlite3 x86 loses actually come from.

    145 are symbols the globals index repeats from a module stream. The other
    7 are inside the globals stream on its own, which lists six symbols more
    than once -- so deduplicating only across the two streams would still
    report a symbol twice.
    """
    pdb = _open("sqlite/x86/sqlite3.pdb")

    def keys(symbols):
        return [(d.name, d.segment, d.offset, d.kind) for d in symbols]

    modules = keys(codeview.extract_data(b"".join(
        pdb.module_symbol_bytes(mod) for mod in pdb.dbi.modules)))
    globals_ = keys(codeview.extract_data(
        pdb.msf.read_stream(pdb.dbi.symrecord_stream_index)))

    assert (len(modules), len(set(modules))) == (438, 438)
    assert (len(globals_), len(set(globals_))) == (195, 188)
    assert len(set(modules) & set(globals_)) == 145
    assert len(pdb.data_symbols()) == len(set(modules) | set(globals_)) == 481
    assert "yy_action" in {name for name, *_ in set(modules) & set(globals_)}
