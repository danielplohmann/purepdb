"""Tests for `PDB.diagnose()`.

Both conditions it reports produce an empty-ish result rather than an error, so
the point of these tests is that the *explanation* appears.
"""

import struct

from purepdb import PDB
from tests._synth import (
    build_msf, dbi_stream, gproc32, make_record, module_info,
    module_sym_stream, pub32, publics_hash_stream, record_offsets,
    section_header,
)

# A record kind purepdb does not decode, with a plausible payload.
UNKNOWN_KIND = 0x1167


def _pdb(*, module_records=b"", pub_records=(), section_stream=6):
    symrecords = b"".join(pub_records)
    module_syms = module_sym_stream(module_records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [section_stream]),
        publics_hash_stream(record_offsets(list(pub_records))),
        module_syms,
        section_header(".text", 0x1000),
        symrecords,
    ]
    return PDB.from_bytes(build_msf(streams))


def test_healthy_pdb_reports_no_warnings():
    pdb = _pdb(module_records=gproc32("main", 1, 0x10),
               pub_records=[pub32("main", 1, 0x10)])
    d = pdb.diagnose()
    assert d.proc_records == 1
    assert d.public_records == 1
    assert d.has_section_headers
    assert d.warnings == []


def test_undecodable_module_streams_are_explained():
    """The FASTLINK shape: module streams full of records we don't decode."""
    records = b"".join(
        make_record(UNKNOWN_KIND, struct.pack("<IH", 2, 16) + b"NAME\x00")
        for _ in range(5)
    )
    pdb = _pdb(module_records=records, pub_records=[pub32("thunk", 1, 0x10)])
    d = pdb.diagnose()

    assert d.proc_records == 0
    assert d.modules_with_symbols == 1
    assert d.module_kinds == {UNKNOWN_KIND: 5}

    warning = "\n".join(d.warnings)
    assert "no procedure records" in warning
    assert "0x1167" in warning, "the unrecognised kind must be named"
    assert "FASTLINK" in warning
    # The publics path still works, which is the whole point of saying so.
    assert [f.name for f in pdb.functions()] == ["thunk"]


def test_missing_section_headers_are_explained():
    pdb = _pdb(module_records=gproc32("main", 1, 0x10),
               pub_records=[pub32("main", 1, 0x10)],
               section_stream=0xFFFF)
    d = pdb.diagnose()
    assert not d.has_section_headers
    assert pdb.sections == []
    assert any("no section-header stream" in w for w in d.warnings)
    # Functions are still listed, just without RVAs.
    fns = pdb.functions()
    assert len(fns) == 1
    assert fns[0].rva is None


def test_missing_publics_are_explained():
    pdb = _pdb(module_records=gproc32("main", 1, 0x10), pub_records=[])
    assert any("no public records" in w for w in pdb.diagnose().warnings)


def test_line_info_after_the_symbols_is_not_parsed_as_records():
    """sym_byte_size bounds the symbol region; C13 data follows it.

    The trailing bytes here begin with a length/kind pair that would decode as
    a proc record if the bound were ignored.
    """
    symbols = gproc32("real", 1, 0x10)
    trailing = gproc32("phantom", 1, 0x99)
    module_syms = module_sym_stream(symbols) + trailing
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=4 + len(symbols))  # signature + symbols
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]),
        module_syms,
        section_header(".text", 0x1000),
        b"",
    ]
    pdb = PDB.from_bytes(build_msf(streams))
    names = [p.name for p in pdb.module_procs()]
    assert names == ["real"], "must stop at sym_byte_size"
