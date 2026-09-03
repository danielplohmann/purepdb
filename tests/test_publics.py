"""Regression tests for public-symbol extraction.

The bug these guard against failed *silently*: `public_symbols()` read the
publics hash stream, which holds offsets rather than records, so it returned an
empty list with no exception on every real PDB. Emptiness is therefore what the
assertions target -- a count of zero has to fail loudly here.
"""

import struct

import pytest

from purepdb import PDB, MsfError
from purepdb.gsi import PublicsStream
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
)


def _pdb(*, pub_records, addr_map=None, public_stream=4, proc_records=b""):
    """Assemble a PDB whose publics live in stream 7 and hash stream in 4."""
    symrecords = b"".join(pub_records)
    offsets = record_offsets(pub_records) if addr_map is None else addr_map
    module_syms = module_sym_stream(proc_records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=public_stream, symrecord_stream=7,
                   module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream(offsets),
        module_syms,
        # Section 1 is code, section 2 is not: publics in a code section count
        # as functions even without the function flag.
        section_header(".text", 0x1000) + section_header(".data", 0x8000),
        symrecords,
    ]
    return PDB.from_bytes(build_msf(streams))


def test_publics_come_from_the_symbol_record_stream():
    """The hash stream holds no records; reading it would yield zero."""
    pdb = _pdb(pub_records=[pub32("a", 1, 0x10), pub32("b", 1, 0x20),
                            pub32("c", 1, 0x30)])
    pubs = pdb.public_symbols()
    assert len(pubs) == 3, "publics must be read from the symbol-record stream"
    assert [p.name for p in pubs] == ["a", "b", "c"]


def test_publics_hash_stream_holds_no_records():
    """Pin the premise: scanning the hash stream really does find nothing."""
    from purepdb import codeview

    raw = publics_hash_stream([0, 24, 48])
    assert codeview.extract_publics(raw) == []
    parsed = PublicsStream.parse(raw)
    assert parsed.addr_map == [0, 24, 48]


def test_publics_ordered_by_address_map():
    """The address map supplies address order; stream order may differ."""
    records = [pub32("high", 1, 0x300), pub32("low", 1, 0x100),
               pub32("mid", 1, 0x200)]
    offsets = record_offsets(records)
    by_address = [offsets[1], offsets[2], offsets[0]]  # low, mid, high
    pdb = _pdb(pub_records=records, addr_map=by_address)
    assert [p.name for p in pdb.public_symbols()] == ["low", "mid", "high"]


def test_incomplete_address_map_keeps_every_record():
    """A map that misses a record must not be allowed to drop it."""
    records = [pub32("a", 1, 0x10), pub32("b", 1, 0x20)]
    partial = record_offsets(records)[:1]
    pdb = _pdb(pub_records=records, addr_map=partial)
    assert [p.name for p in pdb.public_symbols()] == ["a", "b"]


def test_publics_work_without_a_hash_stream():
    """Some PDBs have no publics stream at all; records are still reachable."""
    pdb = _pdb(pub_records=[pub32("a", 1, 0x10)], public_stream=0xFFFF)
    assert pdb.publics_stream() is None
    assert [p.name for p in pdb.public_symbols()] == ["a"]


def test_function_flagged_publics_reach_functions():
    """A public with no proc record still becomes a function."""
    pdb = _pdb(pub_records=[pub32("thunk", 1, 0x40, flags=0x2),
                            pub32("g_data", 2, 0x80, flags=0x0)])
    fns = {f.name: f for f in pdb.functions()}
    assert fns["thunk"].rva == 0x1040
    assert fns["thunk"].source == "public"
    assert "g_data" not in fns, "a public in a data section is not a function"


def test_unflagged_publics_in_code_are_functions():
    """rust-lld leaves the function flag clear on real code symbols.

    `mainCRTStartup` and `__chkstk` arrive with flags=0, so the section's
    executable bit has to be allowed to decide.
    """
    pdb = _pdb(pub_records=[pub32("mainCRTStartup", 1, 0x20, flags=0x0),
                            pub32("g_config", 2, 0x20, flags=0x0)])
    names = {f.name for f in pdb.functions()}
    assert names == {"mainCRTStartup"}


def test_code_publics_can_be_switched_off():
    """Flag-only behaviour stays reachable for callers who want it."""
    pdb = _pdb(pub_records=[pub32("mainCRTStartup", 1, 0x20, flags=0x0),
                            pub32("flagged", 1, 0x40, flags=0x2)])
    strict = {f.name for f in pdb.functions(code_publics=False)}
    assert strict == {"flagged"}


def test_folded_addresses_keep_every_name_as_an_alias():
    """ICF puts several names on one entry point; none may be discarded."""
    pdb = _pdb(
        pub_records=[pub32("?fold_a@@YAXXZ", 1, 0x100, flags=0x2),
                     pub32("?fold_b@@YAXXZ", 1, 0x100, flags=0x2)],
        proc_records=gproc32("fold_a", 1, 0x100, code_size=0x20),
    )
    fns = pdb.functions()
    assert len(fns) == 1
    fn = fns[0]
    # The proc record is richer, so it wins the name slot.
    assert fn.name == "fold_a"
    assert fn.source == "proc"
    assert fn.code_size == 0x20
    # Both decorated public names survive.
    assert set(fn.aliases) == {"?fold_a@@YAXXZ", "?fold_b@@YAXXZ"}
    assert fn.names[0] == "fold_a"
    assert len(fn.names) == 3


def test_publics_stream_parse_raises_msf_error_on_truncated_data():
    with pytest.raises(MsfError):
        PublicsStream.parse(b"")
    # Header claims 100 bytes of address map, but buffer only has the 28-byte header.
    hdr = struct.pack("<IIIIHHII", 0, 100, 0, 0, 0, 0, 0, 0)
    with pytest.raises(MsfError):
        PublicsStream.parse(hdr)
