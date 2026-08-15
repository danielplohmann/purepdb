"""A record stream that stops early must say so.

`iter_records` ends the walk on a malformed length rather than raising, because
the caller may be looking at padding. That is the right default and also the
one way purepdb can return a short listing with no explanation, so the walk
reports where it stopped and `diagnose()` carries it through to the CLI.
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
    pub32,
    publics_hash_stream,
    section_header,
)


def test_a_clean_stream_reports_no_truncation():
    data = pub32("foo", 1, 0x10) + pub32("bar", 1, 0x20)
    report: list[codeview.Truncation] = []
    assert len(list(codeview.iter_records(data, truncation=report))) == 2
    assert report == []
    assert codeview.find_truncation(data) is None


def test_a_corrupt_length_stops_the_walk_and_is_reported():
    """The records before the bad one survive; the ones after are lost."""
    good = pub32("first", 1, 0x10)
    corrupt = struct.pack("<HH", 0, codeview.S_PUB32) + b"\x00" * 12
    data = good + corrupt + pub32("second", 1, 0x20)

    report: list[codeview.Truncation] = []
    records = list(codeview.iter_records(data, truncation=report))

    assert [r.kind for r in records] == [codeview.S_PUB32]
    assert len(report) == 1
    assert report[0].offset == len(good)
    assert "below the 2-byte minimum" in report[0].reason
    assert [p.name for p in codeview.extract_publics(data)] == ["first"]


def test_a_length_running_past_the_end_is_reported():
    good = pub32("first", 1, 0x10)
    overrun = struct.pack("<HH", 0x400, codeview.S_PUB32) + b"\x00" * 8
    report: list[codeview.Truncation] = []

    records = list(codeview.iter_records(good + overrun, truncation=report))

    assert len(records) == 1
    assert report[0].offset == len(good)
    assert "past the end" in report[0].reason


def test_a_stub_of_a_record_header_is_reported():
    data = pub32("first", 1, 0x10) + b"\x00\x00"
    truncation = codeview.find_truncation(data)
    assert truncation is not None
    assert "trailing bytes" in truncation.reason


def test_truncation_is_opt_in_and_never_raises():
    """Existing callers pass no list and keep the old lenient behaviour."""
    data = pub32("first", 1, 0x10) + b"\x00" * 6
    assert [p.name for p in codeview.extract_publics(data)] == ["first"]
    assert codeview.count_kinds(data) == {codeview.S_PUB32: 1}


def _pdb_bytes(module_records: bytes, symrecords: bytes = b"") -> bytes:
    module_syms = module_sym_stream(module_records)
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
    return build_msf(streams)


def _pdb(module_records: bytes, symrecords: bytes = b"") -> PDB:
    return PDB.from_bytes(_pdb_bytes(module_records, symrecords))


def test_diagnose_names_a_truncated_module_stream():
    good = gproc32("real", 1, 0x10)
    corrupt = struct.pack("<HH", 1, codeview.S_GPROC32) + b"\x00" * 12
    pdb = _pdb(good + corrupt + gproc32("lost", 1, 0x20),
               symrecords=pub32("real", 1, 0x10))

    d = pdb.diagnose()
    assert d.truncated_streams == 1
    where, first = d.truncations[0]
    assert where == "module 0 (main.obj)"
    assert first.offset == len(good)

    assert [p.name for p in pdb.module_procs()] == ["real"]
    warning = "\n".join(d.warnings)
    assert "stopped early" in warning
    assert hex(first.offset) in warning


def test_diagnose_names_a_truncated_symbol_record_stream():
    corrupt = struct.pack("<HH", 0, codeview.S_PUB32) + b"\x00" * 12
    pdb = _pdb(gproc32("real", 1, 0x10),
               symrecords=pub32("first", 1, 0x10) + corrupt + pub32("lost", 1, 0x20))

    d = pdb.diagnose()
    assert [(w) for w, _ in d.truncations] == ["the symbol-record stream"]
    assert [p.name for p in pdb.public_symbols()] == ["first"]


def test_a_healthy_pdb_still_reports_nothing():
    pdb = _pdb(gproc32("main", 1, 0x10), symrecords=pub32("main", 1, 0x10))
    d = pdb.diagnose()
    assert d.truncated_streams == 0
    assert d.warnings == []


def test_cli_diagnose_prints_the_truncation(tmp_path, capsys):
    from purepdb.__main__ import main

    corrupt = struct.pack("<HH", 0, codeview.S_GPROC32) + b"\x00" * 12
    path = tmp_path / "truncated.pdb"
    path.write_bytes(_pdb_bytes(gproc32("real", 1, 0x10) + corrupt,
                                symrecords=pub32("real", 1, 0x10)))
    assert main(["purepdb", "diagnose", str(path)]) == 0

    out = capsys.readouterr().out
    assert "truncated streams  : 1" in out
    assert "stopped early" in out


# --- records that are shorter than the kind they claim to be ----------------

def _short_record(kind: int, payload_len: int = 0) -> bytes:
    """A well-formed record header over a payload too short for its kind."""
    payload = b"\x41" * payload_len
    payload += b"\x00" * (-(4 + payload_len) % 4)
    return struct.pack("<HH", 2 + len(payload), kind) + payload


# Every kind `parse_record` dispatches, so that re-narrowing that dispatch
# fails here rather than silently dropping truncated records of the kinds it
# stops covering. S_INLINESITE is absent because 12 bytes is a *whole* one --
# three u32s and no annotations; tests/test_inline.py covers its short form.
@pytest.mark.parametrize("kind", [
    codeview.S_PUB32, codeview.S_GPROC32, codeview.S_LPROC32,
    codeview.S_GDATA32, codeview.S_LDATA32,
    codeview.S_PROCREF, codeview.S_LPROCREF, codeview.S_LABEL32,
    codeview.S_THUNK32, codeview.S_TRAMPOLINE, codeview.S_CONSTANT,
    codeview.S_UDT,
])
@pytest.mark.parametrize("payload_len", [0, 4, 12])
def test_a_record_too_short_for_its_kind_is_skipped_not_raised(kind, payload_len):
    """RecordLen is the record's own claim, and nothing checks it against the
    fixed portion the kind needs. A short one used to hand a truncated payload
    to a parser expecting a whole one, and EOFError escaped `functions()`."""
    assert codeview.decode_record(kind, b"\x41" * payload_len) is None
    data = _short_record(kind, payload_len)
    assert codeview.extract_publics(data) == []
    assert codeview.extract_procs(data) == []
    assert codeview.extract_data(data) == []
    assert codeview.count_malformed_records(data) == 1


def test_good_records_survive_a_malformed_one_between_them():
    data = (pub32("first", 1, 0x10)
            + _short_record(codeview.S_PUB32)
            + pub32("second", 1, 0x20))
    assert [p.name for p in codeview.extract_publics(data)] == ["first", "second"]
    assert codeview.count_malformed_records(data) == 1


def test_diagnose_counts_and_explains_malformed_records():
    pdb = _pdb(gproc32("real", 1, 0x10) + _short_record(codeview.S_GPROC32),
               symrecords=pub32("real", 1, 0x10) + _short_record(codeview.S_PUB32))

    d = pdb.diagnose()
    assert d.malformed_records == 2
    assert [p.name for p in pdb.module_procs()] == ["real"]
    assert [p.name for p in pdb.public_symbols()] == ["real"]
    assert any("shorter than the kind" in w for w in d.warnings)


def test_a_record_kind_we_do_not_decode_is_never_malformed():
    """Skipping an unknown kind is normal, not damage."""
    data = _short_record(0x1167)
    assert codeview.count_malformed_records(data) == 0
    assert codeview.decode_record(0x1167, b"") is None


@pytest.mark.parametrize("rel", [
    "sqlite/x86/sqlite3.pdb",
    "sqlite/x64/sqlite3.pdb",
    "rustpe/rust_pe_symbols_msvc.pdb",
    "rustpe32/rust_pe_symbols_i686.pdb",
])
def test_real_pdbs_are_not_truncated(rel):
    """Guard against the check itself producing false positives."""
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    d = PDB.open(str(path)).diagnose()
    assert d.truncations == []
    assert d.malformed_records == 0


# --- a ragged tail is not an abandoned walk ---------------------------------

def test_a_ragged_tail_is_flagged_and_an_abandoned_walk_is_not():
    """The two shapes make different claims, so they carry different flags.

    Fewer than 4 bytes left cannot hold a record header, so nothing is provably
    lost -- it is padding, or a file cut inside a header, and those look the
    same from here. A corrupt length *does* abandon readable bytes.
    """
    ragged = codeview.find_truncation(pub32("first", 1, 0x10) + b"\x00\x00")
    assert ragged is not None and ragged.ragged_tail

    corrupt = struct.pack("<HH", 0, codeview.S_PUB32) + b"\x00" * 12
    abandoned = codeview.find_truncation(pub32("first", 1, 0x10) + corrupt)
    assert abandoned is not None and not abandoned.ragged_tail


def test_the_warning_for_a_ragged_tail_does_not_claim_missing_symbols():
    pdb = _pdb(gproc32("real", 1, 0x10) + b"\x00\x00",
               symrecords=pub32("real", 1, 0x10))

    d = pdb.diagnose()
    assert d.truncated_streams == 1
    warning = "\n".join(d.warnings)
    assert "too few bytes for a record header" in warning
    assert "usually padding" in warning
    assert "every symbol after that point is missing" not in warning
    assert [p.name for p in pdb.module_procs()] == ["real"]


def test_an_abandoned_walk_still_says_symbols_are_missing():
    corrupt = struct.pack("<HH", 1, codeview.S_GPROC32) + b"\x00" * 12
    pdb = _pdb(gproc32("real", 1, 0x10) + corrupt + gproc32("lost", 1, 0x20),
               symrecords=pub32("real", 1, 0x10))

    warning = "\n".join(pdb.diagnose().warnings)
    assert "every symbol after that point is missing" in warning
    assert "usually padding" not in warning


def test_both_shapes_at_once_are_reported_separately():
    """One stream abandoned, one ragged: two sentences, one count each."""
    corrupt = struct.pack("<HH", 0, codeview.S_GPROC32) + b"\x00" * 12
    pdb = _pdb(gproc32("real", 1, 0x10) + corrupt,
               symrecords=pub32("first", 1, 0x10) + b"\x00\x00")

    d = pdb.diagnose()
    assert d.truncated_streams == 2
    warnings = [w for w in d.warnings if "record stream(s)" in w]
    assert len(warnings) == 2
    assert sum("1 record stream(s)" in w for w in warnings) == 2


# --- a module list that stops early -----------------------------------------

def _truncated_module_list() -> bytes:
    """Two module records, the second with its object name unterminated."""
    good = module_info("first.obj", "first.obj", sym_stream=5, sym_byte_size=0)
    cut = module_info("second.obj", "second.obj", sym_stream=6, sym_byte_size=0)
    # Drop the trailing NUL and padding, so the last name runs to the end.
    return good + cut.rstrip(b"\x00")


def test_a_module_list_that_stops_early_is_reported():
    """The modules before the damage survive; the walk says where it stopped."""
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7,
                   module_list=_truncated_module_list(),
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]),
        b"",
        section_header(".text", 0x1000),
        b"",
    ]
    pdb = PDB.from_bytes(build_msf(streams))

    assert [m.module_name for m in pdb.dbi.modules] == ["first.obj"]
    stopped = pdb.dbi.module_list_stopped_at
    assert stopped is not None

    d = pdb.diagnose()
    assert d.module_list_stopped_at == stopped
    warning = "\n".join(d.warnings)
    assert "module list stopped" in warning
    assert hex(stopped) in warning


def test_a_whole_module_list_reports_nothing():
    pdb = _pdb(gproc32("main", 1, 0x10), symrecords=pub32("main", 1, 0x10))
    assert pdb.dbi.module_list_stopped_at is None
    assert pdb.diagnose().module_list_stopped_at is None
    assert not any("module list" in w for w in pdb.diagnose().warnings)
