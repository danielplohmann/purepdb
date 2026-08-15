"""Thread-local variables: S_GTHREAD32 (0x1113) and S_LTHREAD32 (0x1112).

The record has a data symbol's layout and does not mean what a data symbol
means. `segment:offset` addresses the TLS *initialisation template* -- the
bytes a new thread's copy starts from -- and not the variable, which lives at
a per-thread address computed from the TEB and is in no section of the image.
So these have their own listing rather than joining `data_symbols()`, and the
address is called `template_rva` rather than `rva`.

The golden half proves that claim rather than restating it: the fixture's four
variables initialise to 7, 13, 11 and 17, and the test reads those integers out
of the PE at the addresses purepdb reports, with `tests/_pe.py`, which never
opens the PDB.
"""

import struct
from pathlib import Path

import pytest

from purepdb import PDB, codeview
from tests._pe import PeImage, _rva_to_file_offset
from tests._synth import (
    build_msf,
    dbi_stream,
    gdata32,
    module_info,
    module_sym_stream,
    publics_hash_stream,
    section_header,
    thread32,
)

DATA = Path(__file__).resolve().parent / "data"
FIXTURE = "tls/tls_symbols.pdb"
IMAGE = "tls/tls_symbols.exe"

# What the fixture's four variables are initialised to, from its own source.
# `.tls` holds them in declaration order after the one-byte _tls_start marker.
INITIAL_VALUES = {
    "tls_global_counter": 7,
    "tls_global_scale": 13,
    "tls_static_counter": 11,
    "tls_static_scale": 17,
}


# --- the records ------------------------------------------------------------

@pytest.mark.parametrize("kind,is_global", [
    (codeview.S_GTHREAD32, True),
    (codeview.S_LTHREAD32, False),
])
def test_a_thread_local_record_is_decoded(kind, is_global):
    data = thread32("counter", 4, 0x10, kind=kind)
    found = codeview.extract_thread_locals(data)
    assert len(found) == 1
    tl = found[0]
    assert (tl.name, tl.segment, tl.offset) == ("counter", 4, 0x10)
    assert tl.is_global is is_global


@pytest.mark.parametrize("kind", [codeview.S_GTHREAD32, codeview.S_LTHREAD32])
def test_the_kind_has_a_name_rather_than_hex(kind):
    """`diagnose()` reports record kinds through this, and an undecoded kind
    printing as `0x1112` is the report failing at the one job it has."""
    assert codeview.kind_name(kind).startswith("S_")
    assert codeview.kind_name(kind).endswith("THREAD32")


@pytest.mark.parametrize("kind", [codeview.S_GTHREAD32, codeview.S_LTHREAD32])
def test_a_record_too_short_for_its_kind_is_skipped_and_counted(kind):
    """The `parse_record` dispatch, which is the wiring that gets forgotten.

    A kind absent from that dispatch has its truncated records dropped in
    silence: the listing is one short, `count_malformed_records` says zero and
    no warning fires. Both halves are asserted here, because the skip alone
    passes whether or not the kind was ever added.
    """
    short = struct.pack("<HH", 2, kind)
    good = thread32("kept", 4, 0x10, kind=kind)

    assert [t.name for t in codeview.extract_thread_locals(short + good)] == ["kept"]
    assert codeview.count_malformed_records(short + good) == 1


# --- through a whole PDB ----------------------------------------------------

def _pdb(module_records: bytes = b"", symrecords: bytes = b""):
    return PDB.from_bytes(_pdb_bytes(module_records, symrecords))


def _pdb_bytes(module_records: bytes = b"", symrecords: bytes = b"") -> bytes:
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
        section_header(".text", 0x1000) + section_header(".tls", 0x4000),
        symrecords,
    ]
    return build_msf(streams)


def test_the_template_address_resolves_through_the_section_table():
    pdb = _pdb(thread32("counter", 2, 0x10))
    tl = pdb.thread_locals()[0]
    assert tl.template_rva == 0x4010


def test_thread_locals_stay_out_of_the_data_symbols_listing():
    """The whole reason for a separate accessor. A caller pairing a data
    symbol's address with a function's is comparing two image addresses; a
    thread-local's is an address in the template, so it must not arrive here."""
    pdb = _pdb(thread32("tls_counter", 2, 0x10) + gdata32("plain", 1, 0x20))
    assert [d.name for d in pdb.data_symbols()] == ["plain"]
    assert [t.name for t in pdb.thread_locals()] == ["tls_counter"]


def test_a_static_in_both_streams_is_reported_once():
    """A thread-local with internal linkage is in its module's stream *and* in
    the symbol-record stream the globals hash indexes. Concatenating the two
    sources is what made `data_symbols()` answer 633 for a file of 481."""
    record = thread32("tls_static", 2, 0x10, kind=codeview.S_LTHREAD32)
    pdb = _pdb(record, record)
    assert [t.name for t in pdb.thread_locals()] == ["tls_static"]
    assert pdb.diagnose().thread_local_records == 2, "both records are still counted"


def test_same_named_statics_at_different_addresses_are_both_kept():
    """The other half of deduplicating: one `static _Thread_local int counter;`
    per translation unit is ordinary, and collapsing those by name would be a
    wrong answer rather than an untidy one."""
    pdb = _pdb(thread32("counter", 2, 0x10, kind=codeview.S_LTHREAD32)
               + thread32("counter", 2, 0x20, kind=codeview.S_LTHREAD32))
    assert [t.template_rva for t in pdb.thread_locals()] == [0x4010, 0x4020]


def test_the_same_name_and_address_in_two_linkages_are_both_kept():
    """The `kind` component of the key.

    `_Thread_local int counter;` in one object and a `static` one at the same
    address in another are two symbols, and the record kind is the only field
    that separates them. Nothing in the corpus has this shape, so it is
    synthetic or it is untested -- and dropping `kind` from the key otherwise
    passes the whole suite.
    """
    pdb = _pdb(thread32("counter", 2, 0x10, kind=codeview.S_LTHREAD32)
               + thread32("counter", 2, 0x10, kind=codeview.S_GTHREAD32))
    found = pdb.thread_locals()

    assert len(found) == 2
    assert sorted(t.is_global for t in found) == [False, True]


def test_one_name_at_one_offset_in_two_segments_is_two_symbols():
    """The `segment` component of the key.

    An offset is section-relative, so name and offset alone do not identify a
    symbol. These two resolve to different addresses, which is the point --
    collapsing them would drop a variable that exists.
    """
    pdb = _pdb(thread32("counter", 1, 0x10, kind=codeview.S_LTHREAD32)
               + thread32("counter", 2, 0x10, kind=codeview.S_LTHREAD32))
    found = pdb.thread_locals()

    assert len(found) == 2
    assert sorted(t.template_rva or 0 for t in found) == [0x1010, 0x4010]


def test_the_diagnostic_explains_a_data_listing_that_omits_them():
    pdb = _pdb(thread32("tls_counter", 2, 0x10))
    d = pdb.diagnose()
    assert d.thread_local_records == 1
    assert any("thread-local" in w and "data_symbols()" in w for w in d.warnings)


def test_no_thread_local_warning_when_the_file_has_none():
    d = _pdb(gdata32("plain", 1, 0x20)).diagnose()
    assert d.thread_local_records == 0
    assert not any("thread-local" in w for w in d.warnings)


def test_cli_diagnose_reports_the_record_count(tmp_path, capsys):
    """The count is a `Diagnostics` field, so `diagnose` has to print it.

    Without this line the warning was the only way to learn it, which put a
    number that describes the file in the channel for what went wrong with it.
    """
    from purepdb.__main__ import main

    path = tmp_path / "tls.pdb"
    path.write_bytes(_pdb_bytes(thread32("tls_counter", 2, 0x10)))

    assert main(["purepdb", "diagnose", str(path)]) == 0
    assert "thread-local recs  : 1" in capsys.readouterr().out


def test_cli_diagnose_stays_quiet_about_a_file_with_none(tmp_path, capsys):
    from purepdb.__main__ import main

    path = tmp_path / "plain.pdb"
    path.write_bytes(_pdb_bytes(gdata32("plain", 1, 0x20)))

    assert main(["purepdb", "diagnose", str(path)]) == 0
    assert "thread-local" not in capsys.readouterr().out


# --- against real linker output ---------------------------------------------

def _open(rel):
    path = DATA / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel} "
                    f"(present in the git repo, excluded from the sdist)")
    return PDB.open(str(path))


def test_real_thread_local_counts_are_stable():
    """Counts from `llvm-pdbutil dump --globals --symbols`: two S_GTHREAD32,
    four S_LTHREAD32 -- four, not two, because each of the two statics is in
    its module stream and in the symbol-record stream."""
    pdb = _open(FIXTURE)
    tls = pdb.thread_locals()

    assert len(tls) == 4
    assert pdb.diagnose().thread_local_records == 6
    assert sorted(t.name for t in tls) == [
        "tls_global_counter", "tls_global_scale",
        "tls_static_counter", "tls_static_scale",
    ]
    assert sorted(t.name for t in tls if t.is_global) == [
        "tls_global_counter", "tls_global_scale",
    ]


def test_real_thread_locals_are_absent_from_the_data_symbols():
    pdb = _open(FIXTURE)
    data_names = {d.name for d in pdb.data_symbols()}
    assert data_names, "the fixture has ordinary data symbols too"
    assert data_names.isdisjoint(INITIAL_VALUES)


def test_every_template_address_holds_the_variables_initial_value():
    """The PE oracle, and the evidence that `template_rva` is what it claims.

    `tests/_pe.py` never opens the PDB, so finding purepdb's four addresses
    holding 7, 13, 11 and 17 is agreement between two independent readers
    rather than the parser confirming itself.
    """
    pdb = _open(FIXTURE)
    image_path = DATA / IMAGE
    if not image_path.exists():
        pytest.skip(f"groundtruth fixture missing: {IMAGE}")
    raw = image_path.read_bytes()
    image = PeImage.parse(raw)

    checked = 0
    for tl in pdb.thread_locals():
        assert tl.template_rva is not None
        section = image.section_of(tl.template_rva)
        assert section is not None and section.name == ".tls", (
            f"{tl.name} must resolve into the TLS template section"
        )
        offset = _rva_to_file_offset(raw, image, tl.template_rva)
        assert offset is not None
        value = struct.unpack_from("<i", raw, offset)[0]
        assert value == INITIAL_VALUES[tl.name], (
            f"{tl.name} initialises to {INITIAL_VALUES[tl.name]}, "
            f"the image holds {value} at {tl.template_rva:#x}"
        )
        checked += 1

    assert checked == 4, "a zero-iteration loop asserts nothing"
