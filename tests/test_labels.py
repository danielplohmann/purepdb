"""S_LABEL32: named code addresses inside procedures.

A label is code with a name, like a thunk, but unlike a thunk it is not an
entry point -- it is somewhere to jump to inside a body that already has one.
So it gets its own listing rather than a place in `functions()`, which is the
property most of these tests are about.
"""

import struct

import pytest

from purepdb import PDB, codeview
from tests._synth import (
    build_msf,
    dbi_stream,
    gproc32,
    label32,
    make_record,
    module_info,
    module_sym_stream,
    pub32,
    publics_hash_stream,
    record_offsets,
    section_header,
)


def test_a_label_record_is_decoded():
    labels = codeview.extract_labels(label32("retry", 1, 0x1234, flags=0x01))
    assert len(labels) == 1
    label = labels[0]
    assert (label.name, label.segment, label.offset) == ("retry", 1, 0x1234)
    assert label.flags == 0x01


def test_a_label_inside_a_proc_scope_does_not_disturb_the_proc_walk():
    """Labels sit between an S_*PROC32 and the S_END that closes it."""
    data = (gproc32("main", 1, 0x10)
            + label32("main_retry", 1, 0x18)
            + make_record(codeview.S_END, b"")
            + gproc32("next", 1, 0x40))

    assert [p.name for p in codeview.extract_procs(data)] == ["main", "next"]
    assert [label.name for label in codeview.extract_labels(data)] == ["main_retry"]


def test_a_record_too_short_for_its_kind_is_skipped_not_raised():
    """RecordLen is the record's own claim about its size; a short one hands a
    truncated payload to a parser expecting a whole one."""
    short = struct.pack("<HH", 2, codeview.S_LABEL32)
    data = short + label32("real", 1, 0x10)
    assert [label.name for label in codeview.extract_labels(data)] == ["real"]


def test_a_short_label_is_counted_as_malformed_rather_than_vanishing():
    """Dropping the record silently is the half-fix this parser must not have.

    `diagnose().labels` counts records, `labels()` returns the ones that
    decoded, and the difference has to be accounted for somewhere -- otherwise
    a label the file contains disappears with nothing to say so.
    """
    # A payload with room for Offset and nothing else.
    short = struct.pack("<HHI", 6, codeview.S_LABEL32, 0x1234)
    pdb = _pdb(short + label32("real", 1, 0x10))
    d = pdb.diagnose()

    assert [label.name for label in pdb.labels()] == ["real"]
    assert d.labels == 2, "the record is there, and is counted"
    assert d.malformed_records == 1, "and the one that did not decode is named"
    assert any("shorter than the kind they claim to be" in w for w in d.warnings)


def _pdb(module_records: bytes, publics=()):
    module_syms = module_sym_stream(module_records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream(record_offsets(list(publics))),
        module_syms,
        section_header(".text", 0x1000) + section_header(".data", 0x2000),
        b"".join(publics),
    ]
    return PDB.from_bytes(build_msf(streams))


def test_a_label_resolves_to_an_rva():
    pdb = _pdb(label32("KiUserCallbackDispatcherContinue", 1, 0x40))
    labels = pdb.labels()
    assert [(label.name, label.rva) for label in labels] == [
        ("KiUserCallbackDispatcherContinue", 0x1040),
    ]


def test_labels_stay_out_of_the_function_list():
    """The double-counting this exists to prevent: one body, one entry point."""
    pdb = _pdb(gproc32("main", 1, 0x40, code_size=0x30)
               + label32("main_retry", 1, 0x50)
               + make_record(codeview.S_END, b""))

    assert [(f.name, f.rva) for f in pdb.functions()] == [("main", 0x1040)]
    assert [(label.name, label.rva) for label in pdb.labels()] == [
        ("main_retry", 0x1050),
    ]


def test_a_label_does_not_become_a_function_through_a_public_either():
    """A public at a label's address is still one function, not two."""
    pdb = _pdb(gproc32("main", 1, 0x40, code_size=0x30)
               + label32("main_retry", 1, 0x50),
               publics=[pub32("main", 1, 0x40)])
    assert [f.name for f in pdb.functions()] == ["main"]


def test_diagnose_reports_the_label_count():
    pdb = _pdb(label32("a", 1, 0x10) + label32("b", 1, 0x20))
    assert pdb.diagnose().labels == 2


def test_a_pdb_without_labels_reports_none():
    pdb = _pdb(gproc32("main", 1, 0x40))
    assert pdb.labels() == []
    assert pdb.diagnose().labels == 0


# --- against real linker output ---------------------------------------------

def _open(pdb_rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / pdb_rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {pdb_rel}")
    return PDB.open(str(path))


def _image(image_rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / image_rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {image_rel}")
    return path.read_bytes()


# (pdb, image, label records, of those with a segment that names a section)
CASES = [
    pytest.param("sqlite/x86/sqlite3.pdb", "sqlite/x86/sqlite3.dll",
                 1412, 1412, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", "sqlite/x64/sqlite3.dll",
                 1237, 1237, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb",
                 "rustpe/rust_pe_symbols_msvc.exe", 160, 0, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb",
                 "rustpe32/rust_pe_symbols_i686.exe", 0, 0, id="rustpe-i686"),
]


@pytest.mark.parametrize("pdb_rel,image_rel,n_labels,n_addressed", CASES)
def test_real_counts_are_stable(pdb_rel, image_rel, n_labels, n_addressed):
    pdb = _open(pdb_rel)
    labels = pdb.labels()
    assert len(labels) == n_labels
    assert pdb.diagnose().labels == n_labels
    assert sum(1 for label in labels if label.rva is not None) == n_addressed


@pytest.mark.parametrize("pdb_rel,image_rel,n_labels,n_addressed", CASES)
def test_every_addressed_label_lands_in_executable_code(pdb_rel, image_rel,
                                                        n_labels, n_addressed):
    """The independent check: the sections come from the image, not the PDB."""
    from tests._pe import PeImage

    pdb = _open(pdb_rel)
    image = PeImage.parse(_image(image_rel))
    checked = 0
    for label in pdb.labels():
        if label.rva is None:
            continue
        section = image.section_of(label.rva)
        assert section is not None, f"{label.name} is outside every section"
        assert section.executable, f"{label.name} is in {section.name}"
        checked += 1
    # Two of the four fixtures address no label at all, so the loop above is
    # empty for them by design. Asserting the count keeps that deliberate
    # rather than a check that quietly stopped running.
    assert checked == n_addressed


@pytest.mark.parametrize("pdb_rel,image_rel,n_labels,n_addressed", CASES)
def test_every_addressed_label_falls_inside_a_function_body(
        pdb_rel, image_rel, n_labels, n_addressed):
    """What makes a label a label: it is an address *within* a procedure.

    Reading the offset and segment fields the wrong way round still yields
    addresses in `.text`, so this is the check that says they were read right.
    """
    pdb = _open(pdb_rel)
    bodies = sorted((f.rva, f.rva + f.code_size) for f in pdb.functions()
                    if f.rva is not None and f.code_size)
    checked = 0
    for label in pdb.labels():
        if label.rva is None:
            continue
        assert any(start <= label.rva < end for start, end in bodies), (
            f"{label.name} at {label.rva:#x} is in no function body")
        checked += 1
    assert checked == n_addressed


@pytest.mark.parametrize("pdb_rel,image_rel,n_labels,n_addressed", CASES)
def test_labels_are_not_in_the_function_list(pdb_rel, image_rel, n_labels,
                                             n_addressed):
    """Not by name and not by address: both would double-count a body."""
    pdb = _open(pdb_rel)
    names = {n for f in pdb.functions() for n in f.names}
    entry_points = {(f.segment, f.offset) for f in pdb.functions()}
    for label in pdb.labels():
        assert label.name not in names
        assert (label.segment, label.offset) not in entry_points


def test_rust_lld_emits_label_records_that_name_and_locate_nothing():
    """160 records with no name, and a segment that names no section.

    A twelve-byte S_LABEL32 is the fixed portion and an empty name. The Offset
    field is *not* empty -- these carry 0x1A35 and the like -- but Segment is 0,
    which no section table has, so nothing resolves. They are kept rather than
    filtered because the count is what `diagnose()` reports and what
    `llvm-pdbutil` prints: dropping them would make purepdb disagree with the
    file. What it means for a caller is that a label listing can be non-empty
    and still answer nothing, which no other record kind in the corpus does.
    """
    pdb = _open("rustpe/rust_pe_symbols_msvc.pdb")
    labels = pdb.labels()
    assert len(labels) == 160
    assert all(label.name == "" and label.segment == 0 for label in labels)
    assert all(label.rva is None for label in labels)
    assert any(label.offset for label in labels), "the offsets are real"


def test_labels_carry_names_that_no_other_record_has():
    """The point of reading them.

    586 distinct names across the 1412 records -- a label name repeats between
    procedures, `$LN7` most of all -- and not one of them appears in any other
    listing purepdb produces.
    """
    pdb = _open("sqlite/x86/sqlite3.pdb")
    known = {n for f in pdb.functions() for n in f.names}
    known |= {p.name for p in pdb.public_symbols()}
    known |= {d.name for d in pdb.data_symbols()}
    known |= {t.name for t in pdb.thunks()}
    named = {label.name for label in pdb.labels() if label.name}

    assert len(named) == 586
    assert not (named & known)
    assert "splitnode_out" in named
