"""S_COMPILE3: what produced a module, stated rather than inferred.

The record carries the source language, the target CPU and the compiler's own
version string. The language field is the point: a consumer deciding how to
demangle, or whether a binary contains Rust at all, otherwise has to guess it
from the shape of the mangled names.
"""

import struct

import pytest

from purepdb import PDB, codeview
from tests._synth import (
    build_msf,
    compile3,
    dbi_stream,
    module_info,
    module_sym_stream,
    pub32,
    publics_hash_stream,
    section_header,
    udt,
)


def test_a_compile3_record_is_decoded():
    infos = codeview.extract_compile_infos(compile3(
        "clang LLVM (rustc version 1.94.1)",
        language=0x15, machine=0x07,
        frontend=(1, 94, 1, 0), backend=(21018, 0, 0, 0),
    ))
    assert len(infos) == 1
    info = infos[0]
    assert info.language == 0x15
    assert info.language_name == "Rust"
    assert info.machine_name == "Pentium III"
    assert info.frontend == (1, 94, 1, 0)
    assert info.backend == (21018, 0, 0, 0)
    assert info.compiler == "clang LLVM (rustc version 1.94.1)"


def test_the_feature_bits_above_the_language_byte_are_not_read_as_language():
    """Language is the low byte of a word whose other 24 bits are feature
    flags, so a compiler that sets any of them must still report as itself."""
    infos = codeview.extract_compile_infos(
        compile3("cl", language=0x01, feature_flags=0xFFFFFF))
    assert infos[0].language_name == "C++"


@pytest.mark.parametrize("value,expected", [
    (0x00, "C"),
    (0x01, "C++"),
    (0x07, "Link"),
    (0x15, "Rust"),
    (0x16, "Go"),
    (0x44, "D"),
    (0xFE, "0xfe"),   # not a language we can name
])
def test_language_names(value, expected):
    assert codeview.CompileInfo(
        language=value, machine=0, frontend=(0, 0, 0, 0),
        backend=(0, 0, 0, 0), compiler="",
    ).language_name == expected


@pytest.mark.parametrize("value,expected", [
    (0x03, "Intel 80386"),
    (0xD0, "x64"),
    (0xF6, "ARM64"),
    (0x1234, "0x1234"),   # not a CPU we can name
])
def test_machine_names(value, expected):
    assert codeview.CompileInfo(
        language=0, machine=value, frontend=(0, 0, 0, 0),
        backend=(0, 0, 0, 0), compiler="",
    ).machine_name == expected


def test_every_record_in_a_module_is_returned():
    """An import library arrives as one DBI module holding the records of every
    member `.obj`, so one module can hold many. Taking only the first would
    undercount the sqlite x64 fixture by 78 records."""
    data = (compile3("LINK", language=0x07)
            + compile3("LINK", language=0x07)
            + compile3("LINK", language=0x07))
    assert len(codeview.extract_compile_infos(data)) == 3


@pytest.mark.parametrize("payload_len", [0, 4, 20])
def test_a_record_too_short_for_its_kind_is_skipped_not_raised(payload_len):
    """The fixed portion is 22 bytes before the version string. RecordLen is
    the record's own claim, and nothing checks it against that."""
    payload = b"\x41" * payload_len
    payload += b"\x00" * (-(4 + payload_len) % 4)
    short = struct.pack("<HH", 2 + len(payload), codeview.S_COMPILE3) + payload

    whole = compile3("cl", language=0x00)
    assert codeview.extract_compile_infos(short + whole) == \
        codeview.extract_compile_infos(whole)


def test_a_short_record_is_counted_as_malformed():
    """A kind absent from `parse_record`'s dispatch has its truncated records
    dropped in silence -- the listing one short and the counter saying zero."""
    short = struct.pack("<HHI", 6, codeview.S_COMPILE3, 0)
    assert codeview.count_malformed_records(short) == 1
    assert codeview.count_malformed_records(compile3("cl")) == 0


def test_an_unterminated_version_string_is_malformed_not_a_partial_name():
    """`cstring` needs its NUL: a record whose string runs to the end of the
    payload is short for its kind, not a record with a shorter name."""
    payload = struct.pack("<IH", 0x00, 0xD0) + struct.pack("<8H", *([0] * 8))
    payload += b"cl"  # no NUL
    rec = struct.pack("<HH", 2 + len(payload), codeview.S_COMPILE3) + payload

    assert codeview.extract_compile_infos(rec) == []
    assert codeview.count_malformed_records(rec) == 1


def test_a_short_record_does_not_desynchronise_the_stream():
    short = struct.pack("<HHI", 6, codeview.S_COMPILE3, 0)
    data = short + udt("Widget") + pub32("f", 1, 0x10)

    assert codeview.extract_compile_infos(data) == []
    assert [u.name for u in codeview.extract_udts(data)] == ["Widget"]
    assert [p.name for p in codeview.extract_publics(data)] == ["f"]


# --- through the PDB API ------------------------------------------------------

def _pdb(module_a: bytes, module_b: bytes):
    syms_a, syms_b = module_sym_stream(module_a), module_sym_stream(module_b)
    mods = (module_info("a.obj", "a.obj", sym_stream=5, sym_byte_size=len(syms_a))
            + module_info("KERNEL32.dll", "KERNEL32.lib", sym_stream=8,
                          sym_byte_size=len(syms_b)))
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6]),
        publics_hash_stream([]),
        syms_a,
        section_header(".text", 0x1000),
        b"",
        syms_b,
    ]
    return PDB.from_bytes(build_msf(streams))


def test_each_record_is_tagged_with_the_module_it_came_from():
    pdb = _pdb(
        compile3("rustc", language=0x15),
        compile3("LINK", language=0x07) + compile3("LINK", language=0x07),
    )
    assert [(i.module, i.language_name) for i in pdb.compile_info()] == [
        ("a.obj", "Rust"),
        ("KERNEL32.dll", "Link"),
        ("KERNEL32.dll", "Link"),
    ]


def test_a_damaged_record_is_reported_rather_than_silently_missing():
    """The listing being one short is the failure mode; `diagnose()` saying so
    is what stops it being indistinguishable from a file that has one fewer."""
    short = struct.pack("<HHI", 6, codeview.S_COMPILE3, 0)
    pdb = _pdb(short, compile3("LINK", language=0x07))

    assert [i.module for i in pdb.compile_info()] == ["KERNEL32.dll"]
    d = pdb.diagnose()
    assert d.module_kinds[codeview.S_COMPILE3] == 2, "the walk still sees both"
    assert d.malformed_records == 1
    assert any("shorter than the kind" in w for w in d.warnings)


def test_a_module_without_the_record_is_simply_absent():
    pdb = _pdb(pub32("f", 1, 0x10), compile3("LINK", language=0x07))
    assert [i.module for i in pdb.compile_info()] == ["KERNEL32.dll"]


# --- against real linker output -----------------------------------------------

# Counts and the (language, machine) split come from
#   llvm-pdbutil dump --symbols <pdb> | grep -A1 'S_COMPILE3 \[' | grep language
GOLDEN = [
    pytest.param("sqlite/x86/sqlite3.pdb", {
        ("C", "Pentium III"): 12,
        ("C++", "Pentium III"): 12,
        ("Link", "Intel 80386"): 83,
        ("Link", "Pentium III"): 37,
        ("MASM", "Pentium Pro"): 10,
        ("cvtres", "Intel 80386"): 1,
    }, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", {
        ("C", "x64"): 11,
        ("C++", "x64"): 12,
        ("Link", "x64"): 118,
        ("MASM", "x64"): 3,
        ("cvtres", "x64"): 1,
    }, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", {
        ("Rust", "x64"): 9,
        ("Link", "x64"): 1,
    }, id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", {
        ("Rust", "Pentium III"): 1,
        ("Link", "Intel 80386"): 1,
    }, id="rustpe-i686"),
]


def _fixture(rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    return PDB.open(str(path))


@pytest.mark.parametrize("rel,expected", GOLDEN)
def test_real_language_and_machine_split(rel, expected):
    import collections

    infos = _fixture(rel).compile_info()
    got = collections.Counter((i.language_name, i.machine_name) for i in infos)
    assert dict(got) == expected
    assert all(i.compiler for i in infos), "a producer always names itself"
    assert all(i.module for i in infos), "every record belongs to a module"


@pytest.mark.parametrize("rel,expected", GOLDEN)
def test_the_record_count_matches_the_module_walk(rel, expected):
    """`diagnose()` counts S_COMPILE3 by walking every module stream. The two
    disagreeing means records are being dropped between the walk and the
    listing."""
    pdb = _fixture(rel)
    assert len(pdb.compile_info()) == \
        pdb.diagnose().module_kinds.get(codeview.S_COMPILE3, 0)
    assert len(pdb.compile_info()) == sum(expected.values())


@pytest.mark.parametrize("rel,expected", GOLDEN)
def test_the_symbol_record_stream_holds_none(rel, expected):
    """Which is why the listing does not deduplicate: a module stream and the
    symbol-record stream overlap for symbols, but not for this kind."""
    pdb = _fixture(rel)
    assert codeview.extract_compile_infos(pdb._symbol_records()) == []
    assert sum(expected.values()) > 0, "a count of zero would assert nothing"


@pytest.mark.parametrize("rel", ["rustpe/rust_pe_symbols_msvc.pdb",
                                 "rustpe32/rust_pe_symbols_i686.pdb"])
def test_a_rust_binary_says_so(rel):
    """The answer a name-shape heuristic can only approximate."""
    infos = _fixture(rel).compile_info()
    rust = [i for i in infos if i.language_name == "Rust"]
    assert rust
    assert all("rustc version" in i.compiler for i in rust)
