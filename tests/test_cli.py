"""The command line, over one synthetic PDB that carries every record kind.

The point of these is coverage of the *interface*: that every listing the
library can produce has a subcommand, that a record reaches stdout one line at
a time, and that counts and warnings stay on stderr so a redirected stdout
holds records and nothing else.
"""

import struct

import pytest

from purepdb import c13, codeview
from purepdb.__main__ import _COMMANDS, main
from tests._synth import (
    build_msf,
    constant,
    dbi_stream,
    file_checksums,
    gproc32,
    inline_site,
    ipi_stream,
    label32,
    line_entries,
    make_record,
    module_info,
    module_sym_stream,
    names_stream,
    pdb_info_stream,
    pub32,
    publics_hash_stream,
    record_offsets,
    section_contributions,
    section_header,
    subsection,
    thunk32,
    trampoline,
    udt,
)


def _module_records() -> bytes:
    """A procedure whose scope holds a label and an inline site, then stubs.

    The `End` field has to name the byte offset of the closing S_END in the
    stream *as stored*, signature included, or the inline site is not paired
    with its procedure.
    """
    proc = gproc32("main", 1, 0x40, code_size=0x100)
    inner = (label32("main_retry", 1, 0x50)
             + inline_site(inlinee=0x1000,
                           annotations=bytes([0x0B, 0x04, 0x04, 0x03])))
    end_offset = 4 + len(proc) + len(inner)
    proc = proc[:8] + struct.pack("<I", end_offset) + proc[12:]

    return (proc + inner + make_record(codeview.S_END, b"")
            + thunk32("RoInitialize", 1, 0x200, length=6)
            + trampoline(thunk_segment=1, thunk_offset=0x300,
                         target_segment=1, target_offset=0x40))


@pytest.fixture
def sample(tmp_path):
    """A PDB with a proc, a public, a label, an inline site, a thunk, a
    trampoline, a constant, a UDT, line info and two modules."""
    raw_names, offsets = names_stream(["", "main.c"])
    checksums, entry_offsets = file_checksums([(offsets["main.c"], b"")])
    c13_region = (subsection(c13.DEBUG_S_FILECHECKSUMS, checksums)
                  + subsection(c13.DEBUG_S_LINES,
                               line_entries(segment=1, base_offset=0x40,
                                            file_entry=entry_offsets[0],
                                            entries=[(0, 7, True),
                                                     (0x10, 8, True)])))
    records = _module_records()
    module_stream = module_sym_stream(records) + c13_region
    mods = (module_info("main.obj", "main.obj", sym_stream=5,
                        sym_byte_size=4 + len(records),
                        c13_byte_size=len(c13_region))
            # A module with no symbol stream at all, which is what makes the
            # `modules` listing more than a one-line table.
            + module_info("crt.obj", "crt.obj", sym_stream=0xFFFF,
                          sym_byte_size=0))

    publics = [pub32("_main", 1, 0x40)]
    symrecords = b"".join(publics) + constant("MAX_PAGE", 42) + udt("Pager")

    streams = [
        b"",
        pdb_info_stream({"/names": 9}),
        b"",
        dbi_stream(public_stream=8, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6],
                   sec_contrib=section_contributions([(1, 0x0, 0x1000, 0)])),
        ipi_stream([("func", "helper")]),
        module_stream,
        section_header(".text", 0x1000, 0x10000),
        symrecords,
        publics_hash_stream(record_offsets(publics)),
        raw_names,
    ]
    path = tmp_path / "sample.pdb"
    path.write_bytes(build_msf(streams))
    return str(path)


def _run(capsys, *argv):
    assert main(["purepdb", *argv]) == 0
    captured = capsys.readouterr()
    return captured.out.splitlines(), captured.err.splitlines()


# --- the command table ------------------------------------------------------

def test_no_arguments_lists_every_command(capsys):
    assert main(["purepdb"]) == 2
    out = capsys.readouterr().out
    for name in _COMMANDS:
        assert f"    {name}" in out


def test_an_unknown_command_is_rejected_with_the_list(capsys):
    assert main(["purepdb", "frobnicate", "x.pdb"]) == 2
    err = capsys.readouterr().err
    assert "unknown command: frobnicate" in err
    assert "functions" in err


def test_every_listing_the_library_can_produce_has_a_subcommand():
    """The regression this file exists for: the CLI falling behind the library.

    Each name here is a public listing on `PDB`. Adding one without a
    subcommand is the state issue #28 describes.
    """
    assert set(_COMMANDS) == {
        "info", "diagnose", "functions", "publics", "labels", "thunks",
        "trampolines", "inline", "lines", "constants", "udts", "modules",
    }


# --- one test per listing ---------------------------------------------------

def test_functions(sample, capsys):
    out, err = _run(capsys, "functions", sample)
    assert out == [
        "0x00001040  proc     size=0x100   main  (+1 alias)",
        "0x00001200  thunk    size=0x6     RoInitialize",
    ]
    assert "2 functions" in err


def test_publics(sample, capsys):
    out, err = _run(capsys, "publics", sample)
    assert out == ["seg=1 off=0x40  [func]  _main"]
    assert "1 public symbols" in err


def test_labels(sample, capsys):
    out, err = _run(capsys, "labels", sample)
    assert out == ["0x00001050  main_retry"]
    assert "1 labels" in err


def test_thunks(sample, capsys):
    out, err = _run(capsys, "thunks", sample)
    assert out == ["0x00001200  size=6      notype      RoInitialize"]
    assert "1 thunks" in err


def test_trampolines(sample, capsys):
    out, err = _run(capsys, "trampolines", sample)
    assert out == ["0x00001300  size=5      -> 0x00001040"]
    assert "1 trampolines" in err


def test_inline(sample, capsys):
    out, err = _run(capsys, "inline", sample)
    assert out == ["0x00001044  size=3      helper  <- main"]
    assert "1 inline sites" in err


def test_lines(sample, capsys):
    out, err = _run(capsys, "lines", sample)
    assert out == ["0x00001040  main.c:7", "0x00001050  main.c:8"]
    assert "2 line entries" in err


def test_constants(sample, capsys):
    out, err = _run(capsys, "constants", sample)
    assert out == ["0x2a                MAX_PAGE"]
    assert "1 constants" in err


def test_udts(sample, capsys):
    out, err = _run(capsys, "udts", sample)
    assert out == ["0x00001004  Pager"]
    assert "1 type names" in err


def test_modules(sample, capsys):
    """The contribution summary: how much of the image each input claims."""
    out, err = _run(capsys, "modules", sample)
    assert out == ["       1  main.obj", "       0  crt.obj"]
    assert "2 modules" in err


def test_info(sample, capsys):
    out, err = _run(capsys, "info", sample)
    assert out[0] == "version   : 20000404"
    assert err == [], "a report prints no count and no warnings"


def test_diagnose(sample, capsys):
    out, _err = _run(capsys, "diagnose", sample)
    assert "modules            : 2 (1 with symbols)" in out
    assert "labels             : 1" in out
    assert "inline sites       : 1" in out


# --- the properties that make the output greppable --------------------------

def test_records_go_to_stdout_and_counts_to_stderr(sample, capsys):
    """A redirected stdout must hold records and nothing else."""
    for name, (_handler, noun, _columns) in _COMMANDS.items():
        if noun is None:
            continue
        out, err = _run(capsys, name, sample)
        assert all(line.strip() for line in out), f"{name} printed a blank line"
        assert any(noun in line for line in err), f"{name} printed no count"


def test_an_unresolvable_address_is_not_printed_as_a_number(tmp_path, capsys):
    """No section-header stream, so nothing resolves. The column still lines up."""
    records = gproc32("main", 1, 0x40) + label32("main_retry", 1, 0x50)
    module_stream = module_sym_stream(records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / "no-sections.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 6),
        publics_hash_stream([]),
        module_stream,
        b"",
    ]))

    out, err = _run(capsys, "labels", str(path))
    assert out == ["    ??????  main_retry"]
    assert any("no section-header stream" in line for line in err), (
        "an unresolved listing must say why")
