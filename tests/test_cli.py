"""The command line, over one synthetic PDB that carries every record kind.

The point of these is coverage of the *interface*: that every listing the
library can produce has a subcommand, that a record reaches stdout one line at
a time, and that counts and warnings stay on stderr so a redirected stdout
holds records and nothing else.
"""

import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from purepdb import PDB, MsfError, c13, codeview
from purepdb.__main__ import _COMMANDS, main
from tests._synth import (
    build_msf,
    constant,
    dbi_stream,
    file_checksums,
    gdata32,
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
            # A second module, so the `modules` listing is more than one
            # line, and one with no symbol stream, so `diagnose` has a module
            # to leave out of `modules_with_symbols`.
            + module_info("crt.obj", "crt.obj", sym_stream=0xFFFF,
                          sym_byte_size=0))

    publics = [pub32("_main", 1, 0x40)]
    symrecords = (b"".join(publics) + constant("MAX_PAGE", 42) + udt("Pager")
                  + gdata32("g_page_cache", 1, 0x800))

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
    """On stderr: nobody asked for it, so it must not land in a file meant
    to hold records."""
    assert main(["purepdb"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    for name in _COMMANDS:
        assert f"    {name}" in captured.err


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_is_asked_for_so_it_is_output(capsys, flag):
    assert main(["purepdb", flag]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    for name in _COMMANDS:
        assert f"    {name}" in captured.out


def test_an_unknown_command_is_rejected_with_the_list(capsys):
    assert main(["purepdb", "frobnicate", "x.pdb"]) == 2
    err = capsys.readouterr().err
    assert "unknown command: frobnicate" in err
    assert "functions" in err


# Public listings on `PDB` that deliberately have no subcommand of their own,
# and what reaches the same data instead. Asserted against the class below, so
# adding a listing to `PDB` fails this test until it is either given a command
# or written down here -- which is the regression the CLI had.
UNLISTED = {
    "module_procs": "the proc half of `functions`",
    "proc_refs": "the same procedures by another route; `diagnose` counts",
    "resolve_proc_ref": "takes an argument; not a listing",
    "module_of": "takes an address; `functions` prints its answer per line",
    "to_rva": "takes an address",
    "module_symbol_bytes": "raw bytes for one module",
    "module_c13_bytes": "raw bytes for one module",
    "publics_stream": "the hash stream, which holds no records",
    "string_table": "resolves a file-name offset; `lines` prints the result",
    "id_table": "resolves an inlinee id; `inline` prints the result",
    "named_streams": "stream name -> index; `diagnose` reports what it found",
    "derived_sections": "printed by `sections` when it is the table in use",
    "original_sections": "printed by `sections` when it is the table in use",
    "omap": "an address map, not a listing; `diagnose` reports its size",
    "open": "constructor",
    "from_bytes": "constructor",
}


def test_no_public_listing_on_pdb_is_missing_a_subcommand():
    """The regression this file exists for: the CLI falling behind the library.

    Hard-coding the command set would pass while `PDB` grew listings nothing
    could print, which is exactly the state issue #28 describes -- so this
    walks `PDB` itself.
    """
    printed = {
        "functions", "public_symbols", "data_symbols", "labels", "thunks",
        "trampolines", "inline_sites", "lines", "constants", "udts",
        "section_contributions", "sections", "info", "diagnose",
    }
    public = {name for name, value in vars(PDB).items()
              if not name.startswith("_")
              and (callable(value) or isinstance(value, property))}

    assert public - printed - set(UNLISTED) == set(), (
        "a public listing on PDB that no subcommand prints")
    assert len(_COMMANDS) == len(printed), (
        "one subcommand per listing, and nothing else")


# --- one test per listing ---------------------------------------------------

def test_functions(sample, capsys):
    out, err = _run(capsys, "functions", sample)
    assert out == [
        "0x00001040  proc     size=0x100     +1   main",
        "0x00001200  thunk    size=0x6       -    RoInitialize",
    ]
    assert "2 functions" in err


def test_publics(sample, capsys):
    out, err = _run(capsys, "publics", sample)
    assert out == ["seg=1   off=0x00000040  [func]  _main"]
    assert "1 public symbols" in err


def test_data(sample, capsys):
    out, err = _run(capsys, "data", sample)
    assert out == ["0x00001800  global   g_page_cache"]
    assert "1 data records" in err


def test_sections(sample, capsys):
    out, err = _run(capsys, "sections", sample)
    assert out == ["0x00001000  size=10000      X  .text"]
    assert "1 sections" in err


def test_sections_prints_the_pre_bbt_table_when_that_is_the_only_one(tmp_path,
                                                                     capsys):
    """A BBT-processed PDB can carry slot 10 and no slot 5.

    Every address in such a file resolves -- against slot 10 -- so nothing
    warns, and a listing that consulted only slot 5 printed an empty table
    with no explanation at all.
    """
    module_stream = module_sym_stream(gproc32("main", 1, 0x40))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    dbg = [0xFFFF] * 11
    dbg[10] = 7  # the original section table, and no slot 5
    path = tmp_path / "bbt.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=dbg),
        publics_hash_stream([]),
        module_stream,
        b"",
        section_header(".text", 0x1000, 0x2000),
    ]))

    out, err = _run(capsys, "sections", str(path))
    assert out == ["0x00001000  size=2000       X  .text"]
    assert "1 sections" in err


def test_sections_falls_back_to_the_section_map_when_neither_table_is_there(
        tmp_path, capsys):
    """The third link of the chain, and the last one that answers anything.

    With no slot 5 and no slot 10 the segments are rebuilt from DBI's Section
    Map, which records sizes but no addresses -- so the listing exists and
    every address in it is a reconstruction, which is what the warning says.
    """
    from tests._synth import section_map

    module_stream = module_sym_stream(gproc32("main", 1, 0x40))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / "sectionmap-only.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 11,
                   sec_map=section_map([(0x109, 1, 0x2000)])),
        publics_hash_stream([]),
        module_stream,
        b"",
    ]))

    out, err = _run(capsys, "sections", str(path))

    assert len(out) == 1, "the rebuilt table is the only one left"
    assert out[0].startswith("0x")
    assert any("rebuilt" in line or "reconstruction" in line for line in err), (
        "a rebuilt table must say every address in it is a reconstruction")


def test_labels(sample, capsys):
    out, err = _run(capsys, "labels", sample)
    assert out == ["0x00001050  main_retry"]
    assert "1 labels" in err


def test_thunks(sample, capsys):
    out, err = _run(capsys, "thunks", sample)
    assert out == ["0x00001200  size=6        notype              RoInitialize"]
    assert "1 thunks" in err


def test_a_data_record_with_no_name_keeps_its_columns(tmp_path, capsys):
    """87 of sqlite3 x64's 540 data records carry an empty name, and 151 of
    x86's 633 do, so this is most of a real listing rather than an edge: the
    line used to end after the scope column, one field short."""
    module_stream = module_sym_stream(gdata32("", 1, 0x800))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / "nameless-data.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7]),
        publics_hash_stream([]),
        module_stream,
        b"",
        section_header(".text", 0x1000, 0x10000),
    ]))

    out, _err = _run(capsys, "data", str(path))

    assert out == ["0x00001800  global   ?"]


# THUNK_ORDINAL, against what `llvm-pdbutil` prints for each: 4 is
# THUNK_ORDINAL_LOAD and 5 and 6 are the two trampoline ordinals. 4 and 5 were
# named after delay-loading, which no ordinal means, and 6 was absent, so it
# printed as a bare `0x06`. No fixture in the corpus carries 4, 5 or 6.
THUNK_ORDINALS = [
    (0, "notype"), (1, "adjustor"), (2, "vcall"), (3, "pcode"),
    (4, "load"), (5, "tramp-incremental"), (6, "tramp-branchisland"),
]


@pytest.mark.parametrize("ordinal,name", THUNK_ORDINALS)
def test_every_thunk_ordinal_is_named_and_keeps_the_columns(ordinal, name,
                                                            tmp_path, capsys):
    module_stream = module_sym_stream(
        thunk32("RoInitialize", 1, 0x200, ordinal=ordinal))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / f"thunk-{ordinal}.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7]),
        publics_hash_stream([]),
        module_stream,
        b"",
        section_header(".text", 0x1000, 0x10000),
    ]))

    out, _err = _run(capsys, "thunks", str(path))

    assert len(out) == 1
    assert f" {name} " in f" {out[0]} ", "the ordinal must be named, not hex"
    # The name is last, so an ordinal wider than its field would push it out
    # of the column every other line puts it in.
    assert out[0].endswith("  RoInitialize")
    assert out[0].index("RoInitialize") == len(out[0]) - len("RoInitialize")


def test_trampolines(sample, capsys):
    out, err = _run(capsys, "trampolines", sample)
    assert out == ["0x00001300  size=5        -> 0x00001040"]
    assert "1 trampolines" in err


def test_inline(sample, capsys):
    out, err = _run(capsys, "inline", sample)
    assert out == ["0x00001044  size=3        helper\t<- main"]
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
    assert out == ["0x1004      Pager"]
    assert "1 type names" in err


def test_modules(sample, capsys):
    """The contribution summary: how much of the image each input claims."""
    out, err = _run(capsys, "modules", sample)
    assert out == ["       1  main.obj", "       0  crt.obj"]
    assert "2 modules" in err


def test_modules_accounts_for_a_contribution_with_no_module(tmp_path, capsys):
    """A contribution naming a module the list does not have is not dropped.

    That is the case `module_of()` answers None for, so leaving it out of the
    summary would make the counts quietly disagree with the table.
    """
    module_stream = module_sym_stream(gproc32("main", 1, 0x40))
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / "stray.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7],
                   sec_contrib=section_contributions([(1, 0x0, 0x100, 0),
                                                      (1, 0x100, 0x100, 9)])),
        publics_hash_stream([]),
        module_stream,
        b"",
        section_header(".text", 0x1000, 0x10000),
    ]))

    out, err = _run(capsys, "modules", str(path))
    assert out == [
        "       1  main.obj",
        "       1  <1 module index(es) not in the module list>",
    ]
    # The stray line is contributions, not a module: counting it would say
    # this file has two modules when the module list holds one.
    assert err[:2] == ["", "1 modules"]


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
    """A redirected stdout must hold records and nothing else.

    The sample carries at least one record of every kind, so an empty listing
    is a failure here rather than something to skip over -- which is what let
    an earlier version of this test pass on a listing that printed nothing.
    """
    for name, (_handler, noun, _columns) in _COMMANDS.items():
        if noun is None:
            continue
        out, err = _run(capsys, name, sample)
        assert out, f"{name} printed no records at all"
        assert all(line.strip() for line in out), (
            f"{name} printed a blank line")
        assert not any(noun in line for line in out), (
            f"{name} printed its count on stdout")
        assert [line for line in err if line] == [f"{len(out)} {noun}"], (
            f"{name}: stderr must be the count and nothing else here")


def test_an_unresolvable_address_is_not_printed_as_a_number(tmp_path, capsys):
    """No section-header stream, so nothing resolves, and the column still
    lines up."""
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


# --- against real linker output ---------------------------------------------

REAL = (Path(__file__).resolve().parent / "data" / "rustpe"
        / "rust_pe_symbols_msvc.pdb")
SQLITE = (Path(__file__).resolve().parent / "data" / "sqlite" / "x86"
          / "sqlite3.pdb")

# Every listing whose first column is an address, each against a fixture that
# actually holds records of that kind. The synthetic sample cannot check these:
# its names hold no spaces, its code sizes are three hex digits, and its paths
# are short -- so it agrees with any column layout at all. And one fixture is
# not enough either: rustpe has no thunks and no trampolines, while the sqlite
# builds have no inline sites, so a single choice leaves some loop empty and
# the case passes having checked nothing.
ADDRESS_FIRST = [
    ("functions", REAL),
    ("data", REAL),
    ("labels", REAL),
    ("thunks", SQLITE),
    ("trampolines", SQLITE),
    ("inline", REAL),
    ("lines", REAL),
    ("sections", REAL),
]


def _real(capsys, command, path=REAL):
    if not path.exists():
        pytest.skip("groundtruth fixture missing")
    return _run(capsys, command, str(path))[0]


@pytest.mark.parametrize("command,fixture", ADDRESS_FIRST)
def test_the_first_column_is_an_address_on_a_real_pdb(command, fixture,
                                                      capsys):
    lines = _real(capsys, command, fixture)

    for line in lines:
        first = line.split()[0]
        assert re.fullmatch(r"0x[0-9a-f]{8}|\?{6}", first), (
            f"{command}: {first!r} is not an address")

    assert lines, f"{command} printed nothing, so this checked no column"


def test_an_empty_name_is_printed_as_a_placeholder(capsys):
    """A blank would shorten the line and shift every column after it.

    Not hypothetical: all 160 label records in the rustpe fixture carry an
    empty name and segment 0, so this is what that whole listing looks like.
    """
    lines = _real(capsys, "labels")

    assert lines, "the fixture is supposed to hold labels"
    assert set(lines) == {"    ??????  ?"}


def test_a_name_with_spaces_survives_being_printed(capsys):
    """The check the synthetic fixture cannot make.

    Rust and C++ names hold spaces -- `closure$0<tuple$<> >` -- so a field
    printed after one is unrecoverable. Splitting off exactly the leading
    columns has to give back a name the library agrees exists.
    """
    lines = _real(capsys, "functions")
    names = {n for f in PDB.open(str(REAL)).functions() for n in f.names}
    spaced = 0
    for line in lines:
        name = line.split(maxsplit=4)[4]
        assert name in names, f"{name!r} is not a name purepdb reported"
        spaced += " " in name
    assert spaced, "expected the fixture to carry names with spaces"


def test_an_inline_site_and_its_parent_are_both_recoverable(capsys):
    """Two names on one line, so they are separated by a tab."""
    lines = _real(capsys, "inline")
    pdb = PDB.open(str(REAL))
    names = {site.name for site in pdb.inline_sites()}
    parents = {site.parent for site in pdb.inline_sites()}

    assert lines
    for line in lines:
        record, tab, parent = line.partition("\t")
        assert tab, "the two names must be tab-separated"
        assert record.split(maxsplit=2)[2] in names
        assert parent.removeprefix("<- ") in parents


# --- the ways a process can go wrong, rather than a PDB ---------------------

def test_a_stream_that_fails_mid_listing_is_reported_not_raised(sample, capsys,
                                                                monkeypatch):
    """A stream can be unreadable without the open having said so.

    `PDB.open` reads the DBI stream and nothing else, so a nil or unmapped
    stream -- what a real MSF writes for one that was deleted -- surfaces at
    the moment a listing reaches it.
    """
    def unreadable(_pdb):
        raise MsfError("stream 7 is a nil stream")

    monkeypatch.setitem(_COMMANDS, "labels",
                        (unreadable, "labels", "rva  name"))
    assert main(["purepdb", "labels", sample]) == 1
    captured = capsys.readouterr()
    assert "error:" in captured.err and "nil stream" in captured.err
    assert "Traceback" not in captured.err


def test_a_stream_that_fails_in_the_warning_step_is_reported_too(
        sample, capsys, monkeypatch):
    """The subtle half: `diagnose()` reads streams the listing never touched,
    so it can fail on a file that listed perfectly well -- with the records
    already printed."""
    def unreadable(_self):
        raise MsfError("stream 1 is a nil stream")

    monkeypatch.setattr(PDB, "diagnose", unreadable)
    assert main(["purepdb", "labels", sample]) == 1
    captured = capsys.readouterr()
    assert captured.out == "0x00001050  main_retry\n", "the listing still ran"
    assert "error:" in captured.err
    assert "Traceback" not in captured.err


def test_a_closed_pipe_is_not_an_error(sample, capsys, monkeypatch):
    """`purepdb lines big.pdb | head -3` closes the pipe on the third line.

    Exercised here by raising what the write would raise, because a real pipe
    race is not something to put in a suite.
    """
    def closes_early(_pdb):
        print("0x00001000  first")
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setitem(_COMMANDS, "labels",
                        (closes_early, "labels", "rva  name"))
    assert main(["purepdb", "labels", sample]) == 141
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt", reason="141 is the POSIX SIGPIPE status")
def test_a_reader_that_leaves_before_the_buffer_flushes():
    """The case an in-process test cannot see.

    A listing small enough to sit in the stdio buffer performs no write while
    `main()` is running, so the closed pipe is discovered by the interpreter's
    exit-time flush -- where nothing catches it, and the process ends on
    status 120 with a message from Python instead of 141.
    """
    if not REAL.exists():
        pytest.skip("groundtruth fixture missing")

    with subprocess.Popen(
            [sys.executable, "-m", "purepdb", "functions", str(REAL)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=Path(__file__).resolve().parent.parent) as proc:
        assert proc.stdout is not None and proc.stderr is not None
        proc.stdout.close()  # the reader leaves before a single byte is read
        stderr = proc.stderr.read().decode()

    assert proc.returncode == 141
    assert "Exception ignored" not in stderr
    assert "Traceback" not in stderr


@pytest.mark.skipif(os.name == "nt", reason="closing fd 1 is a POSIX shape")
def test_a_closed_stdout_reports_once_and_exits_one():
    """`purepdb labels x.pdb >&-`: unwritable before the first record.

    A subprocess, because the interpreter's exit-time flush is what makes the
    difference -- it turned a reported error into status 120 and a second
    message no test running in-process would see.
    """
    repo = str(Path(__file__).resolve().parent.parent)
    program = (
        "import os, sys\n"
        f"sys.path.insert(0, {repo!r})\n"
        "os.close(1)\n"
        "from purepdb.__main__ import cli\n"
        f"sys.argv = ['purepdb', 'labels', {str(REAL)!r}]\n"
        "raise SystemExit(cli())\n"
    )
    if not REAL.exists():
        pytest.skip("groundtruth fixture missing")

    proc = subprocess.run([sys.executable, "-c", program],
                          capture_output=True, text=True)
    assert proc.returncode == 1
    assert proc.stderr.count("Bad file descriptor") == 1
    assert "Exception ignored" not in proc.stderr


def test_ctrl_c_is_not_a_traceback(monkeypatch):
    from purepdb import __main__ as entry

    def interrupted(_argv):
        raise KeyboardInterrupt

    monkeypatch.setattr(entry, "main", interrupted)
    assert entry.cli() == 130


def _in_a_subprocess(body: str, *, argv: str) -> subprocess.CompletedProcess:
    """Run `cli()` in a fresh interpreter, so the exit-time flush is real."""
    repo = str(Path(__file__).resolve().parent.parent)
    program = (
        "import os, sys\n"
        f"sys.path.insert(0, {repo!r})\n"
        f"{body}"
        "from purepdb.__main__ import cli\n"
        f"sys.argv = {argv}\n"
        "raise SystemExit(cli())\n"
    )
    return subprocess.run([sys.executable, "-c", program],
                          capture_output=True, text=True)


def test_a_stdout_closed_by_the_shell_is_reported_not_a_traceback():
    """`purepdb functions x.pdb >&-` -- closed before the interpreter starts.

    Different from closing the descriptor afterwards: CPython cannot build a
    stream over it at all and leaves `sys.stdout` as None. `print()` then
    discards every record in silence, so without this the listing vanished,
    the count on stderr still claimed it, and the flush raised AttributeError.
    """
    if not REAL.exists():
        pytest.skip("groundtruth fixture missing")

    proc = _in_a_subprocess("sys.stdout = None\n",
                            argv=f"['purepdb', 'functions', {str(REAL)!r}]")

    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "standard output is closed" in proc.stderr
    assert "functions" not in proc.stderr, "no count for a listing nobody got"


def test_a_stdout_closed_by_the_shell_does_not_traceback_on_a_missing_file():
    """The same shape, reaching the error path instead: the handler that
    settles stdout asked a None for its descriptor."""
    proc = _in_a_subprocess("sys.stdout = None\n",
                            argv="['purepdb', 'functions', '/nonexistent.pdb']")

    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr


def test_a_closed_stderr_does_not_push_diagnostics_into_the_records():
    """`purepdb functions bad.pdb 2>&-` leaves `sys.stderr` as None, and
    `print(..., file=None)` means *stdout* -- so the error message, the count
    and every warning would land in among the records."""
    proc = _in_a_subprocess("sys.stderr = None\n",
                            argv="['purepdb', 'functions', '/nonexistent.pdb']")

    assert proc.returncode == 1
    assert proc.stdout == "", "stdout holds records and nothing else"


def test_ctrl_c_keeps_the_records_already_written(tmp_path):
    """Ctrl-C is the one exit that does not mean stdout is broken.

    Abandoning the descriptor here would throw away a listing that was merely
    interrupted; not settling it at all let the exit flush fail, turning 130
    into 120.
    """
    proc = _in_a_subprocess(
        "import purepdb.__main__ as entry\n"
        "def interrupted(_argv):\n"
        "    print('a record that was already written')\n"
        "    raise KeyboardInterrupt\n"
        "entry.main = interrupted\n",
        argv="['purepdb', 'functions', 'unused.pdb']")

    assert proc.returncode == 130
    assert proc.stdout == "a record that was already written\n"
    assert "Exception ignored" not in proc.stderr


def test_ctrl_c_on_an_unwritable_stdout_still_exits_130():
    """The descriptor is gone, so the buffered line cannot be written.

    Ctrl-C is the one exit that leaves stdout unsettled, so the interpreter's
    exit flush raised where nothing catches it: status 130 became 120, with a
    message from the interpreter after the command had already finished.
    """
    proc = _in_a_subprocess(
        "os.close(1)\n"
        "import purepdb.__main__ as entry\n"
        "def interrupted(_argv):\n"
        "    print('buffered, and now unwritable')\n"
        "    raise KeyboardInterrupt\n"
        "entry.main = interrupted\n",
        argv="['purepdb', 'functions', 'unused.pdb']")

    assert proc.returncode == 130
    assert "Exception ignored" not in proc.stderr


def test_main_does_not_take_its_callers_stdout_away(capfd, tmp_path):
    """`main()` is documented as callable from a test, so it must not touch
    the process's descriptors. It settled stdout on any OSError -- including
    a plain missing file, which has nothing to do with stdout -- pointing the
    caller's descriptor at the null device and leaking the one it opened.

    `capfd`, not `capsys`: the damage is a `dup2` onto a real descriptor, and
    `capsys` replaces stdout with an object that has none, so the call fails
    harmlessly and the bug stays invisible.
    """
    assert main(["purepdb", "functions", str(tmp_path / "nonexistent.pdb")]) == 1

    print("still writing after main() returned")

    assert "still writing after main() returned" in capfd.readouterr().out


def test_main_leaves_stdout_alone_when_the_pipe_closes(capfd, monkeypatch):
    """The same rule for the other branch. `main()` reports 141 and leaves
    settling the descriptor to `cli()`, which owns the process."""
    from purepdb import __main__ as entry

    def closed(_path):
        raise BrokenPipeError

    monkeypatch.setattr(entry.PDB, "open", staticmethod(closed))
    assert main(["purepdb", "functions", "unused.pdb"]) == 141

    print("still writing after a broken pipe")

    assert "still writing after a broken pipe" in capfd.readouterr().out


@pytest.mark.parametrize("raw,printed", [
    ("plain", "plain"),
    # spaces, angle brackets and non-ASCII are all legitimate in a name
    ("std::rt::lang_start::closure$0<tuple$<> >",
     "std::rt::lang_start::closure$0<tuple$<> >"),
    ("caf\u00e9_\u4e2d\u6587", "caf\u00e9_\u4e2d\u6587"),
    ("a\nb", "a\\x0ab"),
    ("a\x1b[31mb", "a\\x1b[31mb"),
    ("a\x7fb", "a\\x7fb"),
    ("a\x85b", "a\\x85b"),          # NEL, a C1 control
    ("a\u2028b", "a\\u2028b"),      # LINE SEPARATOR: splitlines() breaks here
    ("a\u202eb", "a\\u202eb"),      # RTL override: displays as another name
    ("a\U000e0001b", "a\\U000e0001b"),  # a tag character, astral plane
])
def test_only_the_unprintable_is_escaped(raw, printed):
    from purepdb.__main__ import _text

    assert _text(raw) == printed


def test_a_warning_quoting_a_hostile_module_name_is_escaped(tmp_path, capsys):
    """A warning quotes the module it found damage in, and that name is
    file-supplied too: raw, it can erase the line and print another."""
    hostile = "quiet.obj\x1b[2K\rHACKED\nnext.obj"
    truncated = struct.pack("<HH", 1, codeview.S_LABEL32)  # length below 2
    module_stream = module_sym_stream(gproc32("main", 1, 0x40) + truncated)
    mods = module_info(hostile, hostile, sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / "hostile-module.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7]),
        publics_hash_stream([]),
        module_stream,
        b"",
        section_header(".text", 0x1000, 0x10000),
    ]))

    _out, err = _run(capsys, "labels", str(path))
    assert any("stopped early" in line for line in err), "expected the warning"
    for line in err:
        assert "\x1b" not in line and "\r" not in line

    # `diagnose` prints the same warnings through a different path -- as its
    # report rather than as a listing's trailer -- and it is the command a
    # reader runs *because* a file looked wrong, so on the most hostile input.
    out, _err = _run(capsys, "diagnose", str(path))
    assert any("stopped early" in line for line in out), "expected the warning"
    for line in out:
        assert "\x1b" not in line and "\r" not in line
    escaped = r"quiet.obj\x1b[2K\x0dHACKED\x0anext.obj"
    assert any(escaped in line for line in err)


def test_control_characters_in_a_name_are_escaped(tmp_path, capsys):
    """A name is untrusted input: a newline in one would put a record on two
    lines, and an escape sequence would drive the terminal."""
    records = (gproc32("main", 1, 0x40)
               + label32("evil\nsecond\x1b[31mline", 1, 0x50))
    module_stream = module_sym_stream(records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / "hostile.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7]),
        publics_hash_stream([]),
        module_stream,
        b"",
        section_header(".text", 0x1000, 0x10000),
    ]))

    out, _err = _run(capsys, "labels", str(path))
    assert out == [r"0x00001050  evil\x0asecond\x1b[31mline"]


def test_a_console_that_cannot_encode_a_name_still_lists(tmp_path):
    """An undecodable byte in a name becomes U+FFFD, which cp1252 cannot
    encode.

    Run as a subprocess because it is the console encoding that is under test,
    and pytest's capture replaces it.
    """
    # Built by hand: the name is not valid UTF-8, which the string builders
    # cannot express and a real damaged PDB has no trouble carrying.
    undecodable = make_record(
        codeview.S_LABEL32,
        struct.pack("<IHB", 0x50, 1, 0) + b"caf\xff\x00")
    records = gproc32("main", 1, 0x40) + undecodable
    module_stream = module_sym_stream(records)
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_stream))
    path = tmp_path / "unencodable.pdb"
    path.write_bytes(build_msf([
        b"",
        pdb_info_stream({}),
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7]),
        publics_hash_stream([]),
        module_stream,
        b"",
        section_header(".text", 0x1000, 0x10000),
    ]))

    proc = subprocess.run(
        [sys.executable, "-m", "purepdb", "labels", str(path)],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONIOENCODING": "ascii"},
        cwd=Path(__file__).resolve().parent.parent,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "0x00001050" in proc.stdout


def test_a_hostile_file_name_is_escaped_in_the_error(capsys, monkeypatch):
    """`purepdb functions *` over an untrusted directory: the name of a file
    that fails to open is as attacker-chosen as the records inside one.

    The name is never written to disk here -- Windows rejects a file name
    holding control characters outright, so only POSIX can carry the real
    thing, and what is under test is the formatting either way.
    """
    def unreadable(_path):
        raise MsfError("bad magic")

    monkeypatch.setattr(PDB, "open", staticmethod(unreadable))
    assert main(["purepdb", "functions", "quiet.pdb\x1b[2K\rHACKED"]) == 1

    err = capsys.readouterr().err
    assert "\x1b" not in err and "\r" not in err
    assert r"quiet.pdb\x1b[2K\x0dHACKED" in err


def test_a_hostile_exception_message_is_escaped(capsys, monkeypatch):
    """The other half of that line. A `PdbError` quotes what it found -- a
    stream description, a module name -- so the message is file-supplied even
    when the path is not."""
    def unreadable(_path):
        raise MsfError("module \x1b[2K\rHACKED is not a stream")

    monkeypatch.setattr(PDB, "open", staticmethod(unreadable))
    assert main(["purepdb", "functions", "fine.pdb"]) == 1

    err = capsys.readouterr().err
    assert "\x1b" not in err and "\r" not in err
    assert r"module \x1b[2K\x0dHACKED" in err


def test_a_hostile_os_error_is_escaped(capsys, monkeypatch):
    """An OSError carries the file name it failed on, which is the same
    attacker-chosen string, through a different branch."""
    def unreadable(_path):
        raise OSError(2, "No such file \x1b[2K\rHACKED")

    monkeypatch.setattr(PDB, "open", staticmethod(unreadable))
    assert main(["purepdb", "functions", "fine.pdb"]) == 1

    err = capsys.readouterr().err
    assert "\x1b" not in err and "\r" not in err
    assert "HACKED" in err


def test_an_unknown_command_is_escaped(capsys):
    """Typed by the user rather than read from a file, but echoed back, and
    the escaping rule is one rule."""
    assert main(["purepdb", "func\x1b[2K\rHACKED", "x.pdb"]) == 2

    err = capsys.readouterr().err
    assert "\x1b" not in err and "\r" not in err
