"""The llvm-pdbutil cross-check script, checked without an LLVM toolchain.

`dev/validate_against_llvm.py` is the only thing verifying purepdb against a
reference implementation, and nothing was verifying it: a stub that printed
`ok` and returned 0 passed ruff, ty and the whole suite. These cover the
guards that decide whether a run may call itself agreement -- the parts that,
if they rot, turn the nightly job green over a comparison it never made.

The script is not shipped in the sdist, so these skip when it is absent.
"""

import importlib.util
import struct
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "dev" / "validate_against_llvm.py"

# The llvm-pdbutil stand-ins below are shell scripts, which Windows cannot
# execute. The script under test is a developer and nightly-CI tool that runs
# on POSIX; the tests that need no subprocess still run everywhere.
posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the llvm-pdbutil stand-ins are shell scripts")


@pytest.fixture(scope="module")
def validator():
    if not SCRIPT.exists():
        pytest.skip("dev/validate_against_llvm.py is not in this tree")
    spec = importlib.util.spec_from_file_location("_validate_against_llvm",
                                                  SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the module defines dataclasses, which look
    # themselves up in sys.modules while being built.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


@posix_only
def test_a_failed_reference_run_is_not_a_note(validator, tmp_path):
    """A dump that exited non-zero established nothing, whether or not it
    printed something first. Partial output compared against a full listing
    reads as purepdb inventing records; a crash that prints only its banner
    reads as agreement on nothing. Both used to print a note and exit 0.
    """
    tool = tmp_path / "failing-pdbutil"
    tool.write_text("#!/bin/sh\necho some output\n"
                    "echo 'llvm-pdbutil: error: broken' >&2\nexit 1\n")
    tool.chmod(0o755)

    with pytest.raises(validator.ParseError, match="failed"):
        validator.dump(str(tool), tmp_path / "x.pdb", ("--symbols",), {})


@posix_only
def test_a_reference_run_that_hangs_is_bounded(validator, tmp_path):
    tool = tmp_path / "hanging-pdbutil"
    tool.write_text("#!/bin/sh\nsleep 30\n")
    tool.chmod(0o755)

    original = validator.DUMP_TIMEOUT
    validator.DUMP_TIMEOUT = 1
    try:
        with pytest.raises(validator.ParseError, match="did not finish"):
            validator.dump(str(tool), tmp_path / "x.pdb", ("--symbols",), {})
    finally:
        validator.DUMP_TIMEOUT = original


@posix_only
def test_output_that_is_not_utf8_is_read_rather_than_raising(validator,
                                                             tmp_path):
    """llvm-pdbutil passes PDB name bytes through verbatim, so a localized
    build carries names that are not UTF-8. Decoding strictly ended the sweep
    with a UnicodeDecodeError instead of reporting the file."""
    tool = tmp_path / "latin1-pdbutil"
    tool.write_text("#!/bin/sh\nprintf 'name \\377\\376 here\\n'\n")
    tool.chmod(0o755)

    text = validator.dump(str(tool), tmp_path / "x.pdb", ("--symbols",), {})

    assert "name" in text and "here" in text


def test_a_line_entry_carrying_a_column_reads_the_line_not_the_column(
        validator):
    """`line/column/addr` blocks put `line:column` before the address. The
    column was being read as the line, and the line left over as unparsed
    residual, which failed the whole file -- and clang-cl emits columns by
    default."""
    raw = "    66:5 00000000 !   67:9 0000012A ! "

    assert validator._LINE_ENTRY.findall(raw) == [("66", "00000000"),
                                                  ("67", "0000012A")]
    assert not validator._LINE_ENTRY.sub("", raw).strip(" \t!")


@posix_only
def test_a_dump_the_tool_cannot_answer_is_not_a_disagreement(validator,
                                                             tmp_path):
    """`--section-contribs` needs the section-header stream, and exits 1 on a
    PDB that has no slot 5 -- which one fixture deliberately does not have.
    That is the reference implementation declining to read a shape it does not
    support, so it establishes nothing either way; failing the file for it
    reported purepdb as wrong about a comparison that never happened, and took
    the three checks after it down with it.
    """
    assert not issubclass(validator.ToolLimitation, validator.ParseError)

    runs = tmp_path / "runs"
    tool = tmp_path / "slot5-less-pdbutil"
    tool.write_text(f"#!/bin/sh\necho run >> {runs}\n"
                    "echo 'llvm-pdbutil: PDB does not contain the requested "
                    "image section header type' >&2\nexit 1\n")
    tool.chmod(0o755)
    cache: dict = {}

    for _ in range(2):
        with pytest.raises(validator.ToolLimitation, match="slot 5"):
            validator.dump(str(tool), tmp_path / "x.pdb",
                           ("--section-contribs",), cache)

    # Remembered, not just re-raised: two checks read this dump, and the
    # second must not re-run a tool whose answer is already known.
    assert runs.read_text().count("run") == 1


@posix_only
def test_an_unrecognised_failure_is_still_a_parse_error(validator, tmp_path):
    """The skip above is for specific, recognised messages. "exited 1" on its
    own is indistinguishable from the tool having changed under us, which is
    the case that must stop the run rather than quietly compare less."""
    tool = tmp_path / "broken-pdbutil"
    tool.write_text("#!/bin/sh\necho 'llvm-pdbutil: no such file' >&2\n"
                    "exit 1\n")
    tool.chmod(0o755)

    with pytest.raises(validator.ParseError, match="failed"):
        validator.dump(str(tool), tmp_path / "x.pdb",
                       ("--section-contribs",), {})


def test_inline_site_ranges_come_from_the_deltas_not_the_offsets(validator):
    """llvm-pdbutil moves its cursor past the length of a standalone
    `ChangeCodeLength` and not past the one fused into
    `ChangeCodeLengthAndCodeOffset`, so from the second range on, a site built
    out of the fused opcode prints every offset short by the lengths before
    it. Reading the absolutes off the fused form reported all 140 sites of the
    syzygy fixture as a disagreement.
    """
    fused = validator.RefRecord(
        kind="S_INLINESITE", header="", module=0,
        body=["           0C028143  code 0x143 (+0x143) code end 0x145 (+0x2)",
              "           0C0805    code 0x148 (+0x5) code end 0x150 (+0x8)"])

    # 0x14A, not the 0x148 llvm printed: the second range starts where the
    # first one ended plus the delta, which is the reading that makes the two
    # opcodes mean the same thing.
    assert validator.inline_site_ranges(fused) == [(0x143, 2), (0x14A, 8)]


def test_the_standalone_length_opcode_still_reads_as_llvm_prints_it(validator):
    """The other half of the same rule, and the reason this was not noticed
    for so long: on a file whose sites close their ranges with a standalone
    `ChangeCodeLength`, both cursors agree, and rustpe closes 5281 of them."""
    standalone = validator.RefRecord(
        kind="S_INLINESITE", header="", module=0,
        body=["           030C      code 0xC (+0xC)",
              "           0407      code end 0x13 (+0x7)",
              "           0311      code 0x24 (+0x11)",
              "           0405      code end 0x29 (+0x5)"])

    ranges = validator.inline_site_ranges(standalone)

    assert ranges == [(0xC, 7), (0x24, 5)]
    # Every one of them is exactly what llvm's own `code end` minus its length
    # says, which is what the old reading computed directly.
    assert ranges == [(0x13 - 7, 7), (0x29 - 5, 5)]


def test_a_cursor_rule_that_stopped_holding_raises(validator):
    """The model above is llvm's behaviour, not a fact about the format, so
    the run has to notice if it changes rather than compare against a rule
    that no longer holds. llvm's cursor is tracked beside ours and checked
    against every absolute offset printed."""
    moved = validator.RefRecord(
        kind="S_INLINESITE", header="", module=0,
        body=["           0C028143  code 0x143 (+0x143) code end 0x145 (+0x2)",
              # What llvm would print if it started advancing past a fused
              # length: 0x145 + 5 rather than 0x143 + 5.
              "           0C0805    code 0x14A (+0x5) code end 0x152 (+0x8)"])

    with pytest.raises(validator.ParseError, match="no longer holds"):
        validator.inline_site_ranges(moved)


def test_an_inlinee_id_llvm_resolved_in_the_wrong_stream_is_not_compared(
        validator):
    """llvm-pdbutil opens the IPI only when the info stream advertises the
    feature code saying there is one. The syzygy fixture's feature codes were
    dropped by whatever rewrote it, so `Has IDs: false` sits over a perfectly
    good IPI in stream 4 and every inlinee id resolves against the TPI -- the
    name printed is that of whatever type shares the index."""
    assert validator.resolves_item_ids("  Has IDs: true\n")
    assert not validator.resolves_item_ids("  Features: 0x0\n"
                                           "  Has IDs: false\n")

    with pytest.raises(validator.ParseError, match="ID stream"):
        validator.resolves_item_ids("  Has Types: true\n")


def test_every_check_is_named_for_the_verified_nothing_gate(validator):
    """The gate asks which checks compared no record, so a check missing from
    that list would be exempt from it without anything saying so."""
    names = validator.check_names()

    assert len(names) == len(set(names))
    assert set(names) >= {check.name for check in validator.CHECKS}
    assert set(validator.LATE_CHECKS) <= set(names)


def _run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True)


def test_a_negative_diff_limit_is_refused(validator):
    """`-1` is the usual "unlimited" idiom and did the opposite: the overflow
    test is `len(records) > limit`, which an empty difference list satisfies,
    so every agreeing check reported FAIL."""
    proc = _run("--max-diffs", "-1")

    assert proc.returncode == 2
    assert "cannot be negative" in proc.stderr


@pytest.fixture
def stub_tool(tmp_path):
    """A stand-in for llvm-pdbutil, so these test the guard under review and
    not whether an LLVM toolchain happens to be installed."""
    tool = tmp_path / "stub-pdbutil"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    return str(tool)


def test_a_corpus_with_no_pdbs_in_it_fails(validator, tmp_path, stub_tool,
                                           monkeypatch):
    """Verified nothing. Succeeding here is how a nightly job stays green
    through a checkout that lost its fixtures."""
    monkeypatch.setattr(validator, "DEFAULT_CORPUS", tmp_path)
    monkeypatch.setattr(sys, "argv",
                        ["validate", "--llvm-pdbutil", stub_tool])

    assert validator.main() == 1


@posix_only
def test_an_unreadable_file_is_reported_not_a_traceback(tmp_path, stub_tool):
    """A directory named *.pdb, a dangling symlink or an unreadable file
    raises OSError rather than PdbError, which ended the sweep with a
    traceback -- and `--allow-unreadable`, whose whole purpose is sweeping a
    corpus holding such files, did not cover it."""
    directory = tmp_path / "dir.pdb"
    directory.mkdir()

    proc = _run("--allow-unreadable", "--llvm-pdbutil", stub_tool,
                str(directory))

    assert "Traceback" not in proc.stderr
    assert proc.returncode == 1
    # The message, not just the status: the verified-nothing gate below would
    # also fail this run, and would describe the symptom rather than the cause.
    assert "all 1 file(s) were unreadable" in proc.stdout


@posix_only
def test_a_check_that_compared_nothing_fails_the_run(validator, tmp_path,
                                                     monkeypatch):
    """Two empty lists agree, so a check with no records on either side used
    to print `ok` -- indistinguishable from one that verified thousands. It
    is not a failure per file, since a fixture may legitimately have none of
    something, so it is answered for across the corpus.
    """
    from tests._synth import (
        build_msf,
        dbi_stream,
        module_info,
        module_sym_stream,
        publics_hash_stream,
        section_header,
    )

    module_syms = module_sym_stream(b"")
    mods = module_info("empty.obj", "empty.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    (tmp_path / "empty.pdb").write_bytes(build_msf([
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7]),
        publics_hash_stream([]),
        module_syms,
        b"",
        section_header(".text", 0x1000),
    ]))
    # Says nothing, so every check has an empty reference side to match the
    # empty purepdb side -- nine checks, all vacuous, all previously `ok`.
    silent = tmp_path / "silent-pdbutil"
    silent.write_text("#!/bin/sh\nexit 0\n")
    silent.chmod(0o755)

    monkeypatch.setattr(validator, "DEFAULT_CORPUS", tmp_path)
    monkeypatch.setattr(sys, "argv",
                        ["validate", "--llvm-pdbutil", str(silent)])

    assert validator.main() == 1
