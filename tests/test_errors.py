"""Every rejection must name the format and be catchable as one exception.

A consumer sweeping a directory of real binaries hits these constantly -- .NET
projects ship Portable PDBs, and MSVC leaves `vc140.pdb` next to the .obj files
-- so `struct.error` escaping the parser, or a bare "bad magic", is a defect.
"""

import struct

import pytest

from purepdb import MsfError, PDB, PdbError, UnsupportedPdbError
from purepdb.dbi import DbiStream
from purepdb.msf import MsfFile
from tests._synth import (
    build_msf, dbi_stream, module_info, module_sym_stream, publics_hash_stream,
    section_header,
)


def test_portable_pdb_is_named():
    """.NET/Roslyn PDBs are not MSF containers at all."""
    data = b"BSJB\x01\x00\x01\x00" + b"\x00" * 4 + b"PDB v1.0" + b"\x00" * 512
    with pytest.raises(UnsupportedPdbError, match="Portable PDB"):
        MsfFile(data)


def test_msf_2_is_named():
    data = b"Microsoft C/C++ program database 2.00\r\n\x1aJG" + b"\x00" * 512
    with pytest.raises(UnsupportedPdbError, match="MSF 2.00"):
        MsfFile(data)


def test_unrecognised_magic_still_raises_msf_error():
    with pytest.raises(MsfError, match="bad magic"):
        MsfFile(b"not a pdb at all" + b"\x00" * 512)


def test_every_error_is_a_pdb_error():
    """One exception type is enough to wrap a directory sweep."""
    assert issubclass(MsfError, PdbError)
    assert issubclass(UnsupportedPdbError, PdbError)


def test_empty_dbi_stream_is_named_not_a_struct_error():
    """The compiler-intermediate vcNNN.pdb case."""
    with pytest.raises(UnsupportedPdbError, match="compiler-intermediate"):
        DbiStream.parse(b"")


def test_truncated_dbi_stream_raises_msf_error():
    with pytest.raises(MsfError, match="truncated"):
        DbiStream.parse(b"\xff" * 20)


def test_opening_a_pdb_with_an_empty_dbi_stream():
    """End to end: a valid MSF container whose DBI stream is empty."""
    streams = [b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"", b""]
    with pytest.raises(UnsupportedPdbError, match="compiler-intermediate"):
        PDB.from_bytes(build_msf(streams))


def test_cli_reports_rejections_without_a_traceback(tmp_path, capsys):
    """A directory sweep must not be interrupted by a stack trace."""
    from purepdb.__main__ import main

    bad = tmp_path / "managed.pdb"
    bad.write_bytes(b"BSJB\x01\x00\x01\x00" + b"\x00" * 512)
    assert main(["purepdb", "functions", str(bad)]) == 1
    assert "Portable PDB" in capsys.readouterr().err


def test_cli_reports_a_missing_file(tmp_path, capsys):
    from purepdb.__main__ import main

    assert main(["purepdb", "info", str(tmp_path / "nope.pdb")]) == 1
    assert "error:" in capsys.readouterr().err


def test_managed_code_is_diagnosed_as_such():
    """A Windows-format PDB for a .NET assembly holds S_GMANPROC, not procs.

    Without this branch the diagnostic blames FASTLINK, sending the reader
    after a problem that is not there.
    """
    from purepdb.codeview import S_GMANPROC
    from purepdb.pdb import Diagnostics

    d = Diagnostics(modules=3, modules_with_symbols=3, proc_records=0,
                    public_records=1, has_section_headers=True,
                    module_kinds={S_GMANPROC: 81})
    assert d.managed_proc_records == 81
    warning = "\n".join(d.warnings)
    assert "managed (.NET)" in warning
    assert "FASTLINK" not in warning


def test_a_pdb_with_no_symbols_at_all_is_empty_not_broken():
    """Zero functions is a legitimate answer; it must not raise."""
    module_syms = module_sym_stream(b"")
    mods = module_info("empty.obj", "empty.obj", sym_stream=5,
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
        b"",
    ]
    pdb = PDB.from_bytes(build_msf(streams))
    assert pdb.functions() == []
    assert any("no public records" in w for w in pdb.diagnose().warnings)
