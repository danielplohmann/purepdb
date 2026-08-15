"""Every rejection must name the format and be catchable as one exception.

A consumer sweeping a directory of real binaries hits these constantly -- .NET
projects ship Portable PDBs, and MSVC leaves `vc140.pdb` next to the .obj files
-- so `struct.error` escaping the parser, or a bare "bad magic", is a defect.
"""

import struct

import pytest

from purepdb import PDB, MsfError, PdbError, UnsupportedPdbError
from purepdb.dbi import DbiStream
from purepdb.msf import MsfFile
from tests._synth import (
    build_msf,
    dbi_stream,
    module_info,
    module_sym_stream,
    publics_hash_stream,
    section_header,
)


def test_portable_pdb_is_named():
    """.NET/Roslyn PDBs are not MSF containers at all."""
    data = b"BSJB\x01\x00\x01\x00" + b"\x00" * 4 + b"PDB v1.0" + b"\x00" * 512
    with pytest.raises(UnsupportedPdbError, match="Portable PDB"):
        MsfFile(data)


def test_msf_2_is_named():
    data = b"Microsoft C/C++ program database 2.00\r\n\x1aJG" + b"\x00" * 512
    with pytest.raises(UnsupportedPdbError, match=r"MSF 2\.00"):
        MsfFile(data)


def _pdb_with_info_stream(info: bytes) -> PDB:
    return PDB.from_bytes(_info_pdb_bytes(info))


def _info_pdb_bytes(info: bytes) -> bytes:
    module_syms = module_sym_stream(b"")
    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    return build_msf([
        b"",
        info,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=6, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [7]),
        publics_hash_stream([]),
        module_syms,
        b"",
        section_header(".text", 0x1000),
    ])


def _vc70_info(version: int = PDB.PDB_INFO_VC70) -> bytes:
    """A whole PDB Info header: version, signature, age, then the GUID."""
    return struct.pack("<III", version, 0xAABBCCDD, 1) + b"\x11" * 16


@pytest.mark.parametrize("size", [0, 4, 11, 12, 20, 27])
def test_a_short_pdb_info_stream_is_rejected_not_unpacked(size):
    """The stream's length comes from the file, so it can be a lie.

    `info()` reads a 28-byte fixed header out of it, and nothing bounded that
    read. Below 12 bytes it leaked `struct.error`; between 12 and 27 it did
    not raise at all and returned a *short* GUID -- a wrong answer, and the
    one a caller would key a symbol-server lookup on. 12 and 20 are here for
    that half, which is the more serious one.
    """
    pdb = _pdb_with_info_stream(b"\x00" * size)

    with pytest.raises(MsfError, match=rf"is {size} bytes.*28-byte header"):
        pdb.info()


def test_a_pdb_info_stream_of_exactly_the_header_size_is_read():
    """The bound has to be pinned from below too, or a stricter one would
    reject a healthy file with nothing here to notice."""
    pdb = _pdb_with_info_stream(_vc70_info())

    info = pdb.info()
    assert (info.version, info.signature, info.age) == (PDB.PDB_INFO_VC70,
                                                        0xAABBCCDD, 1)
    assert info.guid == b"\x11" * 16


def test_a_pre_vc70_info_stream_is_refused_rather_than_given_a_guid():
    """Older layouts put the named-stream map where the GUID now lives.

    Reading 12..28 as a GUID there reports the map's own bytes as an identity
    -- `llvm-pdbutil` refuses such a file outright rather than answering.
    """
    pdb = _pdb_with_info_stream(_vc70_info(version=19990604))

    with pytest.raises(UnsupportedPdbError, match="predates VC70"):
        pdb.info()


def test_diagnose_says_the_info_stream_is_why_names_are_missing():
    """An unreadable Info stream takes the named-stream map with it, so
    `named_streams()` empties and `/names` cannot be found -- both in silence
    without this."""
    pdb = _pdb_with_info_stream(b"\x00" * 4)

    d = pdb.diagnose()
    assert d.pdb_info_error is not None
    assert any("PDB Info stream cannot be read" in w for w in d.warnings)
    assert pdb.named_streams() == {}


def test_cli_info_on_a_short_info_stream_is_not_a_traceback(tmp_path, capsys):
    """The half of this the library fix does not reach: `info()` is read
    after the open, so guarding only `PDB.open` left the traceback in place."""
    from purepdb.__main__ import main

    path = tmp_path / "short-info.pdb"
    path.write_bytes(_info_pdb_bytes(b"\x00" * 11))

    assert main(["purepdb", "info", str(path)]) == 1
    assert "too short for the" in capsys.readouterr().err


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


# --- lengths read from the file, checked against what the file holds --------

def _msf_with_directory_patched(patch: bytes, offset: int = 0) -> bytes:
    """A valid container whose stream directory has `patch` written into it.

    The directory's own blocks are named by the block map, which the superblock
    points at, so this walks the same path the reader does to find them.
    """
    from tests._synth import build_msf

    data = bytearray(build_msf([b"", b"\x00" * 8]))
    (block_size, _fpm, _nblocks, _ndir, _unk,
     block_map_addr) = struct.unpack_from("<IIIIII", data, 32)
    (first_dir_block,) = struct.unpack_from("<I", data, block_map_addr * block_size)
    struct.pack_into(f"<{len(patch)}s", data,
                     first_dir_block * block_size + offset, patch)
    return bytes(data)


def test_a_stream_count_larger_than_the_directory_is_rejected():
    """`num_streams` is read from the file and sizes the very next read.

    Trusting it handed an absurd count straight to `struct.unpack_from`, which
    raises `struct.error` -- the one exception this parser promises never to
    let out.
    """
    data = _msf_with_directory_patched(struct.pack("<I", 0xFFFFFF))
    with pytest.raises(MsfError, match="more than its"):
        PDB.from_bytes(data)


def test_a_stream_size_past_the_directory_is_rejected():
    """Each stream's block list is sized by its own declared byte count."""
    data = _msf_with_directory_patched(struct.pack("<I", 0x00FFFFFF), offset=4)
    with pytest.raises(MsfError, match="past the end"):
        PDB.from_bytes(data)


def test_a_module_record_with_an_unterminated_name_stops_the_walk():
    """The module list ends in two NUL-terminated strings.

    A name that runs to the end of the substream without its NUL used to raise
    `EOFError` out of `PDB.open()`. The modules already read are still good.
    """
    from tests._synth import (
        build_msf,
        dbi_stream,
        module_info,
        module_sym_stream,
        publics_hash_stream,
    )

    syms = module_sym_stream(b"")
    good = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(syms))
    # A second record: fixed portion intact, then a name with no terminator.
    truncated = good[:64] + b"A" * 40
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=6,
                   module_list=good + truncated, dbg_header=[0xFFFF] * 6),
        publics_hash_stream([]), syms, b"",
    ]

    pdb = PDB.from_bytes(build_msf(streams))
    assert [m.module_name for m in pdb.dbi.modules] == ["main.obj"]
    assert pdb.functions() == []
