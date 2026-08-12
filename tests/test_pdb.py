import struct

from purepdb import PDB
from purepdb.dbi import DbiStream
from purepdb.sections import SectionTable
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


def test_section_table_rva():
    data = section_header(".text", 0x1000) + section_header(".data", 0x5000)
    st = SectionTable.parse(data)
    assert st.to_rva(1, 0x40) == 0x1040
    assert st.to_rva(2, 0x8) == 0x5008
    assert st.to_rva(0, 0) is None   # absolute
    assert st.to_rva(3, 0) is None   # out of range


def test_dbi_header_and_modules():
    mods = module_info("a.obj", "a.obj", sym_stream=5, sym_byte_size=100)
    dbi = dbi_stream(
        public_stream=4, symrecord_stream=4,
        module_list=mods, dbg_header=[0xFFFF] * 6 + [7],
    )
    parsed = DbiStream.parse(dbi)
    assert parsed.public_stream_index == 4
    assert parsed.symrecord_stream_index == 4
    assert len(parsed.modules) == 1
    assert parsed.modules[0].module_name == "a.obj"
    assert parsed.modules[0].sym_stream == 5
    assert parsed.section_header_stream == 0xFFFF  # slot 5 here


def _build_full_pdb():
    # Stream indices:
    # 0 old-dir, 1 pdb-info, 2 tpi, 3 dbi, 4 publics-hash, 5 module-syms,
    # 6 sections, 7 symbol-records
    #
    # 4 and 7 are deliberately distinct: the publics hash stream holds offsets,
    # the symbol-record stream holds the records. Pointing both at one stream
    # would hide a parser that reads publics from the wrong one.
    pdb_info = struct.pack("<III", 20000404, 0xAABBCCDD, 1) + b"\x00" * 16
    tpi = b""
    pub_records = [
        pub32("main", 1, 0x1000),
        pub32("helper", 1, 0x1100, flags=0x2),
        pub32("g_flag", 2, 0x0, flags=0x0),
    ]
    symrecords = b"".join(pub_records)
    publics_hash = publics_hash_stream(record_offsets(pub_records))
    module_syms = module_sym_stream(
        gproc32("main", 1, 0x1000, code_size=0x50)
        + gproc32("internal_only", 1, 0x1200, code_size=0x20)
    )
    sections = section_header(".text", 0x1000) + section_header(".data", 0x8000)

    mods = module_info("main.obj", "main.obj", sym_stream=5,
                       sym_byte_size=len(module_syms))
    dbi = dbi_stream(
        public_stream=4, symrecord_stream=7,
        module_list=mods,
        dbg_header=[0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 6],  # slot 5 -> stream 6
    )
    streams = [b"", pdb_info, tpi, dbi, publics_hash, module_syms, sections,
               symrecords]
    return build_msf(streams)


def test_end_to_end_info():
    pdb = PDB.from_bytes(_build_full_pdb())
    info = pdb.info()
    assert info.signature == 0xAABBCCDD
    assert info.age == 1


def test_end_to_end_public_symbols():
    pdb = PDB.from_bytes(_build_full_pdb())
    names = {p.name for p in pdb.public_symbols()}
    assert {"main", "helper", "g_flag"} <= names


def test_end_to_end_functions_with_rva():
    pdb = PDB.from_bytes(_build_full_pdb())
    fns = {f.name: f for f in pdb.functions()}

    # proc-sourced function resolves to an RVA via section 1 (.text @ 0x1000)
    assert fns["main"].rva == 0x2000        # 0x1000 base + 0x1000 offset
    assert fns["main"].source == "proc"
    assert fns["main"].code_size == 0x50

    # internal_only exists only as a proc record
    assert fns["internal_only"].rva == 0x2200
    assert fns["internal_only"].source == "proc"

    # helper exists only as a public function record
    assert fns["helper"].source == "public"
    assert fns["helper"].rva == 0x2100

    # non-function public must NOT appear as a function
    assert "g_flag" not in fns


def test_functions_sorted_by_rva():
    pdb = PDB.from_bytes(_build_full_pdb())
    rvas = [f.rva for f in pdb.functions() if f.rva is not None]
    assert rvas == sorted(rvas)
