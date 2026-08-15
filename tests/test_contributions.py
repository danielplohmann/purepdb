"""Attributing each function to the linker input that produced it.

The Section Contribution substream partitions the image by contributing
`.obj`/`.lib` member, so it answers "is this application code or library
code?" from the file rather than from a guess about the name.
"""

import struct

import pytest

from purepdb import PDB
from tests._synth import (
    SEC_CONTRIB_V2,
    build_msf,
    dbi_stream,
    gproc32,
    module_info,
    module_sym_stream,
    pub32,
    publics_hash_stream,
    record_offsets,
    section_contributions,
    section_header,
)


def _pdb(*, contributions, version=None, procs=(), publics=()):
    """A PDB with one module per entry in `procs`, named mod0.obj, mod1.obj..."""
    module_syms = [module_sym_stream(records) for records in procs]
    mods = b"".join(
        module_info(f"mod{i}.obj", f"mod{i}.lib", sym_stream=5 + i,
                    sym_byte_size=len(syms))
        for i, syms in enumerate(module_syms)
    )
    kwargs = {} if version is None else {"version": version}
    section_stream = 5 + len(module_syms)
    symrecord_stream = section_stream + 1
    streams = [
        b"",
        struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16,
        b"",
        dbi_stream(public_stream=4, symrecord_stream=symrecord_stream,
                   module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [section_stream],
                   sec_contrib=section_contributions(contributions, **kwargs)),
        publics_hash_stream(record_offsets(list(publics))),
        *module_syms,
        section_header(".text", 0x1000),
        b"".join(publics),
    ]
    return PDB.from_bytes(build_msf(streams))


def test_a_function_is_attributed_to_its_contributing_module():
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 0), (1, 0x100, 0x100, 1)],
               procs=[gproc32("app", 1, 0x000), gproc32("lib", 1, 0x100)])
    assert {f.name: f.module for f in pdb.functions()} == {
        "app": "mod0.obj", "lib": "mod1.obj",
    }


def test_an_address_inside_a_contribution_resolves_not_only_its_start():
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 0)],
               procs=[gproc32("mid", 1, 0x080)])
    assert pdb.functions()[0].module == "mod0.obj"


def test_an_address_in_a_gap_is_unattributed_rather_than_misattributed():
    """The entry before a gap must not swallow addresses past its end."""
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 0), (1, 0x200, 0x100, 1)],
               procs=[gproc32("orphan", 1, 0x180)])
    assert pdb.functions()[0].module is None


def test_an_address_below_the_first_contribution_is_unattributed():
    pdb = _pdb(contributions=[(1, 0x100, 0x100, 0)],
               procs=[gproc32("early", 1, 0x000)])
    assert pdb.functions()[0].module is None


def test_a_segment_with_no_contributions_is_unattributed():
    pdb = _pdb(contributions=[(2, 0x000, 0x1000, 0)],
               procs=[gproc32("elsewhere", 1, 0x000)])
    assert pdb.functions()[0].module is None


def test_public_sourced_functions_are_attributed_too():
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 0)],
               procs=[b""], publics=[pub32("thunk", 1, 0x010)])
    assert [(f.name, f.source, f.module) for f in pdb.functions()] == [
        ("thunk", "public", "mod0.obj"),
    ]


def test_the_v2_entry_size_is_handled():
    """V2 entries are 32 bytes, not 28; reading them as 28 desynchronises."""
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 0), (1, 0x100, 0x100, 1)],
               version=SEC_CONTRIB_V2,
               procs=[gproc32("app", 1, 0x000), gproc32("lib", 1, 0x100)])
    assert len(pdb.section_contributions()) == 2
    assert {f.name: f.module for f in pdb.functions()} == {
        "app": "mod0.obj", "lib": "mod1.obj",
    }


def test_an_unknown_version_yields_no_attribution_rather_than_garbage():
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 0)], version=0xDEADBEEF,
               procs=[gproc32("app", 1, 0x000)])
    assert pdb.section_contributions() == []
    assert pdb.functions()[0].module is None
    assert pdb.diagnose().section_contributions == 0


def test_a_substream_that_does_not_divide_into_entries_is_rejected():
    contribs = section_contributions([(1, 0x000, 0x100, 0)])[:-3]
    module_syms = module_sym_stream(gproc32("app", 1, 0x000))
    mods = module_info("mod0.obj", "mod0.lib", sym_stream=5,
                       sym_byte_size=len(module_syms))
    streams = [
        b"", struct.pack("<III", 20000404, 1, 1) + b"\x00" * 16, b"",
        dbi_stream(public_stream=4, symrecord_stream=7, module_list=mods,
                   dbg_header=[0xFFFF] * 5 + [6], sec_contrib=contribs),
        publics_hash_stream([]), module_syms, section_header(".text", 0x1000), b"",
    ]
    pdb = PDB.from_bytes(build_msf(streams))
    assert pdb.section_contributions() == []


def test_a_module_index_past_the_module_list_is_not_an_index_error():
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 7)],
               procs=[gproc32("app", 1, 0x000)])
    assert pdb.functions()[0].module is None


def test_an_empty_contribution_does_not_shadow_the_real_one():
    """Linkers emit zero-size contributions; one sharing a start address must
    not hide the contribution that actually covers it."""
    pdb = _pdb(contributions=[(1, 0x000, 0x100, 0), (1, 0x000, 0x000, 1)],
               procs=[gproc32("app", 1, 0x010), b""])
    assert len(pdb.section_contributions()) == 2
    assert pdb.functions()[0].module == "mod0.obj"


def test_contributions_out_of_order_still_resolve():
    pdb = _pdb(contributions=[(1, 0x100, 0x100, 1), (1, 0x000, 0x100, 0)],
               procs=[gproc32("app", 1, 0x000), gproc32("lib", 1, 0x100)])
    assert {f.name: f.module for f in pdb.functions()} == {
        "app": "mod0.obj", "lib": "mod1.obj",
    }


# --- against real linker output ---------------------------------------------

GOLDEN = [
    pytest.param("sqlite/x86/sqlite3.pdb", 4050,
                 "C:\\dev\\sqlite\\core\\sqlite3.lo", 3453, id="sqlite-x86"),
    pytest.param("sqlite/x64/sqlite3.pdb", 10725,
                 "C:\\dev\\sqlite\\core\\sqlite3.lo", 3453, id="sqlite-x64"),
    pytest.param("rustpe/rust_pe_symbols_msvc.pdb", 2267,
                 "std-ad7efb1bc85901be.std.fc79cc53f84b73ec-cgu.0.rcgu.o", 147,
                 id="rustpe-msvc"),
    pytest.param("rustpe32/rust_pe_symbols_i686.pdb", 7,
                 "/build/rustpe32/stubs.obj", 4, id="rustpe-i686"),
    pytest.param("tls/tls_symbols.pdb", 13,
                 "/tmp/build/tls/tls_symbols.obj", 2, id="tls-x64"),
]


def _open(rel):
    from pathlib import Path

    path = Path(__file__).resolve().parent / "data" / rel
    if not path.exists():
        pytest.skip(f"groundtruth fixture missing: {rel}")
    return PDB.open(str(path))


@pytest.mark.parametrize("rel,n_contribs,top_module,top_count", GOLDEN)
def test_every_real_function_is_attributed(rel, n_contribs, top_module, top_count):
    """The contributions partition the image, so nothing should fall in a gap."""
    import collections

    pdb = _open(rel)
    assert len(pdb.section_contributions()) == n_contribs

    counts = collections.Counter(f.module for f in pdb.functions())
    assert counts[None] == 0, "every function must resolve to a module"
    assert counts.most_common(1) == [(top_module, top_count)]


def test_import_thunks_are_attributed_to_the_dll_they_import_from():
    """Library code is distinguishable from application code by this alone."""
    pdb = _open("sqlite/x86/sqlite3.pdb")
    modules = {f.module for f in pdb.functions()}
    assert "Import:ucrtbased.dll" in modules


def test_contributions_agree_with_the_section_table():
    """A contribution must not claim bytes outside the section it names."""
    pdb = _open("sqlite/x86/sqlite3.pdb")
    sections = pdb.sections
    for contrib in pdb.section_contributions():
        assert 1 <= contrib.segment <= len(sections)
        section = sections[contrib.segment - 1]
        assert contrib.offset + contrib.size <= section.virtual_size
