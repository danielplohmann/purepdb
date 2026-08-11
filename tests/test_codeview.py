from purepdb import codeview
from tests._synth import pub32, gproc32, make_record


def test_parse_single_public():
    data = pub32("main", segment=1, offset=0x1230, flags=0x2)
    pubs = codeview.extract_publics(data)
    assert len(pubs) == 1
    p = pubs[0]
    assert p.name == "main"
    assert p.segment == 1
    assert p.offset == 0x1230
    assert p.is_function


def test_public_non_function_flag():
    data = pub32("g_counter", segment=2, offset=0x40, flags=0x0)
    p = codeview.extract_publics(data)[0]
    assert not p.is_function


def test_multiple_publics_in_stream():
    data = pub32("foo", 1, 0x10) + pub32("bar", 1, 0x20) + pub32("baz", 1, 0x30)
    pubs = codeview.extract_publics(data)
    assert [p.name for p in pubs] == ["foo", "bar", "baz"]
    assert [p.offset for p in pubs] == [0x10, 0x20, 0x30]


def test_parse_gproc():
    data = gproc32("compute", segment=1, offset=0x2000, code_size=0x84)
    procs = codeview.extract_procs(data)
    assert len(procs) == 1
    p = procs[0]
    assert p.name == "compute"
    assert p.segment == 1
    assert p.offset == 0x2000
    assert p.code_size == 0x84
    assert p.is_global


def test_unknown_records_skipped_without_desync():
    # An unknown record between two known ones must not break the stream.
    unknown = make_record(0x1234, b"\xde\xad\xbe\xef arbitrary payload")
    data = pub32("first", 1, 0x10) + unknown + pub32("second", 1, 0x20)
    pubs = codeview.extract_publics(data)
    assert [p.name for p in pubs] == ["first", "second"]


def test_mixed_proc_and_public_stream():
    data = gproc32("f", 1, 0x100) + pub32("g", 1, 0x200)
    assert [p.name for p in codeview.extract_procs(data)] == ["f"]
    assert [p.name for p in codeview.extract_publics(data)] == ["g"]


def test_empty_stream():
    assert codeview.extract_publics(b"") == []
    assert codeview.extract_procs(b"") == []


def test_parse_data_symbol():
    from tests._synth import gdata32
    data = gdata32("g_counter", segment=2, offset=0x40)
    syms = codeview.extract_data(data)
    assert len(syms) == 1
    assert syms[0].name == "g_counter"
    assert syms[0].segment == 2
    assert syms[0].offset == 0x40
    assert syms[0].is_global


def test_data_and_proc_dont_cross_contaminate():
    from tests._synth import gdata32, gproc32
    data = gproc32("fn", 1, 0x100) + gdata32("var", 2, 0x10)
    assert [d.name for d in codeview.extract_data(data)] == ["var"]
    assert [p.name for p in codeview.extract_procs(data)] == ["fn"]
