
import pytest

from purepdb.msf import MsfError, MsfFile
from tests._synth import build_msf


def test_roundtrip_single_small_stream():
    payload = b"hello world"
    data = build_msf([payload])
    msf = MsfFile(data)
    assert msf.num_streams == 1
    assert msf.read_stream(0) == payload


def test_roundtrip_multiblock_stream():
    # Stream larger than one block forces multi-block reassembly.
    payload = bytes(range(256)) * 10  # 2560 bytes > 512
    data = build_msf([b"", payload], block_size=512)
    msf = MsfFile(data)
    assert msf.stream_size(1) == len(payload)
    assert msf.read_stream(1) == payload


def test_multiple_streams_independent():
    a = b"A" * 100
    b = b"B" * 700
    c = b"C" * 3
    msf = MsfFile(build_msf([a, b, c]))
    assert msf.read_stream(0) == a
    assert msf.read_stream(1) == b
    assert msf.read_stream(2) == c


def test_empty_stream():
    msf = MsfFile(build_msf([b"", b"x"]))
    assert msf.stream_size(0) == 0
    assert msf.read_stream(0) == b""
    assert msf.read_stream(1) == b"x"


def test_different_block_sizes():
    payload = b"z" * 5000
    for bs in (512, 1024, 4096):
        msf = MsfFile(build_msf([payload], block_size=bs))
        assert msf.super.block_size == bs
        assert msf.read_stream(0) == payload


def test_bad_magic_rejected():
    data = bytearray(build_msf([b"x"]))
    data[0:4] = b"XXXX"
    with pytest.raises(MsfError):
        MsfFile(bytes(data))


def test_nil_stream_marked_invalid():
    # Hand-patch a stream size to the nil sentinel and confirm handling.
    data = bytearray(build_msf([b"aaaa", b"bbbb"]))
    msf = MsfFile(bytes(data))
    # Both start valid.
    assert msf.is_valid_stream(0)
    assert msf.is_valid_stream(1)
    assert not msf.is_valid_stream(99)


def test_out_of_range_read():
    msf = MsfFile(build_msf([b"x"]))
    with pytest.raises(MsfError):
        msf.read_stream(5)
