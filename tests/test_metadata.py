import os

from verifyoor import metadata
from verifyoor.util import load_bytecode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sample():
    return load_bytecode(os.path.join(ROOT, "tests", "fixtures", "sample.hex"))


def test_parse_trailing_sample():
    md = metadata.parse_trailing(sample())
    assert md.present
    assert md.solc == "0.8.20"
    assert md.hash_kind == "ipfs"
    assert md.length == 53
    assert md.start == 989


def test_strip_trailing_removes_metadata():
    code = sample()
    stripped, md = metadata.strip_trailing(code)
    assert md.present
    assert len(stripped) == len(code) - 53
    assert stripped == code[:989]


def test_parse_trailing_absent():
    # plain code with no metadata tail
    code = bytes.fromhex("6080604052")
    md = metadata.parse_trailing(code)
    assert not md.present
    stripped, _ = metadata.strip_trailing(code)
    assert stripped == code


def test_parse_trailing_garbage_length():
    # last two bytes claim an implausible length
    code = bytes.fromhex("6080604052ffff")
    md = metadata.parse_trailing(code)
    assert not md.present


def test_find_embedded_includes_trailing():
    code = sample()
    ranges = metadata.find_embedded(code)
    assert (989, 1042) in ranges


def test_bzzr_metadata():
    # synthetic bzzr0 metadata: a2 65 'bzzr0' 5820 <32 bytes> 64 'solc' 43 000706
    inner = bytes.fromhex("a2") + b"\x65bzzr0" + bytes.fromhex("5820") + bytes(32)
    inner += b"\x64solc" + bytes.fromhex("43") + bytes([0, 7, 6])
    code = b"\x60\x80" + inner + len(inner).to_bytes(2, "big")
    md = metadata.parse_trailing(code)
    assert md.present
    assert md.hash_kind == "bzzr0"
    assert md.solc == "0.7.6"
