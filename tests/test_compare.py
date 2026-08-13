import os

from verifyoor.compile import ContractOut
from verifyoor.compare import compare
from verifyoor.metadata import strip_trailing
from verifyoor.util import load_bytecode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _target_no_meta():
    code = load_bytecode(os.path.join(ROOT, "tests", "fixtures", "sample.hex"))
    stripped, _ = strip_trailing(code)
    return code, stripped


def test_exact_match_no_masks():
    code, stripped = _target_no_meta()
    # candidate == target sans metadata
    c = ContractOut(name="Test", deployed_object=stripped.hex())
    res = compare(code, c)
    assert res.match
    assert not res.masked_immutables


def test_length_mismatch_reported():
    code, stripped = _target_no_meta()
    c = ContractOut(name="Test", deployed_object=(stripped + b"\x00\x00").hex())
    res = compare(code, c)
    assert not res.match
    assert "length" in res.reason


def test_immutable_masking_recovers_value():
    # target has a nonzero value in a slot where the candidate has zeros;
    # masking that immutable range should yield a match and recover the value.
    code, stripped = _target_no_meta()
    target = bytearray(stripped)
    off = 100
    target[off : off + 32] = bytes(range(1, 33))  # nonzero on-chain value
    # rebuild a target-with-metadata so compare strips consistently
    target_full = bytes(target) + load_bytecode(os.path.join(ROOT, "tests", "fixtures", "sample.hex"))[989:]
    candidate = ContractOut(
        name="Test",
        deployed_object=stripped.hex(),  # zeros in that slot
        immutable_refs={"1": [{"start": off, "length": 32}]},
    )
    res = compare(target_full, candidate)
    assert res.match
    assert len(res.masked_immutables) == 1
    assert res.masked_immutables[0]["value"] == bytes(range(1, 33)).hex()


def test_link_placeholder_masking():
    code, stripped = _target_no_meta()
    # inject a 20-byte library address into target, put a placeholder in candidate
    off = 50
    target = bytearray(stripped)
    addr = bytes.fromhex("11" * 20)
    target[off : off + 20] = addr
    target_full = bytes(target) + load_bytecode(os.path.join(ROOT, "tests", "fixtures", "sample.hex"))[989:]
    # a 40-char __$...$__ placeholder occupies exactly 20 bytes of the hex string
    placeholder = "__$" + "a" * 34 + "$__"
    cand_hex = stripped.hex()[: off * 2] + placeholder + stripped.hex()[(off + 20) * 2 :]
    candidate = ContractOut(name="Test", deployed_object=cand_hex)
    res = compare(target_full, candidate)
    assert res.match
    assert len(res.masked_links) == 1
    assert res.masked_links[0]["value"] == addr.hex()
