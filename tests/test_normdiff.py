import os

from verifyoor.analyze import analyze
from verifyoor.compile import Settings, compile_standard
from verifyoor.metadata import strip_trailing
from verifyoor.normdiff import diff
from verifyoor.util import load_bytecode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _setup():
    target = load_bytecode(os.path.join(ROOT, "test.hex"))
    a = analyze(target)
    for s in a.selectors:
        s.signature = {"b269681d": "destination()", "c4d66de8": "initialize(address)"}.get(s.selector)
    tstrip, _ = strip_trailing(target)
    src = open(os.path.join(ROOT, "test.sol")).read()
    return target, a, tstrip, src


def _compiled_stripped(src):
    c = compile_standard(src, "0.8.20", Settings()).pick()
    s, _ = strip_trailing(bytes.fromhex(c.deployed_object))
    return s


def test_identical_is_match():
    target, a, tstrip, src = _setup()
    nd = diff(tstrip, _compiled_stripped(src), a.selectors)
    assert nd.match


def test_message_change_localizes():
    target, a, tstrip, src = _setup()
    wrong = src.replace("Invalid destination", "Bad destination XXX")
    nd = diff(tstrip, _compiled_stripped(wrong), a.selectors)
    assert not nd.match
    assert nd.region_count <= 3
    assert {r.function for r in nd.regions} == {"initialize(address)"}


def test_offset_shift_stays_localized():
    # inserting a require at the top of initialize shifts every downstream
    # jumpdest; the normalized diff must stay a few localized regions, not explode.
    target, a, tstrip, src = _setup()
    wrong = src.replace(
        "require(_addr != address(0)",
        "require(_addr != msg.sender, 'x'); require(_addr != address(0)",
    )
    nd = diff(tstrip, _compiled_stripped(wrong), a.selectors)
    assert not nd.match
    assert nd.length_delta > 0  # candidate genuinely longer
    assert nd.region_count <= 6, "diff exploded: normalization failed"
    assert {r.function for r in nd.regions} <= {"initialize(address)"}
