import os

from verifyoor.analyze import analyze
from verifyoor.compile import Settings, compile_standard
from verifyoor.metadata import strip_trailing
from verifyoor.normdiff import diff
from verifyoor.util import load_bytecode, selector_of

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Two byte-identical functions; the candidate adds a require (a new, single-owner
# revert-string helper) to `alpha` only. Global alignment can attribute the inserted
# helper to "shared helper"; per-function must keep every region inside alpha.
_TWIN = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Twin {
    mapping(address => uint256) bal;
    function alpha(address a, uint256 x) external {
        require(a != address(0), "z");
        require(x > 0, "z");
        bal[a] += x;
    }
    function beta(address a, uint256 x) external {
        require(a != address(0), "z");
        require(x > 0, "z");
        bal[a] += x;
    }
}
"""
_TWIN_CAND = _TWIN.replace(
    '        require(x > 0, "z");\n        bal[a] += x;\n    }\n    function beta',
    '        require(x > 0, "z");\n        require(x < 1000000, "big");\n        bal[a] += x;\n    }\n    function beta',
)


def _twin_setup():
    tgt = _compiled_stripped(_TWIN)
    cand = _compiled_stripped(_TWIN_CAND)
    a = analyze(tgt)
    names = {selector_of("alpha(address,uint256)"): "alpha(address,uint256)",
             selector_of("beta(address,uint256)"): "beta(address,uint256)"}
    for s in a.selectors:
        s.signature = names.get(s.selector)
    return tgt, cand, a


def _setup():
    target = load_bytecode(os.path.join(ROOT, "tests", "fixtures", "sample.hex"))
    a = analyze(target)
    for s in a.selectors:
        s.signature = {"b269681d": "destination()", "c4d66de8": "initialize(address)"}.get(s.selector)
    tstrip, _ = strip_trailing(target)
    src = open(os.path.join(ROOT, "tests", "fixtures", "sample.sol")).read()
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


def test_per_function_confines_change_to_owning_function():
    tgt, cand, a = _twin_setup()
    nd = diff(tgt, cand, a.selectors)  # per_function=True (default)
    assert not nd.match
    # every region belongs to the function that actually changed — nothing bleeds to
    # beta (byte-identical) or "shared helper" (the new revert helper is alpha's alone)
    assert {r.function for r in nd.regions} == {"alpha(address,uint256)"}


def test_global_fallback_still_runs_and_finds_the_change():
    tgt, cand, a = _twin_setup()
    nd = diff(tgt, cand, a.selectors, per_function=False)
    assert not nd.match
    # global localizes the change to alpha but may also attribute part of the inserted
    # helper elsewhere — the misattribution per-function removes
    assert any(r.function == "alpha(address,uint256)" for r in nd.regions)


def test_per_function_and_global_agree_on_no_change():
    tgt, _cand, a = _twin_setup()
    assert diff(tgt, tgt, a.selectors).match
    assert diff(tgt, tgt, a.selectors, per_function=False).match
