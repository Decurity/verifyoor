import os

import pytest

from verifyoor.analyze import analyze
from verifyoor.util import load_bytecode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")


def sample():
    return load_bytecode(os.path.join(ROOT, "tests", "fixtures", "sample.hex"))


def _fixture(name):
    p = os.path.join(FIX, name + ".hex")
    if not os.path.exists(p):
        pytest.skip("fixture %s not generated" % name)
    return load_bytecode(p)


def test_dispatcher_selectors_and_offsets():
    a = analyze(sample())
    got = {s.selector: s.body_offset for s in a.selectors}
    assert got == {"b269681d": 0x126, "c4d66de8": 0x150}


def test_receive_detected():
    assert analyze(sample()).has_receive_or_fallback is True


def test_optimizer_and_evm_floor():
    a = analyze(sample())
    assert a.optimizer_guess == "off"
    assert a.evm_floor == "shanghai"
    assert a.solc_floor == "0.8.20"


def test_strings_extracted():
    a = analyze(sample())
    assert a.strings == ["Not initialized", "Invalid destination"]


def test_vault_fixture_dispatcher():
    a = analyze(_fixture("vault"))
    # optimizer-on build; several selectors expected
    assert len(a.selectors) >= 5
    assert a.optimizer_guess == "on"


def test_via_ir_detection():
    # legacy builds must read as unlikely
    for name in ("vault", "counter_unopt", "registry_old"):
        assert analyze(_fixture(name)).via_ir_guess == "unlikely", name
    assert analyze(sample()).via_ir_guess == "unlikely"  # test.hex is unoptimized legacy
    # the viaIR fixture must read as likely
    assert analyze(_fixture("rescuer_viair")).via_ir_guess == "likely"


def test_sub_form_last_selector_and_receive():
    # rescuer_viair: deployer() dispatches via the SUB last-selector trick, and it
    # has a receive() — both were previously missed.
    a = analyze(_fixture("rescuer_viair"))
    sels = {s.selector for s in a.selectors}
    assert {"d5f39488", "9e252f00", "33f3d628"} <= sels  # deployer(), rescueETH, rescueToken
    assert a.has_receive_or_fallback is True
    # deployer() body is a fall-through right after the dispatcher (low offset)
    dep = next(s for s in a.selectors if s.selector == "d5f39488")
    assert dep.body_offset < 0x60


def test_body_offset_traces_trampolines():
    # legacy dispatch relays the pushed target through an arg-decoder and a relay
    # before reaching the real body; _resolve_body must follow both hops.
    from verifyoor.analyze import _resolve_body
    from verifyoor.disasm import Op

    ops = [
        Op(0x00, 0x5B, "JUMPDEST"),
        Op(0x01, 0x61, "PUSH2", b"\x00\x20"),  # ret
        Op(0x04, 0x61, "PUSH2", b"\x00\x10"),  # cont
        Op(0x07, 0x36, "CALLDATASIZE"),
        Op(0x08, 0x60, "PUSH1", b"\x04"),
        Op(0x0A, 0x61, "PUSH2", b"\x00\x30"),  # decoder
        Op(0x0D, 0x56, "JUMP"),
        Op(0x10, 0x5B, "JUMPDEST"),  # cont: relay to real body
        Op(0x11, 0x61, "PUSH2", b"\x00\x25"),
        Op(0x14, 0x56, "JUMP"),
        Op(0x25, 0x5B, "JUMPDEST"),  # real body
        Op(0x26, 0x00, "STOP"),
    ]
    by_pc = {o.pc: i for i, o in enumerate(ops)}
    assert _resolve_body(0x00, ops, by_pc) == 0x25
    # a non-trampoline entry (viaIR / no-arg) is returned unchanged
    assert _resolve_body(0x25, ops, by_pc) == 0x25


def test_word_literal_decoders():
    from verifyoor.analyze import _decode_word_literals, _word_literal
    from verifyoor.disasm import Op

    # padded (unoptimized) form: string left-aligned + zero padding
    assert _word_literal(b"zero".ljust(32, b"\x00")) == "zero"
    # a clean address constant is not a string (no printable left run)
    assert _word_literal(bytes.fromhex("fc3facd67138966ab0c841e905b0c4bca1abe92f".ljust(64, "0"))) is None

    # shift form: PUSH3 0x0cae8d PUSH1 0xeb SHL == 'eth'
    eth_ops = [Op(0, 0x62, "PUSH3", bytes.fromhex("0cae8d")), Op(3, 0x60, "PUSH1", b"\xeb"), Op(5, 0x1B, "SHL")]
    assert "eth" in _decode_word_literals(eth_ops)
    # a function selector built the same way (PUSH4 sel PUSH1 0xe0 SHL) is NOT a string
    sel_ops = [Op(0, 0x63, "PUSH4", bytes.fromhex("a9059cbb")), Op(4, 0x60, "PUSH1", b"\xe0"), Op(6, 0x1B, "SHL")]
    assert _decode_word_literals(sel_ops) == []


def test_string_extraction_across_encodings():
    # shift-encoded (optimizer on), padded (optimizer off), and no false positives
    assert analyze(_fixture("counter_unopt")).strings == ["zero"]  # padded PUSH32
    assert analyze(_fixture("registry_old")).strings == ["not admin"]  # was a false positive before
    assert "insufficient" in analyze(_fixture("vault")).strings  # shift-encoded


def test_legacy_no_false_receive():
    # a contract with no receive/fallback must not be flagged
    for name in ("vault", "counter_unopt", "registry_old"):
        assert analyze(_fixture(name)).has_receive_or_fallback is False, name
