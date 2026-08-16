"""Codegen-pattern recognizer: each rule fires on its exact token signature and
stays silent otherwise (precision matters more than recall — a wrong hint misleads).
Signatures are taken from the real diff regions that motivated the rules.
"""
from verifyoor.hints import hint_for

MASK28 = "PUSH28 0x" + "f" * 56  # bytes4 selector-cleanup mask
ERR_STR_PADDED = "PUSH32 0x08c379a0" + "0" * 56  # padded Error(string) selector


def test_selector_encoding_cast_vs_literal():
    h = hint_for(["PUSH1 0xe0", "SHL"], [MASK28, "NOT", "AND"])
    assert h and "raw literal" in h and "bytes4" in h


def test_selector_encoding_reverse_direction():
    h = hint_for([MASK28, "NOT", "AND"], ["PUSH1 0xe0", "SHL"])
    assert h and "bytes4 cast" in h


def test_selector_mask_wrong_width_does_not_fire():
    # a 20-byte address mask must not be mistaken for the 28-byte selector mask
    addr_mask = "PUSH20 0x" + "f" * 40
    assert hint_for(["PUSH1 0xe0", "SHL"], [addr_mask, "NOT", "AND"]) is None


def test_unchecked_increment():
    h = hint_for(["PUSH1 0x01", "ADD"], ["PUSHDEST", "SWAP1", "PUSHDEST", "JUMP", "JUMPDEST"])
    assert h and "unchecked" in h and "wrap" in h


def test_checked_increment_reverse():
    h = hint_for(["PUSHDEST", "SWAP1", "PUSHDEST", "JUMP", "JUMPDEST"], ["PUSH1 0x01", "ADD"])
    assert h and "remove the `unchecked" in h


def test_plain_add_both_sides_no_hint():
    # a bare ADD on both sides (a real value change, not checked-vs-unchecked)
    assert hint_for(["PUSH1 0x01", "ADD"], ["PUSH1 0x02", "ADD"]) is None


def test_custom_error_vs_require():
    h = hint_for(["PUSH4 0x1234abcd"], [ERR_STR_PADDED])
    assert h and "custom error" in h


def test_custom_error_ignores_error_and_panic_selectors():
    # 0x08c379a0 (Error) and 0x4e487b71 (Panic) are not custom errors
    assert hint_for(["PUSH4 0x08c379a0"], [ERR_STR_PADDED]) is None


def test_benign_dup_swap_no_hint():
    assert hint_for(["DUP2"], ["DUP3"]) is None
    assert hint_for(["DUP3", "DUP3"], ["DUP2", "DUP4"]) is None


def test_empty_regions_no_hint():
    assert hint_for([], []) is None
    assert hint_for(["PUSH1 0x01", "ADD"], []) is None
