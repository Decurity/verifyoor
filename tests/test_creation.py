"""Creation-code split / constructor-write recovery / init comparison.

Hermetic: synthetic creation images (no solc), so these pin the exact behavior the
`--creation` flow relies on to catch a constructor mismatch behind a runtime match.
"""
from verifyoor.creation import compare_init, constructor_writes, split_creation

# init: PUSH1 0x2a (value) PUSH1 0x07 (slot) SSTORE STOP  -> sstore(0x07, 0x2a)
INIT_WRITE = bytes.fromhex("602a600755" + "00")
RUNTIME = bytes.fromhex("deadbeefcafe" * 6)
ARGS = bytes.fromhex("11" * 32)


def test_split_creation_separates_init_runtime_args():
    creation = INIT_WRITE + RUNTIME + ARGS
    sp = split_creation(creation, RUNTIME)
    assert sp is not None
    assert sp.init == INIT_WRITE
    assert sp.runtime == RUNTIME
    assert sp.ctor_args == ARGS
    assert sp.runtime_offset == len(INIT_WRITE)


def test_split_creation_no_args():
    creation = INIT_WRITE + RUNTIME
    sp = split_creation(creation, RUNTIME)
    assert sp is not None and sp.ctor_args == b""


def test_split_creation_runtime_absent_returns_none():
    assert split_creation(INIT_WRITE + b"\x99\x99", RUNTIME) is None


def test_split_falls_back_to_metadata_stripped_runtime():
    # creation embeds a metadata-stripped runtime; caller passes the runtime that still
    # carries its trailing CBOR block. The split must still anchor on the shared prefix.
    from verifyoor import metadata

    body = bytes.fromhex("6001600155" + "00")
    # a minimal but valid trailing metadata block: {"solc": <3 bytes>} + 2-byte length
    cbor = bytes.fromhex("a164736f6c6343000814")  # {"solc": 0x000814}
    runtime_with_meta = body + cbor + len(cbor).to_bytes(2, "big")
    assert metadata.parse_trailing(runtime_with_meta).present
    creation = INIT_WRITE + body  # embeds only the stripped body
    sp = split_creation(creation, runtime_with_meta)
    assert sp is not None
    assert sp.init == INIT_WRITE
    assert sp.runtime == body  # anchored on the stripped runtime


def test_constructor_writes_recovers_slot_and_value():
    w = constructor_writes(INIT_WRITE)
    assert len(w) == 1
    assert w[0].slot == 7
    assert w[0].value == 0x2A


def test_constructor_writes_reports_expression_for_nonconstant():
    # sstore(0x00, caller()) : CALLER PUSH0 SSTORE  (value = msg.sender, non-constant)
    init = bytes.fromhex("335f55" + "00")
    w = constructor_writes(init)
    assert len(w) == 1
    assert w[0].slot == 0
    assert w[0].value is None
    assert "caller" in w[0].value_expr


def test_compare_init_match():
    creation = INIT_WRITE + RUNTIME + ARGS
    compiled = INIT_WRITE + RUNTIME  # same init, no args
    ic = compare_init(creation, compiled, RUNTIME)
    assert ic.match
    assert ic.ctor_args_len == len(ARGS)


def test_compare_init_mismatch_surfaces_missing_write():
    creation = INIT_WRITE + RUNTIME
    compiled = bytes.fromhex("00") + RUNTIME  # constructor missing the sstore
    ic = compare_init(creation, compiled, RUNTIME)
    assert not ic.match
    assert [(w.slot, w.value) for w in ic.onchain_writes] == [(7, 0x2A)]
    assert ic.compiled_writes == []
    assert ic.diff is not None and ic.diff.region_count >= 1
