"""Creation-bytecode analysis: split init / runtime / constructor args, recover the
constructor's storage writes, and compare init code across two creation images.

Why this exists: `verify`/`compare` match the **runtime** bytecode (`eth_getCode`),
but Etherscan verifies the **creation** bytecode. Creation code is
`init ++ runtime ++ constructor_args`, and the `init` (constructor) segment never
appears in runtime — so a perfect runtime match can still carry a wrong constructor
(a storage init, a different `msg.sender` write, an event) that only surfaces as an
Etherscan "deployment bytecode does NOT match" rejection. These helpers let
`analyze --creation` report what the real constructor does and `verify --creation`
diff it against the candidate before submitting.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import metadata
from .cfg import Cfg
from .disasm import disassemble


@dataclass
class CreationSplit:
    init: bytes  # constructor init-code (everything before the embedded runtime)
    runtime: bytes  # the runtime image the init RETURNs (== eth_getCode)
    ctor_args: bytes  # ABI-encoded constructor arguments appended after the runtime
    runtime_offset: int  # index where runtime begins within the creation code


def split_creation(creation: bytes, runtime: bytes) -> Optional[CreationSplit]:
    """Split creation code into (init, runtime, ctor_args).

    The exact deployed runtime is embedded verbatim in the creation code (the init
    CODECOPYs it to memory and RETURNs it), so we locate it as a substring. Anything
    after it is the ABI-encoded constructor arguments. Returns None if the runtime
    isn't found (unusual layouts: metadata-only diffs, factory/CREATE2 patterns).
    """
    if not runtime:
        return None
    idx = creation.find(runtime)
    if idx < 0:
        # The on-chain runtime carries the original metadata hash; a compiled creation
        # image carries a different one. Retry against the metadata-stripped runtime so
        # the shared code prefix still anchors the split.
        rstripped, _ = metadata.strip_trailing(runtime)
        if rstripped and rstripped != runtime:
            idx = creation.find(rstripped)
            if idx >= 0:
                return CreationSplit(creation[:idx], rstripped,
                                     creation[idx + len(rstripped):], idx)
        return None
    return CreationSplit(creation[:idx], runtime, creation[idx + len(runtime):], idx)


@dataclass
class StorageWrite:
    slot: int
    value: Optional[int]  # decoded when the stored value is a constant, else None
    value_expr: str  # the lifted expression as text (e.g. "caller()", "0x01")
    pc: int


_SSTORE_RE = re.compile(r"sstore\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(.+?)\)\s*$")
_HEXINT_RE = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")
_PC_RE = re.compile(r"^\s*0x([0-9a-fA-F]+):")


def constructor_writes(init: bytes) -> List[StorageWrite]:
    """Storage slots the constructor writes, recovered by lifting the init code.

    Reuses the same symbolic lifter as `lift` (CFG-resolved, so the leading
    callvalue-guard jump is followed correctly), then reads back every
    `sstore(<constant-slot>, <value>)`. A constant value is reported literally; a
    computed value (e.g. `owner = msg.sender`) is reported as its expression. Writes
    with a non-constant slot are skipped — they can't be attributed to a declared
    variable from bytecode alone.
    """
    if not init:
        return []
    from .lift import Lifter  # local import: lift.py imports analyze -> avoid a cycle

    ops = disassemble(init)
    lifter = Lifter(ops, cfg=Cfg.from_code(init))
    writes: List[StorageWrite] = []
    for line in lifter.listing():
        m = _SSTORE_RE.search(line)
        if not m:
            continue
        slot_tok, val_tok = m.group(1), m.group(2).strip()
        try:
            slot = int(slot_tok, 0)
        except ValueError:
            continue  # non-constant slot
        value = int(val_tok, 0) if _HEXINT_RE.match(val_tok) else None
        pcm = _PC_RE.match(line)
        pc = int(pcm.group(1), 16) if pcm else 0
        writes.append(StorageWrite(slot=slot, value=value, value_expr=val_tok, pc=pc))
    # de-dup identical (slot,value_expr) that the listing may render more than once
    seen = set()
    uniq: List[StorageWrite] = []
    for w in writes:
        key = (w.slot, w.value_expr)
        if key not in seen:
            seen.add(key)
            uniq.append(w)
    return uniq


@dataclass
class InitComparison:
    match: bool
    reason: str
    init_onchain_len: int = 0
    init_compiled_len: int = 0
    ctor_args_len: int = 0
    diff: object = None  # normdiff.NormDiff of the init prefixes, on mismatch
    onchain_writes: List[StorageWrite] = field(default_factory=list)
    compiled_writes: List[StorageWrite] = field(default_factory=list)


def compare_init(creation_onchain: bytes, creation_compiled: bytes,
                 runtime: bytes, selectors=None) -> InitComparison:
    """Compare the constructor init-code of two creation images.

    The init segment carries no metadata (that lives only in the runtime tail) and no
    constructor args, so once both are split out of their creation code they compare
    byte-for-byte. On a mismatch we attach a normalized opcode diff of the two init
    prefixes and the recovered constructor storage writes from each side — which is
    exactly what pinpoints "your constructor is missing a write to slot N".
    """
    oc = split_creation(creation_onchain, runtime)
    if oc is None:
        return InitComparison(False, "could not locate runtime within the on-chain creation code")
    # For the compiled side, use the compiled runtime tail to anchor the split.
    from .compile import ContractOut  # noqa: F401  (type hint only; import kept local)
    cc = split_creation(creation_compiled, _compiled_runtime_tail(creation_compiled, oc))
    if cc is None:
        # Fall back to a straight length-based split: compiled creation = init ++ runtime
        # (no args), so its init is the prefix that precedes the shared code.
        cc = _split_by_shared_prefix(creation_compiled, oc.init)
    if cc is None:
        return InitComparison(False, "could not locate runtime within the compiled creation code")

    ic = InitComparison(
        match=False, reason="",
        init_onchain_len=len(oc.init), init_compiled_len=len(cc.init),
        ctor_args_len=len(oc.ctor_args),
        onchain_writes=constructor_writes(oc.init),
        compiled_writes=constructor_writes(cc.init),
    )
    if oc.init == cc.init:
        ic.match = True
        ic.reason = "constructor init-code is byte-identical (%d bytes)" % len(oc.init)
        if oc.ctor_args:
            ic.reason += "; %d bytes of constructor args on-chain" % len(oc.ctor_args)
        return ic

    from .normdiff import diff as norm_diff
    ic.reason = "constructor init-code differs (on-chain %d bytes vs compiled %d bytes)" % (
        len(oc.init), len(cc.init))
    ic.diff = norm_diff(oc.init, cc.init, selectors or [])
    return ic


def _compiled_runtime_tail(creation_compiled: bytes, oc: CreationSplit) -> bytes:
    """Best-effort recovery of the compiled runtime image from its creation code.

    The compiled creation is init ++ runtime with no trailing args, so the runtime is
    the tail whose length equals the on-chain runtime (their non-metadata bodies are
    identical when the source matches). Returns that tail for use as a split anchor.
    """
    rt_len = len(oc.runtime)
    if rt_len and rt_len <= len(creation_compiled):
        return creation_compiled[-rt_len:]
    return b""


def _split_by_shared_prefix(creation_compiled: bytes, init_onchain: bytes) -> Optional[CreationSplit]:
    """Last-resort split: assume the compiled init has the same length as on-chain.

    Used only when the runtime substring can't be located in the compiled creation
    (e.g. a metadata-hash divergence that also shifts a CODECOPY offset). The compiled
    init is then just the same-length prefix, and the rest is treated as runtime.
    """
    n = len(init_onchain)
    if n and n <= len(creation_compiled):
        return CreationSplit(creation_compiled[:n], creation_compiled[n:], b"", n)
    return None
