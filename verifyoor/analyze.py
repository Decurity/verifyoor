"""Static analysis of runtime bytecode: dispatcher, selectors, strings, EVM floor, optimizer guess."""
from __future__ import annotations

import string as _string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import metadata
from .disasm import Op, disassemble

_PRINTABLE = set(_string.printable) - set("\x0b\x0c")


@dataclass
class SelectorEntry:
    selector: str  # 8 hex chars, no 0x
    body_offset: int
    signature: Optional[str] = None  # filled by resolve step (Sourcify 4byte DB)
    arguments: Optional[str] = None  # canonical arg types from evmole, e.g. "address,uint256"
    state_mutability: Optional[str] = None  # "pure"|"view"|"payable"|"nonpayable" from evmole

    @property
    def db_name_conflict(self) -> bool:
        """True when the DB-resolved name's arg types disagree with evmole's.

        A 4-byte selector has many preimages, so a signature-DB hit can be the wrong
        one (e.g. `transfer(address,uint256)` for a function whose bytecode actually
        decodes four arrays). When evmole's decoded arg types don't match the
        resolved signature's, the name is a collision — mint from evmole's types."""
        if not self.signature or self.arguments is None:
            return False
        return _canon_args(_sig_args(self.signature)) != _canon_args(self.arguments)

    def mint_signature(self) -> str:
        """Arg-type signature to hand `mine-selector` when the name is unrecoverable."""
        return "(%s)" % (self.arguments or "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "selector": self.selector,
            "body_offset": self.body_offset,
            "signature": self.signature,
            "arguments": self.arguments,
            "state_mutability": self.state_mutability,
            "db_name_conflict": self.db_name_conflict,
        }


def _sig_args(signature: str) -> str:
    """The arg-type list inside a canonical signature: 'f(a,b)' -> 'a,b'."""
    i = signature.find("(")
    return signature[i + 1 : signature.rfind(")")] if i >= 0 else ""


def _canon_args(args: str) -> str:
    return "".join(args.split())  # whitespace-insensitive compare


@dataclass
class Analysis:
    code: bytes
    metadata: metadata.Metadata
    selectors: List[SelectorEntry] = field(default_factory=list)
    has_receive_or_fallback: bool = False
    strings: List[str] = field(default_factory=list)
    push32_hashes: List[str] = field(default_factory=list)  # candidate event topic0s
    error_selectors: List[str] = field(default_factory=list)  # candidate custom-error selectors
    evm_floor: Optional[str] = None
    solc_floor: Optional[str] = None
    optimizer_guess: str = "unknown"  # "off" | "on" | "unknown"
    via_ir_guess: str = "unknown"  # "likely" | "unlikely" | "unknown"
    embedded_metadata: List[Tuple[int, int]] = field(default_factory=list)
    evmole_available: bool = False  # whether arg types / mutability were enriched

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code_len": len(self.code),
            "metadata": self.metadata.to_dict(),
            "selectors": [s.to_dict() for s in self.selectors],
            "has_receive_or_fallback": self.has_receive_or_fallback,
            "strings": self.strings,
            "push32_hashes": self.push32_hashes,
            "error_selectors": self.error_selectors,
            "evm_floor": self.evm_floor,
            "solc_floor": self.solc_floor,
            "optimizer_guess": self.optimizer_guess,
            "via_ir_guess": self.via_ir_guess,
            "embedded_metadata": [list(r) for r in self.embedded_metadata],
            "evmole_available": self.evmole_available,
        }


def _evmole_functions(code: bytes):
    """evmole's decoded functions for the runtime code, or None if unavailable.

    evmole (https://github.com/cdump/evmole, MIT) is the **primary** source for the
    selector set, argument types, and state mutability — materially more accurate
    than a hand-rolled dispatcher walk + ABI guess, in reproducible benchmarks.
    It's a required dependency; the import/error guard is a robustness net so a bad
    bytecode input (or a broken install) degrades to the fallback walk rather than
    crashing analysis."""
    try:
        import evmole
    except ImportError:
        return None
    try:
        info = evmole.contract_info("0x" + code.hex(), selectors=True,
                                    arguments=True, state_mutability=True)
    except Exception:
        return None
    return info.functions


def build_selectors(ops: List[Op], code: bytes) -> Tuple[List[SelectorEntry], bool]:
    """Selector entries, favoring evmole; the dispatcher walk is the fallback/union.

    evmole supplies the selector set, arg types, and mutability. Its dispatcher-entry
    offset is fed through `_resolve_body`, so the trampoline-resolved body offset
    (used for diff attribution) is identical to what `walk_dispatcher` produced —
    verified across all fixtures. `walk_dispatcher` then fills any selector evmole
    missed, and is the sole source when evmole is unavailable. Returns
    (entries sorted by body offset, evmole_used)."""
    by_pc = {op.pc: i for i, op in enumerate(ops)}
    entries: Dict[str, SelectorEntry] = {}
    fns = _evmole_functions(code)
    if fns is not None:
        for f in fns:
            sel = f.selector.lower().removeprefix("0x")
            entries[sel] = SelectorEntry(
                sel,
                _resolve_body(f.bytecode_offset, ops, by_pc),
                arguments=f.arguments,
                state_mutability=f.state_mutability,
            )
    for s in walk_dispatcher(ops):  # union: adds evmole misses / sole source on fallback
        entries.setdefault(s.selector, s)
    return sorted(entries.values(), key=lambda e: e.body_offset), fns is not None


def attribute_function(pc: int, selectors: List[SelectorEntry]) -> str:
    """Name the function whose body region contains pc (via sorted body offsets)."""
    if not selectors:
        return "code@0x%x" % pc
    name = None
    for s in sorted(selectors, key=lambda s: s.body_offset):
        if s.body_offset <= pc:
            name = s.signature or ("selector 0x%s" % s.selector)
        else:
            break
    return name or "dispatcher/prologue"


def _resolve_body(entry_pc: int, ops: List[Op], by_pc: Dict[int, int], depth: int = 0) -> int:
    """Follow a dispatcher entry through decode/relay trampolines to the real body.

    Legacy solc dispatches an external function with args as
      <entry>: JUMPDEST PUSH2 <ret> PUSH2 <cont> CALLDATASIZE PUSH1 0x04 PUSH2 <dec> JUMP
    which decodes calldata then jumps to <cont>, itself often a relay
      <cont>: JUMPDEST PUSH2 <body> JUMP
    so the pushed dispatcher target is two hops from the code that actually
    implements the function. Following those hops gives accurate diff attribution.
    Non-trampoline dispatch (no-arg functions, viaIR) returns the entry unchanged.
    """
    if depth > 4 or entry_pc not in by_pc:
        return entry_pc
    i = by_pc[entry_pc]
    window = ops[i : i + 10]
    if not window or window[0].name != "JUMPDEST":
        return entry_pc
    # bound to this basic block: everything up to (and including) its first terminator
    term = next((k for k, w in enumerate(window) if w.name in ("JUMP", "JUMPI", "STOP", "RETURN")), None)
    if term is None:
        return entry_pc
    block = window[: term + 1]
    names = [w.name for w in block]
    # simple relay: JUMPDEST PUSH <body> JUMP
    if len(block) == 3 and names == ["JUMPDEST", block[1].name, "JUMP"] and block[1].name.startswith("PUSH") and block[1].imm is not None:
        return _resolve_body(block[1].imm_int, ops, by_pc, depth + 1)
    # decode trampoline: JUMPDEST PUSH<ret> PUSH<cont> CALLDATASIZE PUSH1 0x04 PUSH<dec> JUMP
    if names[-1] == "JUMP" and "CALLDATASIZE" in names:
        cds = names.index("CALLDATASIZE")
        pre_pushes = [w for w in block[:cds] if w.name.startswith("PUSH") and w.imm is not None]
        if len(pre_pushes) >= 2 and pre_pushes[1].imm_int is not None:
            return _resolve_body(pre_pushes[1].imm_int, ops, by_pc, depth + 1)
    return entry_pc


def walk_dispatcher(ops: List[Op]) -> List[SelectorEntry]:
    """Extract selector -> body-offset entries from solc's dispatcher.

    Handles the forms solc emits:
      EQ form:   DUP1 PUSH4 <sel> EQ PUSH<n> <body> JUMPI   -> body = pushed target
      SUB form:  PUSH4 <sel> SUB PUSH<n> <nomatch> JUMPI    -> body = fall-through
                 (the optimizer's last-selector trick: jump away on mismatch, so
                  the function body is the instruction right after the JUMPI)
      binary search: GT/LT pivot splits whose leaves are EQ/SUB checks (covered).

    body_offset is resolved through decode/relay trampolines to the pc where the
    function's own code begins (see _resolve_body).
    """
    entries: Dict[str, int] = {}
    for i, op in enumerate(ops):
        if not op.name.startswith("PUSH") or op.imm is None or len(op.imm) != 4:
            continue
        window = ops[i + 1 : i + 6]
        names = [w.name for w in window]

        # EQ form: body is the pushed jump target.
        if "EQ" in names:
            cmp_idx = names.index("EQ")
            dest: Optional[int] = None
            for w in window[cmp_idx + 1 :]:
                if w.name.startswith("PUSH") and w.imm is not None and 1 <= len(w.imm) <= 3:
                    dest = w.imm_int
                elif w.name == "JUMPI" and dest is not None:
                    entries.setdefault(op.imm.hex(), dest)
                    break
                elif w.name in ("JUMP", "JUMPDEST", "REVERT", "STOP"):
                    break

        # SUB form (last selector): SUB must immediately follow the PUSH4, and the
        # body is the fall-through right after the mismatch JUMPI.
        elif names and names[0] == "SUB":
            saw_dest = False
            for k in range(1, len(window)):
                w = window[k]
                if w.name.startswith("PUSH") and w.imm is not None and 1 <= len(w.imm) <= 3:
                    saw_dest = True
                elif w.name == "JUMPI" and saw_dest:
                    body_idx = i + 1 + k + 1  # op after the JUMPI
                    if body_idx < len(ops):
                        entries.setdefault(op.imm.hex(), ops[body_idx].pc)
                    break
                elif w.name in ("JUMP", "JUMPDEST", "REVERT", "STOP"):
                    break

    by_pc = {op.pc: idx for idx, op in enumerate(ops)}
    resolved = {sel: _resolve_body(off, ops, by_pc) for sel, off in entries.items()}
    return [SelectorEntry(sel, off) for sel, off in sorted(resolved.items(), key=lambda kv: kv[1])]


def _detect_receive_or_fallback(ops: List[Op], selector_entries: List[SelectorEntry]) -> bool:
    """A contract has receive()/fallback() iff the dispatcher's calldatasize<4
    branch does something other than revert immediately.

    Locates the `CALLDATASIZE LT` size check and its <4 handler under both
    polarities (legacy: `LT PUSHn JUMPI` -> handler at the target; viaIR:
    `LT ISZERO PUSHn JUMPI` -> handler is the fall-through), then classifies the
    handler: an immediate `PUSH0/PUSH1 0x00 DUP1 REVERT` means no receive/fallback;
    anything else (a size==0 -> STOP branch, or a real body) means one exists.
    """
    by_pc = {op.pc: i for i, op in enumerate(ops)}
    for i in range(min(len(ops), 16)):
        if ops[i].name != "CALLDATASIZE" or i + 2 >= len(ops):
            continue
        if ops[i + 1].name != "LT":
            continue
        if ops[i + 2].name == "ISZERO":
            # viaIR polarity: >=4 jumps to selectors; <4 falls through past the JUMPI
            j = i + 2
            while j < len(ops) and ops[j].name != "JUMPI":
                j += 1
            handler_idx = j + 1
        elif ops[i + 2].name.startswith("PUSH") and ops[i + 2].imm is not None:
            # legacy polarity: <4 jumps to the handler at the pushed target
            dest = ops[i + 2].imm_int
            if dest is None or dest not in by_pc:
                return False
            handler_idx = by_pc[dest]
        else:
            continue
        tail = [o.name for o in ops[handler_idx : handler_idx + 6]]
        compact = [n for n in tail if n != "JUMPDEST"]
        if compact[:3] in (["PUSH0", "DUP1", "REVERT"], ["PUSH1", "DUP1", "REVERT"]):
            return False
        return True
    return False


# viaIR routes calldatasize>=4 to the selector table via `CALLDATASIZE LT ISZERO
# ... JUMPI`; legacy routes calldatasize<4 to a handler via `CALLDATASIZE LT ...
# JUMPI` (no ISZERO between LT and the push). Empirically stable across 0.8.20-0.8.35.
def detect_via_ir(ops: List[Op]) -> str:
    """Heuristic pipeline detection: 'likely' | 'unlikely' | 'unknown'."""
    head = ops[:20]
    names = [o.name for o in head]
    # Strong positive: PUSH1 0x80 DUP1 PUSH1 0x40 MSTORE (viaIR free-ptr init w/ reuse)
    for i in range(len(head) - 4):
        if (
            head[i].name == "PUSH1" and head[i].imm_int == 0x80
            and head[i + 1].name == "DUP1"
            and head[i + 2].name == "PUSH1" and head[i + 2].imm_int == 0x40
            and head[i + 3].name == "MSTORE"
        ):
            return "likely"
    # Primary marker: CALLDATASIZE LT ISZERO (size-first routing) => viaIR
    for i in range(len(names) - 2):
        if names[i] == "CALLDATASIZE" and names[i + 1] == "LT" and names[i + 2] == "ISZERO":
            return "likely"
    # Legacy marker: CALLDATASIZE LT <PUSH> (no ISZERO) => not viaIR
    for i in range(len(names) - 2):
        if names[i] == "CALLDATASIZE" and names[i + 1] == "LT" and names[i + 2].startswith("PUSH"):
            return "unlikely"
    return "unknown"


_STRING_CHARS = set(_string.ascii_letters + _string.digits + " .,:;!?'\"()-_/%")
_VOWELS = set("aeiouAEIOU")


def _plausible_message(s: str) -> bool:
    """Filter candidate strings down to likely revert/log literals. Length floor is
    3 so short shift-decoded literals ('eth','bal') survive; raw ASCII runs use a
    higher floor (see _message_char_runs) to avoid opcode-byte noise."""
    if len(s) < 3 or not set(s) <= _STRING_CHARS:
        return False
    if not set(s) & _VOWELS:
        return False
    letters = sum(c.isalpha() for c in s)
    return letters / len(s) >= 0.5


def _word_literal(word: bytes) -> Optional[str]:
    """A short string literal occupies a 32-byte word left-aligned (message bytes
    first, then zero padding). Return that leading run iff the rest is zero-padded,
    which distinguishes a string from an address/hash/selector constant."""
    j = 0
    while j < len(word) and chr(word[j]) in _STRING_CHARS:
        j += 1
    if j < 3 or any(b != 0 for b in word[j:]):
        return None
    return word[:j].decode("ascii")


def _decode_word_literals(ops: List[Op]) -> List[str]:
    """Recover string literals that never appear as raw ASCII in the bytecode:
      shift form (optimized): PUSHn X PUSH1 sh SHL  -> word = X << sh
      padded form (unoptimized): PUSH32 <string ++ zero padding>
    then take the left-aligned message run of the word."""
    out: List[str] = []
    for i, op in enumerate(ops):
        if not (op.name.startswith("PUSH") and op.imm):
            continue
        # shift form
        if i + 2 < len(ops) and ops[i + 1].name == "PUSH1" and ops[i + 1].imm and ops[i + 2].name == "SHL":
            word = ((op.imm_int << ops[i + 1].imm_int) & ((1 << 256) - 1)).to_bytes(32, "big")
            s = _word_literal(word)
            if s:
                out.append(s)
            continue
        # padded form (only wide pushes can hold a >=3 char string + padding)
        if len(op.imm) >= 4:
            s = _word_literal(op.imm.ljust(32, b"\x00"))
            if s:
                out.append(s)
    return out


def _data_section_runs(code: bytes, min_len: int = 8) -> List[str]:
    """Long string literals (>31 bytes) live in the code's data section and are
    CODECOPY'd, appearing as raw ASCII. Scanning message chars directly bounds the
    run at adjacent opcode bytes; a space is required because such literals are
    multi-word messages, which rejects ASCII-valued opcode runs ('j8)Pu%')."""
    out: List[str] = []
    cur: List[str] = []
    for byte in code:
        if chr(byte) in _STRING_CHARS:
            cur.append(chr(byte))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return [s for s in out if " " in s.strip()]


def extract_strings(code: bytes, ops: Optional[List[Op]] = None, cap: int = 64) -> List[str]:
    candidates = _data_section_runs(code)
    if ops is not None:
        candidates += _decode_word_literals(ops)
    seen: Set[str] = set()
    cleaned = []
    for s in candidates:
        s = s.strip()
        if s in seen or not _plausible_message(s):
            continue
        seen.add(s)
        cleaned.append(s)
    return cleaned[:cap]


# Feature opcode -> (evm floor, solc floor). Requires >=2 sightings to tolerate
# data sections being misread as code by the linear scan.
_FLOOR_FEATURES = {
    "PUSH0": ("shanghai", "0.8.20"),
    "MCOPY": ("cancun", "0.8.24"),
    "TLOAD": ("cancun", "0.8.24"),
    "TSTORE": ("cancun", "0.8.24"),
    "BLOBHASH": ("cancun", "0.8.24"),
    "BASEFEE": ("london", "0.8.7"),
    "CHAINID": ("istanbul", "0.5.12"),
    "SELFBALANCE": ("istanbul", "0.5.12"),
    "SHR": ("constantinople", "0.4.21"),
    "CREATE2": ("constantinople", "0.4.24"),
    "EXTCODEHASH": ("constantinople", "0.5.0"),
}
_EVM_RANK = ["constantinople", "istanbul", "london", "shanghai", "cancun"]


def detect_floors(ops: List[Op]) -> Tuple[Optional[str], Optional[str]]:
    counts: Dict[str, int] = {}
    for op in ops:
        if op.name in _FLOOR_FEATURES:
            counts[op.name] = counts.get(op.name, 0) + 1
    evm_floor: Optional[str] = None
    solc_floor: Optional[str] = None
    for name, cnt in counts.items():
        threshold = 1 if name in ("PUSH0", "SHR") else 2
        if cnt < threshold:
            continue
        evm, solc = _FLOOR_FEATURES[name]
        if evm_floor is None or _EVM_RANK.index(evm) > _EVM_RANK.index(evm_floor):
            evm_floor = evm
        if solc_floor is None or tuple(map(int, solc.split("."))) > tuple(map(int, solc_floor.split("."))):
            solc_floor = solc
    return evm_floor, solc_floor


# PUSH32 0x08c379a000...00 (padded Error(string) selector) => classic unoptimized codegen.
_UNOPT_MARKER = bytes.fromhex("7f08c379a0" + "00" * 28)
# PUSH3 0x461bcd PUSH1 0xe5 SHL (Error(string) selector built by shift) => optimizer on.
_OPT_MARKER = bytes.fromhex("62461bcd60e51b")


def detect_optimizer(code: bytes) -> str:
    if _UNOPT_MARKER in code:
        return "off"
    if _OPT_MARKER in code:
        return "on"
    return "unknown"


def collect_hash_candidates(ops: List[Op], selectors: Set[str]) -> Tuple[List[str], List[str]]:
    """(candidate event topic0s from PUSH32, candidate error selectors from PUSH4)."""
    topics: List[str] = []
    errors: List[str] = []
    known_noise = {"ffffffff", "00000000", "4e487b71", "08c379a0"}  # masks, Panic, Error
    for op in ops:
        if op.imm is None:
            continue
        if len(op.imm) == 32:
            h = op.imm.hex()
            # skip masks / small constants / ascii payloads
            if op.imm.count(0xFF) > 16 or op.imm.count(0x00) > 16:
                continue
            if all(0x20 <= b < 0x7F or b == 0 for b in op.imm):
                continue
            if h not in topics:
                topics.append(h)
        elif len(op.imm) == 4:
            h = op.imm.hex()
            if h not in selectors and h not in known_noise and h not in errors:
                errors.append(h)
    return topics[:32], errors[:32]


def analyze(code: bytes) -> Analysis:
    md = metadata.parse_trailing(code)
    stripped = code[: md.start] if md.present else code
    ops = disassemble(stripped)

    selectors, evmole_available = build_selectors(ops, stripped)
    sel_set = {s.selector for s in selectors}
    topics, error_sels = collect_hash_candidates(ops, sel_set)
    evm_floor, solc_floor = detect_floors(ops)

    return Analysis(
        code=code,
        metadata=md,
        selectors=selectors,
        has_receive_or_fallback=_detect_receive_or_fallback(ops, selectors),
        strings=extract_strings(stripped, ops),
        push32_hashes=topics,
        error_selectors=error_sels,
        evm_floor=evm_floor,
        solc_floor=solc_floor,
        optimizer_guess=detect_optimizer(stripped),
        via_ir_guess=detect_via_ir(ops),
        embedded_metadata=[r for r in metadata.find_embedded(code) if not (md.present and r[0] == md.start)],
        evmole_available=evmole_available,
    )
