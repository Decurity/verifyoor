"""Intra-block IR lift: per-basic-block symbolic stack execution.

Within a basic block every stack motion (PUSH/DUP/SWAP/POP) is statically
resolvable, so each block lifts deterministically and completely to a short
list of Yul-style statements — no fixpoint, no jump-target resolution, no
failure mode. Values flowing in from predecessors become symbolic inputs
(``in0`` = top of the entry stack, revealed lazily as the block digs deeper).
Control flow between blocks stays explicit (``jump``/``jumpi`` with literal pc
targets); stitching blocks together is the reader's job.

Rendering rules keep evaluation order and count honest:
  - pure values (arithmetic, environment constants) inline freely, even when
    DUP'd, unless a long expression is used more than once (then a ``let``);
  - impure reads (SLOAD/MLOAD/KECCAK256/BALANCE/…) inline only when used once
    with no interfering write between creation and use — otherwise they bind
    to a ``let`` at the pc where they actually execute;
  - calls/creates always bind (``let tN := call(…)``), or render as
    ``pop(call(…))`` when the result is discarded.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .disasm import Op

# opcode name -> (stack pops, stack pushes). PUSH/DUP/SWAP handled structurally.
_ARITY: Dict[str, Tuple[int, int]] = {
    "STOP": (0, 0), "ADD": (2, 1), "MUL": (2, 1), "SUB": (2, 1), "DIV": (2, 1),
    "SDIV": (2, 1), "MOD": (2, 1), "SMOD": (2, 1), "ADDMOD": (3, 1), "MULMOD": (3, 1),
    "EXP": (2, 1), "SIGNEXTEND": (2, 1),
    "LT": (2, 1), "GT": (2, 1), "SLT": (2, 1), "SGT": (2, 1), "EQ": (2, 1),
    "ISZERO": (1, 1), "AND": (2, 1), "OR": (2, 1), "XOR": (2, 1), "NOT": (1, 1),
    "BYTE": (2, 1), "SHL": (2, 1), "SHR": (2, 1), "SAR": (2, 1), "KECCAK256": (2, 1),
    "ADDRESS": (0, 1), "BALANCE": (1, 1), "ORIGIN": (0, 1), "CALLER": (0, 1),
    "CALLVALUE": (0, 1), "CALLDATALOAD": (1, 1), "CALLDATASIZE": (0, 1),
    "CALLDATACOPY": (3, 0), "CODESIZE": (0, 1), "CODECOPY": (3, 0), "GASPRICE": (0, 1),
    "EXTCODESIZE": (1, 1), "EXTCODECOPY": (4, 0), "RETURNDATASIZE": (0, 1),
    "RETURNDATACOPY": (3, 0), "EXTCODEHASH": (1, 1), "BLOCKHASH": (1, 1),
    "COINBASE": (0, 1), "TIMESTAMP": (0, 1), "NUMBER": (0, 1), "PREVRANDAO": (0, 1),
    "GASLIMIT": (0, 1), "CHAINID": (0, 1), "SELFBALANCE": (0, 1), "BASEFEE": (0, 1),
    "BLOBHASH": (1, 1), "BLOBBASEFEE": (0, 1),
    "POP": (1, 0), "MLOAD": (1, 1), "MSTORE": (2, 0), "MSTORE8": (2, 0),
    "SLOAD": (1, 1), "SSTORE": (2, 0), "JUMP": (1, 0), "JUMPI": (2, 0),
    "PC": (0, 1), "MSIZE": (0, 1), "GAS": (0, 1), "JUMPDEST": (0, 0),
    "TLOAD": (1, 1), "TSTORE": (2, 0), "MCOPY": (3, 0),
    "LOG0": (2, 0), "LOG1": (3, 0), "LOG2": (4, 0), "LOG3": (5, 0), "LOG4": (6, 0),
    "CREATE": (3, 1), "CALL": (7, 1), "CALLCODE": (7, 1), "RETURN": (2, 0),
    "DELEGATECALL": (6, 1), "CREATE2": (4, 1), "STATICCALL": (6, 1), "REVERT": (2, 0),
    "INVALID": (0, 0), "SELFDESTRUCT": (1, 0),
}

_TERMINATORS = {"STOP", "JUMP", "JUMPI", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}
_CALL_LIKE = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"}

# Which mutable domain an impure value reads; absent = pure within the tx
# (env opcodes are constant for the whole execution, so duplicating/reordering
# them is sound). PC is folded to its literal value instead.
_READS = {
    "MLOAD": "mem", "KECCAK256": "mem", "MSIZE": "mem",
    "SLOAD": "sto", "TLOAD": "tra",
    "BALANCE": "ext", "SELFBALANCE": "ext", "EXTCODESIZE": "ext",
    "EXTCODEHASH": "ext", "RETURNDATASIZE": "ext", "GAS": "ext",
}
_MEM_WRITERS = {"MSTORE", "MSTORE8", "CALLDATACOPY", "CODECOPY", "EXTCODECOPY",
                "RETURNDATACOPY", "MCOPY"}


def _clobbers(name: str) -> frozenset:
    if name in _CALL_LIKE:  # calls write returndata and can reenter us
        return frozenset(("mem", "sto", "tra", "ext"))
    if name in _MEM_WRITERS:
        return frozenset(("mem",))
    if name == "SSTORE":
        return frozenset(("sto",))
    if name == "TSTORE":
        return frozenset(("tra",))
    return frozenset()


@dataclass
class _Node:
    kind: str  # "const" | "input" | "op"
    seq: int
    born: int  # statements emitted when created — where a `let` would go
    name: str = ""
    args: Tuple["_Node", ...] = ()
    value: int = 0
    width: int = 0  # const byte width (original PUSH width; 0 = minimal)
    pc: int = -1
    reads: Optional[str] = None
    is_call: bool = False


def _const_str(node: _Node) -> str:
    # Keep the original push width so constants render byte-for-byte like the
    # token view (0x08c379a0 stays recognizable, PUSH1 0x00 stays 0x00).
    width = max(node.width, (node.value.bit_length() + 7) // 8, 1)
    return "0x" + node.value.to_bytes(width, "big").hex()


@dataclass
class _Stmt:
    pc: int
    name: str
    args: Tuple[_Node, ...]
    clobbers: frozenset
    define: Optional[_Node] = None  # call-like result bound at this position


def split_blocks(ops: Sequence[Op]) -> List[List[Op]]:
    """Leaders: op 0, every JUMPDEST, and the op after every terminator."""
    blocks: List[List[Op]] = []
    cur: List[Op] = []
    for op in ops:
        if op.name == "JUMPDEST" and cur:
            blocks.append(cur)
            cur = []
        cur.append(op)
        if op.name in _TERMINATORS or op.name.startswith("UNKNOWN"):
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    return blocks


def _ascii_note(value: int) -> Optional[str]:
    """Left-aligned printable payloads (string literal words) decoded inline."""
    if value < (1 << 32):
        return None
    b = value.to_bytes((value.bit_length() + 7) // 8, "big").rstrip(b"\x00")
    if len(b) >= 4 and all(0x20 <= c < 0x7F for c in b):
        return b.decode("ascii")
    return None


@dataclass
class LiftedBlock:
    start_pc: int
    next_pc: int  # first pc after the block (fallthrough target)
    is_jumpdest: bool
    falls_through: bool
    lines: List[str]  # "0x1a4: mstore(0x40, 0x80)"
    n_inputs: int
    exit_stack: List[str] = field(default_factory=list)  # rendered, top first
    dyn_jump_pc: Optional[int] = None  # pc of a stack-computed jump target (unresolved here)
    resolved_succs: Optional[List[int]] = None  # CFG-resolved targets for that dynamic jump

    def render(self, max_succs: int = 8) -> List[str]:
        out = ["block 0x%x%s:" % (self.start_pc, " [jumpdest]" if self.is_jumpdest else "")]
        if self.n_inputs:
            out.append("  // reads %d stack input(s); in0 = top of stack at entry" % self.n_inputs)
        out.extend("  " + l for l in self.lines)
        if self.exit_stack:
            out.append("  // stack out (top first): [%s]" % ", ".join(self.exit_stack))
        if self.resolved_succs:  # evmole resolved the stack-computed jump target(s)
            tgts = ["0x%x" % s for s in self.resolved_succs[:max_succs]]
            more = "" if len(self.resolved_succs) <= max_succs else " (+%d more)" % (len(self.resolved_succs) - max_succs)
            out.append("  // dynamic jump -> %s%s  [resolved by evmole]" % (", ".join(tgts), more))
        if self.falls_through:
            out.append("  // falls through to 0x%x" % self.next_pc)
        return out


def lift_block(ops: Sequence[Op]) -> LiftedBlock:
    stack: List[_Node] = []
    stmts: List[_Stmt] = []
    seq_counter = 0
    n_inputs = 0

    def mk(**kw) -> _Node:
        nonlocal seq_counter
        node = _Node(seq=seq_counter, born=len(stmts), **kw)
        seq_counter += 1
        return node

    def need(depth: int) -> None:
        # Underflow reveals the entry stack top-first: the modeled bottom always
        # corresponds to the shallowest not-yet-revealed entry slot.
        nonlocal n_inputs
        while len(stack) < depth:
            stack.insert(0, mk(kind="input", value=n_inputs))
            n_inputs += 1

    def pop() -> _Node:
        need(1)
        return stack.pop()

    falls_through = True
    dyn_jump_pc = None
    for op in ops:
        name = op.name
        if name == "JUMPDEST":
            continue
        if name == "PC":  # constant at its own site — fold it
            stack.append(mk(kind="const", value=op.pc, pc=op.pc))
            continue
        if name.startswith("PUSH"):
            stack.append(mk(kind="const", value=op.imm_int or 0,
                            width=len(op.imm) if op.imm is not None else 0, pc=op.pc))
            continue
        if name.startswith("DUP"):
            n = int(name[3:])
            need(n)
            stack.append(stack[-n])
            continue
        if name.startswith("SWAP"):
            n = int(name[4:])
            need(n + 1)
            stack[-1], stack[-n - 1] = stack[-n - 1], stack[-1]
            continue
        if name == "POP":
            pop()
            continue
        if name.startswith("UNKNOWN"):  # invalid opcode halts execution
            stmts.append(_Stmt(op.pc, "unknown_0x%s" % name[8:], (), frozenset()))
            falls_through = False
            break
        pops, pushes = _ARITY.get(name, (0, 0))
        args = tuple(pop() for _ in range(pops))
        lname = name.lower()
        if name in _CALL_LIKE:
            node = mk(kind="op", name=lname, args=args, pc=op.pc, reads="ext", is_call=True)
            stmts.append(_Stmt(op.pc, lname, args, _clobbers(name), define=node))
            stack.append(node)
        elif pushes:
            stack.append(mk(kind="op", name=lname, args=args, pc=op.pc, reads=_READS.get(name)))
        else:
            stmts.append(_Stmt(op.pc, lname, args, _clobbers(name)))
            if name in _TERMINATORS:
                falls_through = name == "JUMPI"
                # a stack-computed jump target (not a PUSHed constant) is the lift's
                # blind spot — record its pc so the CFG can resolve it.
                if name in ("JUMP", "JUMPI") and args and args[0].kind != "const":
                    dyn_jump_pc = op.pc
                break

    exit_nodes = list(reversed(stack))  # top first
    virtual_exit = len(stmts)

    # ---- pass 2: reference counts and (conservative) latest use sites ----
    # refs approximates "occurrences if fully inlined": recursing on every
    # visit makes an impure value inside a twice-used pure expression count
    # twice (forcing a let). Capped so shared DAGs stay linear to walk.
    refs: Dict[int, int] = {}
    use_site: Dict[int, int] = {}
    _CAP = 8

    def visit(node: _Node, site: int) -> None:
        i = id(node)
        refs[i] = refs.get(i, 0) + 1
        if use_site.get(i, -1) < site:
            use_site[i] = site
        if refs[i] <= _CAP and node.kind == "op" and not node.is_call:
            for a in node.args:
                visit(a, site)

    for si, st in enumerate(stmts):
        for a in st.args:
            visit(a, si)
    for n in exit_nodes:
        visit(n, virtual_exit)

    # ---- temp decisions ----
    def conflict(node: _Node) -> bool:
        if node.reads is None:
            return False
        hi = use_site.get(id(node), node.born)
        return any(node.reads in s.clobbers for s in stmts[node.born:hi])

    rlen_memo: Dict[int, int] = {}

    def rlen(node: _Node) -> int:
        i = id(node)
        if i not in rlen_memo:
            if node.kind == "const":
                rlen_memo[i] = len(_const_str(node))
            elif node.kind == "input" or node.is_call:
                rlen_memo[i] = 3
            else:
                rlen_memo[i] = (len(node.name) + 2 + sum(rlen(a) for a in node.args)
                                + 2 * max(0, len(node.args) - 1))
        return rlen_memo[i]

    needs_temp: Set[int] = set()
    all_nodes: List[_Node] = []
    decided: Set[int] = set()

    def decide(node: _Node) -> None:
        i = id(node)
        if i in decided:
            return
        decided.add(i)
        all_nodes.append(node)
        if node.kind == "op" and not node.is_call:
            for a in node.args:
                decide(a)
        if node.is_call:
            return  # bound at its own statement
        r = refs.get(i, 0)
        if node.kind == "op" and node.reads is not None:
            if r > 1 or conflict(node):
                needs_temp.add(i)
        elif node.kind in ("op", "const"):
            if r > 1 and rlen(node) > 20:
                needs_temp.add(i)

    for st in stmts:
        for a in st.args:
            decide(a)
    for n in exit_nodes:
        decide(n)

    # ---- render ----
    names: Dict[int, str] = {}

    def render(node: _Node) -> str:
        i = id(node)
        if i in names:
            return names[i]
        if node.kind == "const":
            s = _const_str(node)
            note = _ascii_note(node.value)
            return '%s /* "%s" */' % (s, note) if note else s
        if node.kind == "input":
            return "in%d" % node.value
        return "%s(%s)" % (node.name, ", ".join(render(a) for a in node.args))

    deferred = sorted((n for n in all_nodes if id(n) in needs_temp),
                      key=lambda n: (n.born, n.seq))
    lines: List[str] = []
    tcount = 0
    di = 0
    for si in range(len(stmts) + 1):
        while di < len(deferred) and deferred[di].born <= si:
            node = deferred[di]
            di += 1
            rhs = render(node)  # before naming, so the rhs is the expression itself
            nm = "t%d" % tcount
            tcount += 1
            names[id(node)] = nm
            lines.append("0x%x: let %s := %s" % (node.pc, nm, rhs))
        if si == len(stmts):
            break
        st = stmts[si]
        if st.define is not None:
            rhs = "%s(%s)" % (st.name, ", ".join(render(a) for a in st.args))
            if refs.get(id(st.define), 0) == 0:
                lines.append("0x%x: pop(%s)" % (st.pc, rhs))
            else:
                nm = "t%d" % tcount
                tcount += 1
                names[id(st.define)] = nm
                lines.append("0x%x: let %s := %s" % (st.pc, nm, rhs))
        else:
            lines.append("0x%x: %s(%s)" % (st.pc, st.name, ", ".join(render(a) for a in st.args)))

    last = ops[-1]
    next_pc = last.pc + 1 + (len(last.imm) if last.imm is not None else 0)
    return LiftedBlock(
        start_pc=ops[0].pc,
        next_pc=next_pc,
        is_jumpdest=ops[0].name == "JUMPDEST",
        falls_through=falls_through,
        lines=lines,
        n_inputs=n_inputs,
        exit_stack=[render(n) for n in exit_nodes],
        dyn_jump_pc=dyn_jump_pc,
    )


class Lifter:
    """Lifts blocks of one disassembled code image on demand (cached).

    Given an optional evmole `Cfg`, each block's stack-computed jump target is
    resolved to concrete successor pcs — turning the lift's `jump(in0)` blind spot
    into a connected control-flow view. Every evmole block boundary aligns with a
    lift boundary (verified), so a dynamic jump's pc maps cleanly onto its CFG block."""

    def __init__(self, ops: Sequence[Op], cfg=None):
        self._blocks = split_blocks(ops)
        self._starts = [b[0].pc for b in self._blocks]
        self._cfg = cfg
        self._cache: Dict[int, LiftedBlock] = {}

    def _lifted(self, i: int) -> LiftedBlock:
        if i not in self._cache:
            lb = lift_block(self._blocks[i])
            if self._cfg is not None and lb.dyn_jump_pc is not None:
                succs = self._cfg.succs_at(lb.dyn_jump_pc)
                if succs:
                    lb.resolved_succs = sorted(succs)
            self._cache[i] = lb
        return self._cache[i]

    def lift_range(self, lo_pc: int, hi_pc: int, max_blocks: int = 2,
                   max_lines: int = 16) -> List[str]:
        """Rendered IR of the blocks covering [lo_pc, hi_pc], truncated."""
        if not self._blocks:
            return []
        i = max(0, bisect.bisect_right(self._starts, lo_pc) - 1)
        out: List[str] = []
        used = 0
        while i < len(self._blocks) and used < max_blocks and self._starts[i] <= hi_pc:
            out.extend(self._lifted(i).render())
            used += 1
            i += 1
        remaining = 0
        while i < len(self._blocks) and self._starts[i] <= hi_pc:
            remaining += 1
            i += 1
        if len(out) > max_lines:
            out = out[:max_lines] + ["..."]
        if remaining:
            out.append("... (+%d more block(s) in this region)" % remaining)
        return out

    def listing(self, selectors=None) -> List[str]:
        """Full lifted listing, grouped under function headings by body offset."""
        from .analyze import attribute_function

        selectors = selectors or []
        lines: List[str] = []
        current = None
        for i in range(len(self._blocks)):
            fn = attribute_function(self._starts[i], selectors)
            if fn != current:
                if lines:
                    lines.append("")
                lines.append("== %s ==" % fn)
                current = fn
            lines.extend(self._lifted(i).render())
        return lines
