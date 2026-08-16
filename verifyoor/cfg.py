"""evmole control-flow graph: basic blocks with resolved successor edges.

The intra-block lift is deterministic and complete *within* a block but cannot see
*between* blocks — a stack-computed jump renders as `jump(in0)`. evmole resolves
those edges, including context-sensitive dynamic jumps (function returns, shared-
helper dispatch), by symbolic execution. This wraps evmole's CFG into a
block-start -> resolved-successor-set map the lift and diff consume.

Optional/guarded like the rest of the evmole surface: `from_code` returns None when
evmole is unavailable or errors, so callers degrade to the raw lift.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class CfgBlock:
    start: int
    end: int  # last byte offset of the block (inclusive, per evmole)
    kind: str  # "jump" | "jumpi" | "dynamicjump" | "dynamicjumpi" | "terminate"
    succs: Set[int] = field(default_factory=set)  # all resolved successors (flat) — lift edges
    static_succs: Set[int] = field(default_factory=set)  # non-dynamic edges (context-free)
    dyn_edges: List[Tuple[Tuple[int, ...], int]] = field(default_factory=list)  # (path, to)
    success: Optional[bool] = None  # terminate only: True=return/stop, False=revert/invalid
    dynamic: bool = False  # target was stack-computed (evmole resolved it)


def _edges_of(bt):
    """(static_succs, dyn_edges) from any evmole block-type variant.

    Jump has `to: int`; Jumpi has `true_to`/`false_to: int`; DynamicJump has
    `to: [DynamicJump(path, to)]` (a resolved return per call-stack context);
    DynamicJumpi mixes a static branch with a dynamic list. Keeping the `path`
    (the call stack) lets reachability follow only the context-matching return,
    instead of fanning a shared helper back to every caller."""
    static: Set[int] = set()
    dyn: List[Tuple[Tuple[int, ...], int]] = []
    for attr in ("to", "true_to", "false_to"):
        v = getattr(bt, attr, None)
        if isinstance(v, int):
            static.add(v)
        elif isinstance(v, list):
            for e in v:
                t = getattr(e, "to", None)
                if isinstance(t, int):
                    dyn.append((tuple(getattr(e, "path", None) or ()), t))
    return static, dyn


class Cfg:
    def __init__(self, blocks: Dict[int, CfgBlock]):
        self.blocks = blocks
        self._starts = sorted(blocks)
        # longest call-stack context any dynamic edge needs to match against
        self._ctx = max((len(p) for b in blocks.values() for p, _ in b.dyn_edges), default=1)

    @classmethod
    def from_code(cls, code: bytes) -> Optional["Cfg"]:
        try:
            import evmole
        except ImportError:
            return None
        try:
            info = evmole.contract_info("0x" + code.hex(), control_flow_graph=True)
            raw = info.control_flow_graph.blocks
        except Exception:
            return None
        blocks: Dict[int, CfgBlock] = {}
        for b in raw:
            kind = type(b.btype).__name__.lower()
            static, dyn = _edges_of(b.btype)
            blocks[b.start] = CfgBlock(
                start=b.start,
                end=b.end,
                kind=kind,
                succs=static | {t for _, t in dyn},
                static_succs=static,
                dyn_edges=dyn,
                success=getattr(b.btype, "success", None),
                dynamic=kind.startswith("dynamic"),
            )
        return cls(blocks)

    def block_at(self, pc: int) -> Optional[CfgBlock]:
        """The block whose [start, end] range contains pc."""
        i = bisect.bisect_right(self._starts, pc) - 1
        if i < 0:
            return None
        blk = self.blocks[self._starts[i]]
        return blk if blk.start <= pc <= blk.end else None

    def succs_at(self, pc: int) -> Set[int]:
        """Resolved successor block starts for the block containing pc (empty if none)."""
        blk = self.block_at(pc)
        return blk.succs if blk else set()

    def reachable(self, entry: int) -> Set[int]:
        """Context-sensitive: block starts reachable from `entry` (its own block
        included). At a dynamic jump we follow only the return whose `path` (call
        stack) matches how we arrived, so a shared helper returns to *this* caller
        rather than fanning out to all callers. The traversal carries a bounded trace
        (length `self._ctx`, the longest path) and memoizes on (block, trace)."""
        start_blk = self.block_at(entry)
        if start_blk is None:
            return set()
        K = self._ctx
        seen = set()
        reached: Set[int] = set()
        stack = [(start_blk.start, (start_blk.start,))]
        while stack:
            b, trace = stack.pop()
            if (b, trace) in seen:
                continue
            seen.add((b, trace))
            reached.add(b)
            blk = self.blocks[b]
            succ = set(blk.static_succs)
            for path, to in blk.dyn_edges:
                # trace ends at b and path[0] == b; the edge fires iff its call stack
                # equals our arrival trace (reversed): path == reversed(trace[-len(path):])
                if len(path) <= len(trace) and tuple(reversed(trace[-len(path):])) == path:
                    succ.add(to)
            for s in succ:
                if s in self.blocks:
                    stack.append((s, (trace + (s,))[-K:]))
        return reached

    def function_owners(self, entries) -> Dict[int, Set[int]]:
        """block_start -> set of function entry pcs whose context-sensitive reach
        includes it. Owned by one entry = that function's code; by several = a genuine
        shared helper; by none = dispatcher/prologue/dead. Context-sensitivity keeps
        function-specific codegen (per-type ABI decode/encode, that function's revert
        strings) attributed to its function instead of leaking across the shared
        return machinery."""
        owner: Dict[int, Set[int]] = {}
        for e in entries:
            blk = self.block_at(e)
            if blk is None:
                continue
            for b in self.reachable(blk.start):
                owner.setdefault(b, set()).add(blk.start)
        return owner


class Attributor:
    """Maps a pc to the function that owns its block via the context-sensitive CFG,
    falling back to the offset heuristic when there's no CFG or the block is unreached
    from any function (dispatcher/prologue/dead code)."""

    #: bucket keys for the two non-function ownerships (see `key`).
    SHARED = "__shared__"
    PROLOGUE = "__prologue__"

    def __init__(self, cfg: Optional[Cfg], selectors):
        self._cfg = cfg
        self._selectors = list(selectors)
        self._name = {s.body_offset: (s.signature or "selector 0x%s" % s.selector) for s in selectors}
        self._sel_of = {s.body_offset: s.selector for s in selectors}
        self._entry_of = {}
        self._owner = {}
        if cfg is not None:
            for s in selectors:
                blk = cfg.block_at(s.body_offset)
                if blk is not None:
                    self._entry_of[blk.start] = s.body_offset
            self._owner = cfg.function_owners([s.body_offset for s in selectors])

    def _owner_body_offset(self, pc: int) -> Optional[int]:
        """The single owning function's body offset, or None (shared/prologue/no-cfg)."""
        if self._cfg is None:
            return None
        blk = self._cfg.block_at(pc)
        if blk is None:
            return None
        owners = self._owner.get(blk.start)
        if owners and len(owners) == 1:
            return self._entry_of[next(iter(owners))]
        return None

    def attribute(self, pc: int) -> str:
        from .analyze import attribute_function
        if self._cfg is not None:
            blk = self._cfg.block_at(pc)
            if blk is not None:
                owners = self._owner.get(blk.start)
                if owners and len(owners) == 1:
                    return self._name[self._entry_of[next(iter(owners))]]
                if owners and len(owners) > 1:
                    return "shared helper"
                # unreached by any function: dispatcher/prologue below the first
                # function, otherwise library/shared — never the last-offset function
                # (the offset heuristic's failure mode we set out to fix)
                first = min((s.body_offset for s in self._selectors), default=None)
                if first is not None:
                    return "dispatcher/prologue" if pc < first else "shared helper"
        return attribute_function(pc, self._selectors)

    def key(self, pc: int) -> str:
        """A side-independent bucket key for `pc`: the owning function's 4-byte
        selector ('0x<sel>'), or SHARED / PROLOGUE. Unlike `attribute` (a display
        name), this keys on the selector so a target function and its candidate
        counterpart land in the same bucket despite different body offsets — the basis
        for diffing each function independently instead of one global, cascade-prone
        alignment."""
        if self._cfg is not None:
            blk = self._cfg.block_at(pc)
            if blk is not None:
                owners = self._owner.get(blk.start)
                if owners and len(owners) == 1:
                    return "0x" + self._sel_of[self._entry_of[next(iter(owners))]]
                if owners and len(owners) > 1:
                    return self.SHARED
                first = min((s.body_offset for s in self._selectors), default=None)
                if first is not None:
                    return self.PROLOGUE if pc < first else self.SHARED
        return self.SHARED
