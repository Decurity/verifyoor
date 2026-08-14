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
    succs: Set[int] = field(default_factory=set)  # resolved successor block starts
    success: Optional[bool] = None  # terminate only: True=return/stop, False=revert/invalid
    dynamic: bool = False  # target was stack-computed (evmole resolved it)


def _succs_of(bt) -> Set[int]:
    """Collect resolved successor pcs from any evmole block-type variant.

    Jump has `to: int`; Jumpi has `true_to`/`false_to: int`; DynamicJump has
    `to: [DynamicJump(path, to)]`; DynamicJumpi mixes a static edge with a dynamic list."""
    out: Set[int] = set()
    for attr in ("to", "true_to", "false_to"):
        v = getattr(bt, attr, None)
        if isinstance(v, int):
            out.add(v)
        elif isinstance(v, list):
            for e in v:
                t = getattr(e, "to", None)
                if isinstance(t, int):
                    out.add(t)
    return out


class Cfg:
    def __init__(self, blocks: Dict[int, CfgBlock]):
        self.blocks = blocks
        self._starts = sorted(blocks)

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
            blocks[b.start] = CfgBlock(
                start=b.start,
                end=b.end,
                kind=kind,
                succs=_succs_of(b.btype),
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
        """Block starts reachable from `entry` following resolved edges (entry's own
        block included). Dynamic edges are followed too, so a shared helper pulls its
        resolved return targets in — used for shared-block detection, not precise slicing."""
        start_blk = self.block_at(entry)
        if start_blk is None:
            return set()
        seen: Set[int] = set()
        stack = [start_blk.start]
        while stack:
            s = stack.pop()
            if s in seen or s not in self.blocks:
                continue
            seen.add(s)
            stack.extend(self.blocks[s].succs)
        return seen
