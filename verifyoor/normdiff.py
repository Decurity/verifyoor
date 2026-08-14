"""Offset-stable disassembly diff for LLM feedback.

A one-byte source change shifts every downstream jump target, so a raw byte or
naive opcode diff drowns the real change in noise. We normalize each PUSH whose
immediate is a valid JUMPDEST into a symbolic label (indexed by sorted-jumpdest
order), leaving semantic immediates (selectors, constants, string data) literal.
Then difflib localizes the genuine divergences, and each is attributed to the
enclosing function via the selector->body-offset map.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .analyze import SelectorEntry, attribute_function
from .disasm import Op, disassemble, jumpdests
from .lift import Lifter


def _normalize_tokens(code: bytes) -> Tuple[List[str], List[Op]]:
    """Tokenize with jump targets abstracted for offset stability.

    A PUSH whose immediate is a valid JUMPDEST collapses to a single opaque
    `PUSHDEST` token — no width, no value. When source grows, every downstream
    jumpdest pc changes and small targets widen PUSH1->PUSH2, so keeping either
    would make the whole tail diff; dropping both leaves only genuine structural
    changes. Non-jump immediates (selectors, constants, string data) stay literal
    because their values carry meaning.
    """
    ops = disassemble(code)
    dests = jumpdests(code)
    tokens: List[str] = []
    for op in ops:
        if op.imm is None:
            tokens.append(op.name)
        elif op.name.startswith("PUSH") and 1 <= len(op.imm) <= 3 and op.imm_int in dests:
            tokens.append("PUSHDEST")
        else:
            tokens.append("%s 0x%s" % (op.name, op.imm.hex()))
    return tokens, ops


@dataclass
class RegionDiff:
    tag: str  # replace | delete | insert
    target_pc: int
    function: str
    expected: List[str] = field(default_factory=list)  # target (on-chain) side
    got: List[str] = field(default_factory=list)  # candidate side
    expected_ir: List[str] = field(default_factory=list)  # lifted enclosing block(s)
    got_ir: List[str] = field(default_factory=list)

    def render(self, ctx: int = 8) -> str:
        exp = self.expected[:ctx] + (["..."] if len(self.expected) > ctx else [])
        got = self.got[:ctx] + (["..."] if len(self.got) > ctx else [])
        head = "[%s @ 0x%x in %s]" % (self.tag, self.target_pc, self.function)
        parts = [head,
                 "    expected: %s" % (" ; ".join(exp) or "(none)"),
                 "    got:      %s" % (" ; ".join(got) or "(none)")]
        if self.expected_ir:
            parts.append("    expected IR (target block):")
            parts.extend("      " + l for l in self.expected_ir)
        if self.got_ir:
            parts.append("    got IR (candidate block):")
            parts.extend("      " + l for l in self.got_ir)
        return "\n".join(parts)


@dataclass
class NormDiff:
    match: bool
    length_delta: int
    region_count: int
    regions: List[RegionDiff] = field(default_factory=list)

    def summary(self, max_regions: int = 6) -> str:
        if self.match:
            return "normalized opcode streams are identical (any residual diff is data/immediates only)"
        lines = [
            "%d divergent region(s); candidate length delta = %+d opcodes" % (self.region_count, self.length_delta)
        ]
        for r in self.regions[:max_regions]:
            lines.append(r.render())
        if self.region_count > max_regions:
            lines.append("... %d more region(s)" % (self.region_count - max_regions))
        return "\n".join(lines)


def diff(target_code: bytes, candidate_code: bytes, selectors: Optional[List[SelectorEntry]] = None,
         lift_ir: bool = True) -> NormDiff:
    selectors = selectors or []
    t_tokens, t_ops = _normalize_tokens(target_code)
    c_tokens, c_ops = _normalize_tokens(candidate_code)

    # pc of each target token, to attribute regions to functions
    t_pcs = [op.pc for op in t_ops]

    sm = difflib.SequenceMatcher(a=t_tokens, b=c_tokens, autojunk=False)
    regions: List[RegionDiff] = []
    t_lifter: Optional[Lifter] = None
    c_lifter: Optional[Lifter] = None
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if lift_ir and t_lifter is None:
            from .cfg import Cfg
            # resolve dynamic-jump edges on the target (expected) side — the
            # authoritative reference the model reads on a mismatch
            t_lifter = Lifter(t_ops, cfg=Cfg.from_code(target_code))
            c_lifter = Lifter(c_ops)
        pc = t_pcs[i1] if i1 < len(t_pcs) else (t_pcs[-1] if t_pcs else 0)
        regions.append(
            RegionDiff(
                tag=tag,
                target_pc=pc,
                function=attribute_function(pc, selectors),
                expected=t_tokens[i1:i2],
                got=c_tokens[j1:j2],
                expected_ir=(t_lifter.lift_range(t_ops[i1].pc, t_ops[i2 - 1].pc)
                             if lift_ir and i2 > i1 else []),
                got_ir=(c_lifter.lift_range(c_ops[j1].pc, c_ops[j2 - 1].pc)
                        if lift_ir and j2 > j1 else []),
            )
        )
    return NormDiff(
        match=not regions,
        length_delta=len(c_tokens) - len(t_tokens),
        region_count=len(regions),
        regions=regions,
    )
