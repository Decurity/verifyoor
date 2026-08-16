"""Offset-stable disassembly diff for LLM feedback.

A one-byte source change shifts every downstream jump target, so a raw byte or
naive opcode diff drowns the real change in noise. We normalize each PUSH whose
immediate is a valid JUMPDEST into a symbolic label, leaving semantic immediates
(selectors, constants, string data) literal.

Two failure modes then remain that a single global `difflib` pass hits:
  - a length change inside one function desyncs the alignment of *every* later
    function, printing phantom regions in code that's actually byte-identical;
  - the "got" side of such a phantom region belongs to a shifted, unrelated part of
    the candidate, so its attribution is wrong too.
So by default we diff **each function independently**: partition both images into
per-function token streams (keyed by the owning function's 4-byte selector via the
context-sensitive CFG, so a target function pairs with its candidate counterpart
despite different body offsets), and run difflib per bucket. A length change is then
contained to its own function; every other function diffs cleanly. Shared helpers
and the dispatcher/prologue are their own buckets. Falls back to the global pass
when a CFG isn't available for both sides.
"""
from __future__ import annotations

import difflib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .analyze import SelectorEntry, walk_dispatcher
from .cfg import Attributor, Cfg
from .disasm import Op, disassemble, jumpdests
from .hints import hint_for
from .lift import Lifter


def normalize_tokens(code: bytes) -> Tuple[List[str], List[Op]]:
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
    hint: Optional[str] = None  # recognized-pattern fix suggestion, if any

    def render(self, ctx: int = 8) -> str:
        exp = self.expected[:ctx] + (["..."] if len(self.expected) > ctx else [])
        got = self.got[:ctx] + (["..."] if len(self.got) > ctx else [])
        head = "[%s @ 0x%x in %s]" % (self.tag, self.target_pc, self.function)
        parts = [head,
                 "    expected: %s" % (" ; ".join(exp) or "(none)"),
                 "    got:      %s" % (" ; ".join(got) or "(none)")]
        if self.hint:
            parts.append("    hint: %s" % self.hint)
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


def _region_pc(t_ops: List[Op], t_idx: List[int], i1: int, i2: int) -> int:
    """Target pc to anchor a region: its first target op, or (for a pure insertion)
    the op just before the insertion point, or the bucket's first op."""
    if i2 > i1:
        return t_ops[t_idx[i1]].pc
    if i1 > 0:
        return t_ops[t_idx[i1 - 1]].pc
    return t_ops[t_idx[0]].pc if t_idx else 0


def _regions_for_bucket(
    t_tokens: List[str], t_idx: List[int], t_ops: List[Op],
    c_tokens: List[str], c_idx: List[int], c_ops: List[Op],
    label_at: Callable[[int], str],
    t_lifter: Optional[Lifter], c_lifter: Optional[Lifter],
) -> List[RegionDiff]:
    """difflib over one bucket's (target, candidate) token subsequences.

    `t_idx`/`c_idx` map bucket-local token positions back to original op indices, so
    regions carry real pcs and lift back to real blocks. `label_at(pc)` names the
    region (a fixed function name per bucket, or the per-pc attribution in the global
    fallback)."""
    sm = difflib.SequenceMatcher(a=t_tokens, b=c_tokens, autojunk=False)
    regions: List[RegionDiff] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        pc = _region_pc(t_ops, t_idx, i1, i2)
        exp_ir = (t_lifter.lift_range(t_ops[t_idx[i1]].pc, t_ops[t_idx[i2 - 1]].pc)
                  if t_lifter is not None and i2 > i1 else [])
        got_ir = (c_lifter.lift_range(c_ops[c_idx[j1]].pc, c_ops[c_idx[j2 - 1]].pc)
                  if c_lifter is not None and j2 > j1 else [])
        exp_tok, got_tok = t_tokens[i1:i2], c_tokens[j1:j2]
        regions.append(RegionDiff(
            tag=tag, target_pc=pc, function=label_at(pc),
            expected=exp_tok, got=got_tok,
            expected_ir=exp_ir, got_ir=got_ir,
            hint=hint_for(exp_tok, got_tok),
        ))
    return regions


def _bucket(keys: List[str]) -> "OrderedDict[str, List[int]]":
    """key -> list of token indices, preserving first-seen key order."""
    out: "OrderedDict[str, List[int]]" = OrderedDict()
    for i, k in enumerate(keys):
        out.setdefault(k, []).append(i)
    return out


def _display_name(key: str, target_selectors: List[SelectorEntry]) -> str:
    if key == Attributor.SHARED:
        return "shared helper"
    if key == Attributor.PROLOGUE:
        return "dispatcher/prologue"
    if key.startswith("0x"):
        sel = key[2:]
        for s in target_selectors:
            if s.selector == sel:
                return s.signature or "selector 0x%s" % sel
        return "selector 0x%s" % sel
    return key


def _diff_per_function(
    target_code: bytes, candidate_code: bytes, selectors: List[SelectorEntry],
    t_cfg: Cfg, c_cfg: Cfg, lift_ir: bool,
) -> NormDiff:
    t_tokens, t_ops = normalize_tokens(target_code)
    c_tokens, c_ops = normalize_tokens(candidate_code)

    t_attr = Attributor(t_cfg, selectors)
    # The candidate's function bodies sit at shifted offsets; recover its own dispatcher
    # entries (pure, no network/evmole) so its blocks key on the same selectors.
    c_selectors = walk_dispatcher(c_ops)
    c_attr = Attributor(c_cfg, c_selectors)

    t_keys = [t_attr.key(op.pc) for op in t_ops]
    c_keys = [c_attr.key(op.pc) for op in c_ops]
    t_buckets = _bucket(t_keys)
    c_buckets = _bucket(c_keys)

    t_lifter = Lifter(t_ops, cfg=t_cfg) if lift_ir else None
    c_lifter = Lifter(c_ops, cfg=c_cfg) if lift_ir else None

    regions: List[RegionDiff] = []
    for key in list(t_buckets.keys()) + [k for k in c_buckets if k not in t_buckets]:
        t_ix = t_buckets.get(key, [])
        c_ix = c_buckets.get(key, [])
        t_sub = [t_tokens[i] for i in t_ix]
        c_sub = [c_tokens[i] for i in c_ix]
        if t_sub == c_sub:
            continue
        name = _display_name(key, selectors)
        regions.extend(_regions_for_bucket(
            t_sub, t_ix, t_ops, c_sub, c_ix, c_ops,
            label_at=lambda _pc, _n=name: _n,
            t_lifter=t_lifter, c_lifter=c_lifter,
        ))

    regions.sort(key=lambda r: r.target_pc)
    return NormDiff(
        match=not regions,
        length_delta=len(c_tokens) - len(t_tokens),
        region_count=len(regions),
        regions=regions,
    )


def _diff_global(
    target_code: bytes, candidate_code: bytes, selectors: List[SelectorEntry], lift_ir: bool,
) -> NormDiff:
    """Single global difflib pass with per-pc attribution — the fallback when a CFG
    isn't available for both sides (attribution/regions can cascade past a length
    change; that's the limitation per-function diffing removes)."""
    t_tokens, t_ops = normalize_tokens(target_code)
    c_tokens, c_ops = normalize_tokens(candidate_code)
    t_idx = list(range(len(t_ops)))
    c_idx = list(range(len(c_ops)))

    # Prime the attributor/lifters only if there is at least one divergence.
    sm = difflib.SequenceMatcher(a=t_tokens, b=c_tokens, autojunk=False)
    if all(tag == "equal" for tag, *_ in sm.get_opcodes()):
        return NormDiff(True, len(c_tokens) - len(t_tokens), 0, [])

    t_cfg = Cfg.from_code(target_code)
    attributor = Attributor(t_cfg, selectors)
    t_lifter: Optional[Lifter] = None
    c_lifter: Optional[Lifter] = None
    if lift_ir:
        t_lifter = Lifter(t_ops, cfg=t_cfg)
        c_lifter = Lifter(c_ops)
    regions = _regions_for_bucket(
        t_tokens, t_idx, t_ops, c_tokens, c_idx, c_ops,
        label_at=attributor.attribute, t_lifter=t_lifter, c_lifter=c_lifter,
    )
    return NormDiff(
        match=not regions,
        length_delta=len(c_tokens) - len(t_tokens),
        region_count=len(regions),
        regions=regions,
    )


def diff(target_code: bytes, candidate_code: bytes, selectors: Optional[List[SelectorEntry]] = None,
         lift_ir: bool = True, per_function: bool = True) -> NormDiff:
    """Normalized, function-attributed diff of two runtime images.

    Diffs each function independently when a CFG is available for both sides (the
    default — it contains a length change to its own function). Set
    `per_function=False`, or when either CFG is unavailable, to use the single global
    pass. `lift_ir=False` skips the per-region IR (cheaper; used for sweep ranking).
    """
    selectors = selectors or []
    if per_function and selectors:
        t_cfg = Cfg.from_code(target_code)
        c_cfg = Cfg.from_code(candidate_code)
        if t_cfg is not None and c_cfg is not None:
            return _diff_per_function(target_code, candidate_code, selectors, t_cfg, c_cfg, lift_ir)
    return _diff_global(target_code, candidate_code, selectors, lift_ir)
