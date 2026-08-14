"""Expand a templated candidate into all source variants for a deterministic sweep.

Reconstruction often comes down to a few *equivalent-behavior, different-bytecode*
source dials — inline vs a factored `private` helper, assembly `sload(SLOT)` vs
`StorageSlot.getAddressSlot(SLOT).value`, masking vs not — that each nudge solc's
codegen. Rather than editing and re-verifying one at a time, mark the choices in the
source and let the toolkit compile the whole grid (variants × compiler settings).

Marker syntax: `<<< optionA ||| optionB ||| ... >>>`. Options may span multiple lines.
Markers don't nest. A template with K markers of sizes n1..nK expands to n1*…*nK
variants (the caller bounds this).
"""
from __future__ import annotations

import itertools
import re
from typing import Iterator, List, Tuple

_MARKER = re.compile(r"<<<(.*?)>>>", re.DOTALL)
_SEP = "|||"


def _axes(text: str) -> Tuple[List[str], List[List[str]]]:
    """(literal segments, per-marker option lists). Interleaved: seg0 axis0 seg1 axis1 … segN."""
    segs: List[str] = []
    axes: List[List[str]] = []
    pos = 0
    for m in _MARKER.finditer(text):
        segs.append(text[pos : m.start()])
        axes.append([o.strip() for o in m.group(1).split(_SEP)])
        pos = m.end()
    segs.append(text[pos:])
    return segs, axes


def count_variants(text: str) -> int:
    _, axes = _axes(text)
    n = 1
    for a in axes:
        n *= len(a)
    return n


def marker_count(text: str) -> int:
    return len(_MARKER.findall(text))


def expand(text: str) -> Iterator[Tuple[Tuple[int, ...], str]]:
    """Yield (choice-index-tuple, source) for every variant. One item (empty tuple,
    text) when the template has no markers."""
    segs, axes = _axes(text)
    if not axes:
        yield (), text
        return
    for combo in itertools.product(*[range(len(a)) for a in axes]):
        parts = [segs[0]]
        for i, choice in enumerate(combo):
            parts.append(axes[i][choice])
            parts.append(segs[i + 1])
        yield combo, "".join(parts)
