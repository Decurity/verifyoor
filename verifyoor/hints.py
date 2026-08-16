"""Recognize a few source->bytecode codegen patterns in a diff region and name the
source-level fix.

These are the mappings that cost the most iterations by hand: the diff shows the
symptom (a `SHL` vs a mask, a bare `ADD` vs a helper JUMP) but not the cause. Each
rule matches an unambiguous token signature on a region's `expected`/`got` streams
and returns a one-line fix. High precision over recall: a wrong hint misleads more
than a missing one, so a rule stays silent unless its signature is unmistakable, and
`hint_for` returns the first match (rules are ordered most-specific first).
"""
from __future__ import annotations

from typing import Callable, List, Optional


def _contig(tokens: List[str], sub: List[str]) -> bool:
    """Is `sub` a contiguous run within `tokens`?"""
    n = len(sub)
    return n > 0 and any(tokens[i:i + n] == sub for i in range(len(tokens) - n + 1))


def _hexpart(tok: str) -> Optional[str]:
    return tok.split(" 0x", 1)[1] if " 0x" in tok else None


def _is_selector_clean_mask(tok: str) -> bool:
    """PUSH28 0xffff…ff — the 28-byte mask that clears a bytes4 selector's low bytes."""
    hx = _hexpart(tok)
    return bool(hx) and len(hx) == 56 and set(hx) == {"f"}


def _selector_helper_shift(tokens: List[str]) -> bool:
    """`shl(0xe0, sel)` — the selector positioned inside the ABI encoder."""
    return _contig(tokens, ["PUSH1 0xe0", "SHL"])


def _selector_cast_clean(tokens: List[str]) -> bool:
    """`and(shl(0xe0, sel), not(mask28))` — a pre-shifted bytes4 cast being cleaned."""
    return any(_is_selector_clean_mask(t) for t in tokens) and "NOT" in tokens and "AND" in tokens


def _checked_add_helper(tokens: List[str]) -> bool:
    """An internal call (`… JUMP` past a PUSHDEST return tag) with no inline ADD —
    the shape of solc's overflow-checked `+`/`++` helper invocation."""
    return "JUMP" in tokens and "PUSHDEST" in tokens and "ADD" not in tokens


def _plain_increment(tokens: List[str]) -> bool:
    """`PUSH1 0x01 ADD` — an unchecked +1."""
    return _contig(tokens, ["PUSH1 0x01", "ADD"])


def _error_string_marker(tokens: List[str]) -> bool:
    """The `Error(string)` selector 0x08c379a0, padded (unopt) or shift-built (opt)."""
    return (any(t.startswith("PUSH32 0x08c379a0") for t in tokens)
            or _contig(tokens, ["PUSH3 0x461bcd", "PUSH1 0xe5", "SHL"]))


def _lone_custom_error_selector(tokens: List[str]) -> bool:
    """A single PUSH4 that isn't Error(string)/Panic — a `revert CustomError()` head."""
    push4s = [t for t in tokens if t.startswith("PUSH4 0x")]
    return len(push4s) == 1 and push4s[0] not in ("PUSH4 0x08c379a0", "PUSH4 0x4e487b71")


def _rule_selector_encoding(exp: List[str], got: List[str]) -> Optional[str]:
    if _selector_helper_shift(exp) and _selector_cast_clean(got):
        return ("selector encoding: the target passes the selector as a raw integer "
                "literal (the ABI encoder does `shl(0xe0, sel)`); your build pre-shifts "
                "and cleans a `bytes4(0x…)` cast. Use the raw literal — "
                "`abi.encodeWithSelector(0x12345678, …)` — not `bytes4(0x…)`/`X.f.selector`.")
    if _selector_cast_clean(exp) and _selector_helper_shift(got):
        return ("selector encoding: the target cleans a `bytes4` selector "
                "(`and(sel, ~mask)`); your build routes a raw literal through the "
                "encoder. Use a bytes4 cast — `abi.encodeWithSelector(bytes4(0x…), …)` "
                "or `IERC20.f.selector`.")
    return None


def _rule_unchecked_increment(exp: List[str], got: List[str]) -> Optional[str]:
    if _plain_increment(exp) and _checked_add_helper(got):
        return ("increment is unchecked on-chain (plain `ADD`) but checked in your "
                "build (calls the overflow helper) — wrap the `x++` / `x += 1` in an "
                "`unchecked { }` block.")
    if _plain_increment(got) and _checked_add_helper(exp):
        return ("increment is checked on-chain (overflow helper) but you used "
                "`unchecked` (plain `ADD`) — remove the `unchecked { }` around it.")
    return None


def _rule_custom_error_vs_require(exp: List[str], got: List[str]) -> Optional[str]:
    if _lone_custom_error_selector(exp) and _error_string_marker(got):
        return ("the target reverts with a custom error (`revert CustomError(…)`), "
                "your build uses `require(_, \"…\")` / `Error(string)` — switch to the "
                "custom error.")
    if _error_string_marker(exp) and _lone_custom_error_selector(got):
        return ("the target uses `require(_, \"…\")` / `Error(string)`, your build "
                "reverts with a custom error — switch to `require`/`revert(\"…\")`.")
    return None


# Ordered most-specific first; hint_for returns the first match.
_RULES: List[Callable[[List[str], List[str]], Optional[str]]] = [
    _rule_selector_encoding,
    _rule_unchecked_increment,
    _rule_custom_error_vs_require,
]


def hint_for(expected: List[str], got: List[str]) -> Optional[str]:
    """A source-level fix suggestion for a region's (expected, got) tokens, or None."""
    for rule in _RULES:
        h = rule(expected, got)
        if h:
            return h
    return None
