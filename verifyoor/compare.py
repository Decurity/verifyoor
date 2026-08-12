"""Masked byte-exact comparison between target runtime bytecode and a compiled candidate.

Match standard: every byte identical after
  1. stripping the trailing CBOR metadata from both sides,
  2. masking immutable value slots (the on-chain code carries real values where
     solc emits zeros — we recover and report them),
  3. masking unlinked library placeholders (__$...$__ in the solc output),
  4. masking embedded child-contract metadata blocks (factory contracts).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import metadata
from .compile import ContractOut

_LINK_PLACEHOLDER_RE = re.compile(r"__\$[0-9a-fA-F]{34}\$__|__[A-Za-z0-9_.:]{36}__")


@dataclass
class Comparison:
    match: bool
    reason: str
    input_len: int = 0
    compiled_len: int = 0
    input_stripped_len: int = 0
    compiled_stripped_len: int = 0
    first_diff: Optional[int] = None
    diff_bytes: int = 0
    masked_immutables: List[Dict[str, Any]] = field(default_factory=list)
    masked_links: List[Dict[str, Any]] = field(default_factory=list)
    masked_embedded_meta: List[Tuple[int, int]] = field(default_factory=list)
    # stripped-and-masked images, kept for downstream diffing
    input_image: bytes = b""
    compiled_image: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "match": self.match,
            "reason": self.reason,
            "input_len": self.input_len,
            "compiled_len": self.compiled_len,
            "input_stripped_len": self.input_stripped_len,
            "compiled_stripped_len": self.compiled_stripped_len,
            "first_diff": self.first_diff,
            "diff_bytes": self.diff_bytes,
            "masked_immutables": self.masked_immutables,
            "masked_links": self.masked_links,
            "masked_embedded_meta": list(self.masked_embedded_meta),
        }


def _resolve_link_placeholders(obj: str) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Replace __$...$__ spans with zero bytes; return code + placeholder byte ranges."""
    links: List[Dict[str, Any]] = []
    out = obj
    for m in _LINK_PLACEHOLDER_RE.finditer(obj):
        start_c, end_c = m.span()
        links.append({"offset": start_c // 2, "length": (end_c - start_c) // 2, "placeholder": m.group(0)})
    if links:
        out = _LINK_PLACEHOLDER_RE.sub(lambda m: "00" * (len(m.group(0)) // 2), obj)
    return bytes.fromhex(out), links


def _mask(buf: bytearray, start: int, length: int) -> None:
    buf[start : start + length] = b"\x00" * length


def compare(input_code: bytes, contract: ContractOut) -> Comparison:
    compiled_code, link_spans = _resolve_link_placeholders(contract.deployed_object)

    input_stripped, in_md = metadata.strip_trailing(input_code)
    compiled_stripped, _ = metadata.strip_trailing(compiled_code)

    cmp = Comparison(
        match=False,
        reason="",
        input_len=len(input_code),
        compiled_len=len(compiled_code),
        input_stripped_len=len(input_stripped),
        compiled_stripped_len=len(compiled_stripped),
    )

    if len(input_stripped) != len(compiled_stripped):
        cmp.reason = "length mismatch after metadata strip (input %d vs compiled %d)" % (
            len(input_stripped),
            len(compiled_stripped),
        )
        cmp.input_image = input_stripped
        cmp.compiled_image = compiled_stripped
        return cmp

    a = bytearray(input_stripped)  # target (on-chain)
    b = bytearray(compiled_stripped)  # candidate

    # Immutable slots: recover on-chain values, then zero both sides.
    for ast_id, refs in (contract.immutable_refs or {}).items():
        for ref in refs:
            start, length = ref["start"], ref["length"]
            if start + length > len(a):
                continue
            cmp.masked_immutables.append(
                {"ast_id": ast_id, "offset": start, "length": length, "value": bytes(a[start : start + length]).hex()}
            )
            _mask(a, start, length)
            _mask(b, start, length)

    # Unlinked library placeholders: recover the on-chain library address.
    for span in link_spans:
        start, length = span["offset"], span["length"]
        if start + length > len(a):
            continue
        cmp.masked_links.append(dict(span, value=bytes(a[start : start + length]).hex()))
        _mask(a, start, length)
        _mask(b, start, length)

    # Embedded child metadata (factory contracts): mask the union of both sides'
    # detected blocks — hashes differ there by construction, like the trailing one.
    embedded = set(metadata.find_embedded(bytes(a))) | set(metadata.find_embedded(bytes(b)))
    for start, end in sorted(embedded):
        cmp.masked_embedded_meta.append((start, end))
        _mask(a, start, end - start)
        _mask(b, start, end - start)

    cmp.input_image = bytes(a)
    cmp.compiled_image = bytes(b)

    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    if not diffs:
        cmp.match = True
        cmp.reason = "exact match (metadata-stripped%s)" % (
            ", %d region(s) masked" % (len(cmp.masked_immutables) + len(cmp.masked_links) + len(cmp.masked_embedded_meta))
            if (cmp.masked_immutables or cmp.masked_links or cmp.masked_embedded_meta)
            else ""
        )
        return cmp

    cmp.first_diff = diffs[0]
    cmp.diff_bytes = len(diffs)
    cmp.reason = "code mismatch: %d differing byte(s), first at offset 0x%x" % (len(diffs), diffs[0])
    return cmp
