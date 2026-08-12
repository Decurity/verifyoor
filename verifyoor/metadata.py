"""Parse the CBOR metadata solc appends to bytecode.

Layout: <code> <cbor-encoded map> <2-byte big-endian length of the cbor map>.
The map's schema is tiny and fixed: {ipfs|bzzr0|bzzr1: bytes, solc: 3 raw bytes
(or a text string for prerelease builds), experimental: bool}.

Factory contracts embed child creation bytecode, which carries its own metadata
block mid-code; find_embedded() locates those so compare.py can mask them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_HASH_KEYS = ("ipfs", "bzzr0", "bzzr1")


@dataclass
class Metadata:
    present: bool = False
    start: int = 0  # offset of the CBOR map within the code
    length: int = 0  # total bytes occupied incl. the 2-byte length suffix
    solc: Optional[str] = None
    hash_kind: Optional[str] = None
    hash: Optional[bytes] = None
    experimental: bool = False
    raw: bytes = b""
    keys: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "start": self.start,
            "length": self.length,
            "solc": self.solc,
            "hash_kind": self.hash_kind,
            "hash": self.hash.hex() if self.hash else None,
            "experimental": self.experimental,
        }


class _CborError(ValueError):
    pass


def _read_uint(buf: bytes, i: int, info: int) -> Tuple[int, int]:
    if info < 24:
        return info, i
    if info == 24:
        if i + 1 > len(buf):
            raise _CborError("truncated uint8")
        return buf[i], i + 1
    if info == 25:
        if i + 2 > len(buf):
            raise _CborError("truncated uint16")
        return int.from_bytes(buf[i : i + 2], "big"), i + 2
    raise _CborError("unsupported uint width %d" % info)


def _read_item(buf: bytes, i: int) -> Tuple[Any, int]:
    if i >= len(buf):
        raise _CborError("truncated")
    initial = buf[i]
    major, info = initial >> 5, initial & 0x1F
    i += 1
    if major == 0:  # unsigned int
        return _read_uint(buf, i, info)
    if major == 2:  # byte string
        n, i = _read_uint(buf, i, info)
        if i + n > len(buf):
            raise _CborError("truncated bytes")
        return buf[i : i + n], i + n
    if major == 3:  # text string
        n, i = _read_uint(buf, i, info)
        if i + n > len(buf):
            raise _CborError("truncated text")
        return buf[i : i + n].decode("utf-8", "strict"), i + n
    if major == 5:  # map
        n, i = _read_uint(buf, i, info)
        if n > 16:
            raise _CborError("implausible map size")
        out: Dict[Any, Any] = {}
        for _ in range(n):
            k, i = _read_item(buf, i)
            v, i = _read_item(buf, i)
            out[k] = v
        return out, i
    if major == 7:
        if info == 20:
            return False, i
        if info == 21:
            return True, i
        raise _CborError("unsupported simple value")
    raise _CborError("unsupported major type %d" % major)


def _decode_map(blob: bytes) -> Dict[str, Any]:
    """Decode blob as a full CBOR map (must consume every byte)."""
    value, end = _read_item(blob, 0)
    if end != len(blob) or not isinstance(value, dict):
        raise _CborError("not a clean cbor map")
    if not any(isinstance(k, str) for k in value):
        raise _CborError("no string keys")
    return value


def _metadata_from_map(m: Dict[str, Any], raw: bytes, start: int, length: int) -> Metadata:
    md = Metadata(present=True, start=start, length=length, raw=raw, keys=m)
    for k in _HASH_KEYS:
        if k in m and isinstance(m[k], bytes):
            md.hash_kind, md.hash = k, m[k]
            break
    solc = m.get("solc")
    if isinstance(solc, bytes) and len(solc) == 3:
        md.solc = "%d.%d.%d" % (solc[0], solc[1], solc[2])
    elif isinstance(solc, str):
        md.solc = solc  # prerelease builds embed a version string
    md.experimental = bool(m.get("experimental", False))
    return md


def parse_trailing(code: bytes) -> Metadata:
    """Parse the metadata block at the very end of the bytecode, if any."""
    if len(code) < 4:
        return Metadata()
    cbor_len = int.from_bytes(code[-2:], "big")
    total = cbor_len + 2
    if cbor_len < 4 or total > len(code):
        return Metadata()
    blob = code[-total:-2]
    try:
        m = _decode_map(blob)
    except (_CborError, UnicodeDecodeError):
        return Metadata()
    if not (set(m) & set(_HASH_KEYS)) and "solc" not in m:
        return Metadata()  # decodes as CBOR but isn't solc metadata
    return _metadata_from_map(m, blob, len(code) - total, total)


def strip_trailing(code: bytes) -> Tuple[bytes, Metadata]:
    md = parse_trailing(code)
    if md.present:
        return code[: md.start], md
    return code, md


# Map-header + first-key byte patterns that open every known solc metadata map.
_EMBED_MARKERS = [
    bytes([mh]) + key
    for mh in (0xA1, 0xA2, 0xA3)
    for key in (b"\x64ipfs", b"\x65bzzr0", b"\x65bzzr1")
]


def find_embedded(code: bytes) -> List[Tuple[int, int]]:
    """Find metadata blocks anywhere in the code (child contracts of factories).

    Returns [start, end) ranges covering each CBOR map plus its 2-byte length
    suffix, including the trailing block if present (callers can filter).
    """
    found: List[Tuple[int, int]] = []
    for marker in _EMBED_MARKERS:
        pos = code.find(marker)
        while pos != -1:
            try:
                value, end = _read_item(code, pos)
                if (
                    isinstance(value, dict)
                    and (set(value) & set(_HASH_KEYS))
                    and end + 2 <= len(code)
                    and int.from_bytes(code[end : end + 2], "big") == end - pos
                ):
                    found.append((pos, end + 2))
            except (_CborError, UnicodeDecodeError):
                pass
            pos = code.find(marker, pos + 1)
    return sorted(set(found))
