"""Shared helpers: hex I/O, keccak-256, subprocess wrapper."""
from __future__ import annotations

import os
import re
import subprocess
from typing import List, Optional

_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]*$")


def load_bytecode(path_or_hex: str) -> bytes:
    """Accept a file path containing hex, or a raw hex string (0x-prefixed or not)."""
    text = path_or_hex
    if os.path.exists(path_or_hex):
        with open(path_or_hex) as f:
            text = f.read()
    text = "".join(text.split())
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if not text or not _HEX_RE.match(text) or len(text) % 2 != 0:
        raise ValueError("input is not valid hex bytecode (or file not found): %r" % path_or_hex[:64])
    return bytes.fromhex(text)


def keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak  # pycryptodome

        return keccak.new(data=data, digest_bits=256).digest()
    except ImportError:
        pass
    try:
        import sha3  # pysha3

        return sha3.keccak_256(data).digest()
    except ImportError:
        pass
    from eth_hash.auto import keccak as _keccak

    return _keccak(data)


def selector_of(signature: str) -> str:
    """4-byte selector hex (no 0x) for a canonical function signature."""
    return keccak256(signature.encode()).hex()[:8]


def run(cmd: List[str], input_text: Optional[str] = None, timeout: int = 300) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
