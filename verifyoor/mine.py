"""Mint a function name for an exact selector.

A function's name never appears in runtime bytecode — solc's dispatcher carries
only the 4-byte selector `keccak(name+types)[:4]`. So when the real name is
unrecoverable (a custom name, or a selector collision the signature DB resolves
wrongly), we don't need it: any name with the *correct arg types* that hashes to
the target selector compiles to byte-identical runtime code. Since a selector is
4 bytes, such a preimage always exists and is found by search.

Mining is pure hash throughput (keccak is a PRF — no shortcut under ~2^32 tries),
so it wants a fast keccak. Two backends, in order:

  1. **external** — Vectorized's `function-selector-miner` (MIT, Rust; AVX2 +
     multithread). Sub-minute on an x86 box with AVX2; on non-AVX2 hosts it falls
     back to a scalar path (~same as ours). Found via $VERIFYOOR_SELECTOR_MINER
     or `function-selector-miner` on PATH. Its naming scheme is `<name><decimal
     nonce>(<params>)` — identical to ours, so results are drop-in and we
     re-verify every one with our own keccak.
  2. **python** — pure-Python multiprocessing fallback (pycryptodome keccak).
     No build step; ~2.7M h/s aggregate. Correctness backstop and always present.

The minted name (`func_<selector>_<n>`) is cosmetic — only the selector lands in
bytecode — so either backend yields the same byte-exact result.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import re
import shutil
import subprocess
from typing import Optional

from .util import selector_of

_FOUND_RE = re.compile(r"Function found:\s*(\S.*?)\s+in\s")


def _canonical(argtypes: str) -> str:
    a = argtypes.strip()
    if not a.startswith("("):
        a = "(" + a + ")"
    return a


# ---------------------------------------------------------------- external backend
def find_external_miner() -> Optional[str]:
    """Path to Vectorized's function-selector-miner, or None."""
    env = os.environ.get("VERIFYOOR_SELECTOR_MINER")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    return shutil.which("function-selector-miner")


def _mine_external(binary: str, sel: str, argtypes: str, prefix: str,
                   threads: Optional[int]) -> str:
    cmd = [binary, prefix, argtypes, "0x" + sel]
    if threads:
        cmd.append(str(threads))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=None)
    m = _FOUND_RE.search(proc.stdout)
    if not m:
        raise RuntimeError(
            "selector miner produced no result (exit %d): %s"
            % (proc.returncode, (proc.stderr or proc.stdout)[-200:])
        )
    sig = m.group(1)  # e.g. "func_a9059cbb_12345(address[],uint256[])"
    if selector_of(sig) != sel:  # trust nothing — verify with our own keccak
        raise RuntimeError("miner returned %r whose selector != %s" % (sig, sel))
    return sig.split("(", 1)[0]


# ------------------------------------------------------------------ python backend
_STRIDE_CHECK = 1 << 16  # read the shared stop flag this rarely (keeps the loop hot)


def _scan(target: bytes, prefix: bytes, suffix: bytes, start: int, stride: int,
          found, result) -> None:
    from Crypto.Hash import keccak  # bound locally; avoids attribute lookups in-loop
    K = keccak.new
    i = start
    c = 0
    while True:
        if K(data=prefix + b"%d" % i + suffix, digest_bits=256).digest()[:4] == target:
            with found.get_lock():
                if not found.value:
                    found.value = 1
                    result.put(prefix.decode() + str(i))
            return
        c += 1
        if c >= _STRIDE_CHECK:
            c = 0
            if found.value:
                return
        i += stride


def _mine_python(sel: str, argtypes: str, prefix: str, workers: Optional[int]) -> str:
    target = bytes.fromhex(sel)
    suffix = argtypes.encode()
    prefix_b = prefix.encode()
    workers = workers or mp.cpu_count()
    found = mp.Value("b", 0)
    result: mp.Queue = mp.Queue()
    procs = [mp.Process(target=_scan, args=(target, prefix_b, suffix, i, workers, found, result),
                        daemon=True) for i in range(workers)]
    for p in procs:
        p.start()
    name = result.get()
    for p in procs:
        p.terminate()
    return name


# ------------------------------------------------------------------------- public
def mine(selector: str, argtypes: str, workers: Optional[int] = None,
         prefix: Optional[str] = None, backend: str = "auto") -> str:
    """Return a `<prefix><n>` name whose selector == `selector` (8 hex, no 0x).

    `prefix` defaults to `func_<selector>_` (self-documenting); override to pin the
    candidate family (tests use it to hit a known small `n`). `backend` is
    "auto" (external if available, else python), "external", or "python".
    """
    sel = selector.lower().removeprefix("0x")
    argtypes = _canonical(argtypes)
    prefix = prefix if prefix is not None else "func_%s_" % sel

    if backend in ("auto", "external"):
        binary = find_external_miner()
        if binary:
            return _mine_external(binary, sel, argtypes, prefix, workers)
        if backend == "external":
            raise RuntimeError(
                "no external selector miner found (set $VERIFYOOR_SELECTOR_MINER "
                "or put `function-selector-miner` on PATH)"
            )
    return _mine_python(sel, argtypes, prefix, workers)
