"""Identify a known open-source library (OpenZeppelin, Solady, ...) embedded in
target bytecode, and pin the compiler settings that reproduce it, by sweeping
library version x compiler settings and scoring **basic-block fingerprints**
against the target — rather than testing candidates one at a time.

Why block-level, not function-level: a library function compiled in isolation
(a small probe contract) gets a different internal-function call graph than the
same function embedded in a large multi-function contract — solc's optimizer
inlines/orders/shares differently depending on the whole program. So a selector-
to-selector body comparison between an isolated probe and the real target is
unreliable (confirmed empirically: exact function-body matches came back 0/5 for
a case block-fingerprinting resolved to 25/30). A basic block's *content* doesn't
depend on its caller, only its jump target does — and that's already abstracted
by normdiff's PUSHDEST normalization — so blocks are the right unit: library
blocks appear verbatim in the target regardless of surrounding call-graph shape.

The sweep is a natural extension of `sweep` (template variants x settings): here
the "variant" axis is library version instead of marked source choices, and the
scoring is block-overlap fraction instead of exact match / region count.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from .compile import Settings, ensure_solc
from .disasm import disassemble
from .lift import split_blocks
from .normdiff import normalize_tokens

_CACHE_DIR = os.path.expanduser("~/.cache/verifyoor/libs")
Fetcher = Callable[[str, str], Optional[str]]  # (version, path-within-package) -> source or None

_MIN_BLOCK_LEN = 3  # skip trivial 1-2 opcode blocks; too common to be a useful fingerprint


# --------------------------------------------------------------------------- fetching
def npm_fetcher(package: str, registry: str = "https://cdn.jsdelivr.net/npm") -> Fetcher:
    """A Fetcher backed by the jsdelivr npm CDN, with on-disk caching under
    ~/.cache/verifyoor/libs — so repeated sweeps (iterating settings, retrying) are
    instant and offline-capable after the first fetch."""

    def fetch(version: str, path: str) -> Optional[str]:
        cache_path = os.path.join(_CACHE_DIR, "npm", package.replace("/", "_"), version, path)
        if os.path.isfile(cache_path):
            with open(cache_path) as f:
                return f.read()
        url = "%s/%s@%s/%s" % (registry, package, version, path)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "verifyoor"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                text = resp.read().decode()
        except Exception:
            return None
        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "w") as f:
                f.write(text)
        except OSError:
            pass
        return text

    return fetch


def npm_versions(package: str, max_versions: int = 30) -> List[str]:
    """Published versions from the npm registry, newest-first (cached on disk)."""
    cache_path = os.path.join(_CACHE_DIR, "npm-versions", package.replace("/", "_") + ".json")
    versions: Optional[List[str]] = None
    if os.path.isfile(cache_path):
        try:
            with open(cache_path) as f:
                versions = json.load(f)
        except (OSError, json.JSONDecodeError):
            versions = None
    if versions is None:
        try:
            req = urllib.request.Request(
                "https://registry.npmjs.org/%s" % package, headers={"User-Agent": "verifyoor"}
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.load(resp)
            versions = list(data.get("versions", {}).keys())
        except Exception:
            versions = []
        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "w") as f:
                json.dump(versions, f)
        except OSError:
            pass

    def key(v: str) -> tuple:
        core = re.split(r"[-+]", v, 1)[0]
        try:
            return tuple(int(x) for x in core.split("."))
        except ValueError:
            return (-1,)

    return sorted(versions, key=key, reverse=True)[:max_versions]


# --------------------------------------------------------------------- import resolution
_IMPORT_RE = re.compile(r'import\s+(?:[^;]*?from\s+)?["\']([^"\']+)["\']')


def _normalize_path(base: str, ref: str) -> str:
    parts = (base.split("/")[:-1] if base else []) + ref.split("/")
    out: List[str] = []
    for p in parts:
        if p in ("", "."):
            continue
        if p == "..":
            if out:
                out.pop()
            continue
        out.append(p)
    return "/".join(out)


def resolve_package_files(fetch: Fetcher, version: str, root_path: str,
                          package_prefix: str) -> Optional[Dict[str, str]]:
    """Transitively resolve a package-internal root file's imports.

    `package_prefix` (e.g. `@openzeppelin/contracts/`) marks absolute imports that
    belong to this package — those resolve via `fetch` at (version, path-after-prefix).
    Relative imports (`./`, `../`) resolve against the importing file's own directory.
    Returns {path-within-package: source}, or None if any file fails to fetch.
    """
    files: Dict[str, str] = {}
    stack = [root_path]
    while stack:
        path = stack.pop()
        if path in files:
            continue
        src = fetch(version, path)
        if src is None:
            return None
        files[path] = src
        for ref in _IMPORT_RE.findall(src):
            if ref.startswith(package_prefix):
                stack.append(ref[len(package_prefix) :])
            elif ref.startswith("./") or ref.startswith("../"):
                stack.append(_normalize_path(path, ref))
            # else: a bare package-root import (no leading dot) names a *different*
            # npm package — out of scope for a single-package probe, left unresolved
    return files


# ------------------------------------------------------------------------- fingerprinting
def block_fingerprint(code: bytes) -> Set[Tuple[str, ...]]:
    """Normalized-token basic blocks of length >= _MIN_BLOCK_LEN, as a set.

    Jump targets are PUSHDEST-abstracted (via normdiff.normalize_tokens), so a
    block's fingerprint is independent of where it sits in the final program —
    only its own opcode/immediate content matters."""
    tokens, ops = normalize_tokens(code)
    pc_to_idx = {op.pc: i for i, op in enumerate(ops)}
    out: Set[Tuple[str, ...]] = set()
    for block in split_blocks(ops):
        i0 = pc_to_idx.get(block[0].pc)
        i1 = pc_to_idx.get(block[-1].pc)
        if i0 is None or i1 is None:
            continue
        seg = tuple(tokens[i0 : i1 + 1])
        if len(seg) >= _MIN_BLOCK_LEN:
            out.add(seg)
    return out


def block_bytes(blocks: Set[Tuple[str, ...]]) -> int:
    """Rough byte-size estimate of a block set, for a 'chunk recovered' figure.
    Approximates each token at 1-33 bytes (opcode + immediate width from its
    literal, PUSHDEST counted as a 2-byte PUSH)."""
    total = 0
    for block in blocks:
        for tok in block:
            if " 0x" in tok:
                total += 1 + (len(tok.split("0x", 1)[1]) + 1) // 2
            elif tok == "PUSHDEST":
                total += 2
            else:
                total += 1
    return total


# ------------------------------------------------------------------------------ sweep
@dataclass
class LibResult:
    version: str
    settings: Settings
    hit: int
    total: int
    matched_bytes: int
    probe_code: bytes = field(repr=False)

    @property
    def fraction(self) -> float:
        return self.hit / self.total if self.total else 0.0


def compile_probe(solc: str, files: Dict[str, str], probe_source: str,
                  probe_name: str, st: Settings) -> Optional[bytes]:
    sources = {p: {"content": c} for p, c in files.items()}
    sources["Probe.sol"] = {"content": probe_source}
    settings: Dict = {
        "optimizer": {"enabled": st.optimizer_enabled, "runs": st.optimizer_runs},
        "outputSelection": {"*": {"*": ["evm.deployedBytecode.object"]}},
    }
    if st.evm_version:
        settings["evmVersion"] = st.evm_version
    inp = {"language": "Solidity", "sources": sources, "settings": settings}
    try:
        res = subprocess.run([solc, "--standard-json"], input=json.dumps(inp),
                             capture_output=True, text=True, timeout=60)
        out = json.loads(res.stdout)
    except Exception:
        return None
    for contracts in out.get("contracts", {}).values():
        co = contracts.get(probe_name)
        if co:
            obj = co.get("evm", {}).get("deployedBytecode", {}).get("object")
            return bytes.fromhex(obj) if obj else None
    return None


def sweep_versions(
    target_code: bytes,
    probe_template: str,
    probe_name: str,
    package: str,
    root_path: str,
    solc_version: str,
    versions: List[str],
    settings_list: List[Settings],
    fetch: Optional[Fetcher] = None,
) -> List[LibResult]:
    """Compile `probe_template` (importing `package/root_path`) at every
    (version, settings) combination and score its block fingerprint against the
    target's. Deduplicates versions whose resolved source is byte-identical to an
    already-tried version (common — a library file often doesn't change across
    several releases), so those don't get redundantly recompiled.

    `probe_template` must import strictly from `package` (transitively); mixing in
    a second external package is out of scope for one sweep."""
    fetch = fetch or npm_fetcher(package)
    prefix = package + "/"
    solc = ensure_solc(solc_version)
    target_blocks = block_fingerprint(target_code)

    results: List[LibResult] = []
    seen_source_hashes: Dict[str, str] = {}  # source-hash -> version already compiled
    for version in versions:
        files = resolve_package_files(fetch, version, root_path, prefix)
        if files is None:
            continue
        source_hash = hashlib.sha256(
            "".join(files[p] for p in sorted(files)).encode()
        ).hexdigest()
        if source_hash in seen_source_hashes:
            continue  # identical source to an already-swept version
        seen_source_hashes[source_hash] = version
        files_full = {prefix + p: c for p, c in files.items()}
        for st in settings_list:
            probe_code = compile_probe(solc, files_full, probe_template, probe_name, st)
            if probe_code is None:
                continue
            probe_blocks = block_fingerprint(probe_code)
            hit = len(probe_blocks & target_blocks)
            results.append(LibResult(
                version=version, settings=st, hit=hit, total=len(probe_blocks),
                matched_bytes=block_bytes(probe_blocks & target_blocks), probe_code=probe_code,
            ))
    results.sort(key=lambda r: (-r.hit, -r.fraction))
    return results
