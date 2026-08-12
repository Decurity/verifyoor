"""Wrap `heimdall decompile` to produce an approximate Solidity scaffold + ABI."""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from typing import Any, List, Optional

from .util import run


@dataclass
class Decompilation:
    ok: bool
    solidity: Optional[str] = None
    abi: Optional[Any] = None
    outdir: Optional[str] = None
    error: Optional[str] = None
    resolved_signatures: List[str] = field(default_factory=list)


def _extract_signatures(abi: Any) -> List[str]:
    sigs: List[str] = []
    if not isinstance(abi, list):
        return sigs
    for item in abi:
        t = item.get("type")
        name = item.get("name")
        if t in ("function", "event", "error") and name:
            args = ",".join(i.get("type", "") for i in item.get("inputs", []))
            sigs.append("%s %s(%s)" % (t, name, args))
    return sigs


def decompile(code_hex: str, outdir: str, timeout: int = 120, skip_resolving: bool = False) -> Decompilation:
    if shutil.which("heimdall") is None:
        return Decompilation(ok=False, error="heimdall not found on PATH")
    os.makedirs(outdir, exist_ok=True)
    cmd = ["heimdall", "decompile", code_hex, "--include-sol", "-o", outdir, "-d"]
    if skip_resolving:
        cmd.append("--skip-resolving")
    res = run(cmd, timeout=timeout)

    sol_path = os.path.join(outdir, "decompiled.sol")
    abi_path = os.path.join(outdir, "abi.json")
    solidity = None
    abi = None
    if os.path.isfile(sol_path):
        with open(sol_path) as f:
            solidity = f.read()
    if os.path.isfile(abi_path):
        try:
            with open(abi_path) as f:
                abi = json.load(f)
        except (OSError, json.JSONDecodeError):
            abi = None

    if solidity is None and abi is None:
        return Decompilation(ok=False, outdir=outdir, error=(res.stderr or res.stdout).strip()[:500])
    return Decompilation(
        ok=True,
        solidity=solidity,
        abi=abi,
        outdir=outdir,
        resolved_signatures=_extract_signatures(abi),
    )
