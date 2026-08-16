"""Drive a pinned solc binary via --standard-json and enumerate candidate settings."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

from .util import run

# EVM targets in chronological order, with the first solc version supporting each.
_EVM_ORDER = [
    "homestead", "tangerineWhistle", "spuriousDragon", "byzantium",
    "constantinople", "petersburg", "istanbul", "berlin", "london",
    "paris", "shanghai", "cancun", "prague", "osaka",
]
_EVM_MIN_SOLC = {
    "constantinople": (0, 5, 5), "petersburg": (0, 5, 5), "istanbul": (0, 5, 14),
    "berlin": (0, 8, 5), "london": (0, 8, 7), "paris": (0, 8, 18),
    "shanghai": (0, 8, 20), "cancun": (0, 8, 24), "prague": (0, 8, 27),
    "osaka": (0, 8, 29),
}

OPTIMIZER_RUNS_SWEEP = [200, 1000, 999999, 1, 100, 10000, 300, 500]


def _ver_tuple(version: str) -> tuple:
    return tuple(int(x) for x in version.split("-")[0].split("+")[0].split("."))


def solc_path(version: str) -> Optional[str]:
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".svm", version, "solc-%s" % version),
        os.path.join(home, ".solc-select", "artifacts", "solc-%s" % version, "solc-%s" % version),
        os.path.join(home, ".solc-select", "artifacts", "solc-%s" % version),
    ]
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def ensure_solc(version: str) -> str:
    p = solc_path(version)
    if p:
        return p
    # Fall back to solc-select's installer (downloads the official binary).
    res = run(["solc-select", "install", version], timeout=600)
    p = solc_path(version)
    if p:
        return p
    raise RuntimeError(
        "solc %s not found and auto-install failed: %s" % (version, (res.stderr or res.stdout).strip()[:300])
    )


@dataclass(frozen=True)
class Settings:
    optimizer_enabled: bool = False
    optimizer_runs: int = 200
    evm_version: Optional[str] = None  # None = compiler default
    via_ir: bool = False

    def to_solc(self, version: str) -> Dict[str, Any]:
        s: Dict[str, Any] = {
            "optimizer": {"enabled": self.optimizer_enabled, "runs": self.optimizer_runs},
            "outputSelection": {
                "*": {
                    "*": [
                        "abi",
                        "evm.bytecode.object",
                        "evm.deployedBytecode.object",
                        "evm.deployedBytecode.immutableReferences",
                        "evm.deployedBytecode.linkReferences",
                    ]
                }
            },
        }
        if self.evm_version:
            s["evmVersion"] = self.evm_version
        if self.via_ir and _ver_tuple(version) >= (0, 8, 13):
            s["viaIR"] = True
        return s

    def describe(self) -> str:
        opt = "runs=%d" % self.optimizer_runs if self.optimizer_enabled else "off"
        return "optimizer=%s evm=%s viaIR=%s" % (opt, self.evm_version or "default", self.via_ir)


@dataclass
class ContractOut:
    name: str
    deployed_object: str  # runtime hex, may contain __$...$__ link placeholders
    creation_object: str = ""  # full creation (init ++ runtime) hex, for --creation checks
    immutable_refs: Dict[str, List[Dict[str, int]]] = field(default_factory=dict)
    link_refs: Dict[str, Any] = field(default_factory=dict)
    abi: Any = None

    @property
    def deployed_len(self) -> int:
        return len(self.deployed_object) // 2


@dataclass
class CompileResult:
    ok: bool
    contracts: List[ContractOut] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def pick(self, contract_name: Optional[str] = None, target_len: Optional[int] = None) -> Optional[ContractOut]:
        pool = [c for c in self.contracts if c.deployed_object]
        if contract_name:
            pool = [c for c in pool if c.name == contract_name]
        if not pool:
            return None
        if target_len is not None:
            return min(pool, key=lambda c: abs(c.deployed_len - target_len))
        return max(pool, key=lambda c: c.deployed_len)


def compile_standard(source: str, version: str, settings: Settings, source_name: str = "contract.sol") -> CompileResult:
    solc = ensure_solc(version)
    std_input = {
        "language": "Solidity",
        "sources": {source_name: {"content": source}},
        "settings": settings.to_solc(version),
    }
    res = run([solc, "--standard-json"], input_text=json.dumps(std_input), timeout=300)
    if res.returncode != 0 and not res.stdout.strip():
        return CompileResult(ok=False, errors=["solc crashed: %s" % res.stderr.strip()[:500]])
    try:
        out = json.loads(res.stdout)
    except json.JSONDecodeError:
        return CompileResult(ok=False, errors=["unparseable solc output: %s" % res.stdout[:500]])

    errors = [
        e.get("formattedMessage") or e.get("message", "")
        for e in out.get("errors", [])
        if e.get("severity") == "error"
    ]
    contracts: List[ContractOut] = []
    for _file, by_name in out.get("contracts", {}).items():
        for name, art in by_name.items():
            evm = art.get("evm", {}) or {}
            dep = evm.get("deployedBytecode", {}) or {}
            creation = evm.get("bytecode", {}) or {}
            contracts.append(
                ContractOut(
                    name=name,
                    deployed_object=dep.get("object", "") or "",
                    creation_object=creation.get("object", "") or "",
                    immutable_refs=dep.get("immutableReferences", {}) or {},
                    link_refs=dep.get("linkReferences", {}) or {},
                    abi=art.get("abi"),
                )
            )
    return CompileResult(ok=not errors, contracts=contracts, errors=errors)


def evm_candidates(version: str, floor: Optional[str] = None) -> List[Optional[str]]:
    """Candidate evmVersion values for this solc version, compiler default first."""
    vt = _ver_tuple(version)
    names = [n for n in _EVM_ORDER if _EVM_MIN_SOLC.get(n, (0, 0, 0)) <= vt]
    if floor and floor in _EVM_ORDER:
        names = [n for n in names if _EVM_ORDER.index(n) >= _EVM_ORDER.index(floor)]
    # Newest targets first: deployments overwhelmingly use the compiler default,
    # which for a given solc release is near the top of its supported range.
    names.reverse()
    return [None] + names  # type: ignore[list-item]


def settings_sweep(
    version: str,
    evm_floor: Optional[str] = None,
    optimizer_first: str = "off",
    runs_sweep: Optional[List[int]] = None,
    via_ir_first: bool = False,
) -> Iterator[Settings]:
    """Yield candidate settings in priority order. Caller short-circuits on match.

    via_ir_first=True (from the analyze heuristic) tries viaIR builds before legacy,
    saving the whole legacy sweep when the bytecode is clearly viaIR.
    """
    runs_list = runs_sweep or OPTIMIZER_RUNS_SWEEP
    opt_variants: List[tuple] = [(False, 200)] + [(True, r) for r in runs_list]
    if optimizer_first == "on":
        opt_variants = [(True, r) for r in runs_list] + [(False, 200)]
    evms = evm_candidates(version, evm_floor)
    via_order = (True, False) if via_ir_first else (False, True)
    for via_ir in via_order:
        for enabled, runs in opt_variants:
            for evm in evms:
                yield Settings(
                    optimizer_enabled=enabled,
                    optimizer_runs=runs,
                    evm_version=evm,
                    via_ir=via_ir,
                )
