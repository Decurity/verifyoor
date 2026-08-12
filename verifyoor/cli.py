"""verifyoor CLI: analyze | decompile | verify.

The deterministic toolkit Claude Code drives while reconstructing source. JSON on
stdout for machine consumption; a human-readable summary on stderr. `verify` exits
0 on a byte-exact (metadata-stripped) match, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import metadata
from .analyze import analyze
from .compare import Comparison, compare
from .compile import CompileResult, Settings, compile_standard, settings_sweep
from .decompile import decompile
from .fetch import fetch_code
from .normdiff import diff
from .report import build_report, write_artifacts
from .resolve import resolve_selectors, resolve_topics
from .util import load_bytecode


def _eprint(*a):
    print(*a, file=sys.stderr)


def _resolve_source(tokens: List[str], rpc_url: Optional[str], no_cache: bool):
    """Resolve a bytecode source to (code_bytes, label).

    Two tokens  -> <network> <address>: fetch runtime code via eth_getCode.
    One token   -> a hex file path or a raw hex string: load locally.
    """
    if len(tokens) == 2:
        network, address = tokens
        code = fetch_code(network, address, rpc_url=rpc_url, use_cache=not no_cache)
        _eprint("fetched %d bytes of runtime code from %s at %s" % (len(code), network, address))
        return code, "%s:%s" % (network, address)
    if len(tokens) == 1:
        return load_bytecode(tokens[0]), tokens[0]
    raise SystemExit("provide '<network> <address>' or a single hex file / hex string")


def _resolve_analysis(a, use_network: bool):
    sels = [s.selector for s in a.selectors]
    resolved = resolve_selectors(sels, use_network=use_network) if sels else {}
    for s in a.selectors:
        s.signature = resolved.get(s.selector)
    topics = resolve_topics(a.push32_hashes, use_network=use_network) if a.push32_hashes else {}
    errors = resolve_selectors(a.error_selectors, use_network=use_network) if a.error_selectors else {}
    return resolved, topics, errors


def cmd_analyze(args) -> int:
    code, _label = _resolve_source(args.target, args.rpc_url, args.no_cache)
    a = analyze(code)
    resolved, topics, errors = _resolve_analysis(a, use_network=not args.offline)
    out = a.to_dict()
    out["resolved_events"] = {k: v for k, v in topics.items() if v}
    out["resolved_errors"] = {k: v for k, v in errors.items() if v}
    out["unresolved_selectors"] = [s.selector for s in a.selectors if not s.signature]
    print(json.dumps(out, indent=2))

    _eprint("== analyze ==")
    md = a.metadata
    _eprint(
        "solc (metadata): %s   evm floor: %s   optimizer: %s   viaIR: %s"
        % (md.solc, a.evm_floor, a.optimizer_guess, a.via_ir_guess)
    )
    _eprint("functions:")
    for s in a.selectors:
        _eprint("  0x%s -> %s  (body @ 0x%x)" % (s.selector, s.signature or "??? UNRESOLVED", s.body_offset))
    if a.has_receive_or_fallback:
        _eprint("  + receive()/fallback() present")
    if a.strings:
        _eprint("strings: %s" % ", ".join(repr(x) for x in a.strings))
    for h, names in out["resolved_events"].items():
        _eprint("event topic 0x%s… -> %s" % (h[:12], names))
    for h, names in out["resolved_errors"].items():
        _eprint("error 0x%s -> %s" % (h, names))
    return 0


def cmd_decompile(args) -> int:
    code, _label = _resolve_source(args.target, args.rpc_url, args.no_cache)
    outdir = args.out or os.path.join("runs", "decompile")
    code_hex = "0x" + code.hex()
    d = decompile(code_hex, outdir, timeout=args.timeout, skip_resolving=args.skip_resolving)
    if not d.ok:
        _eprint("decompile failed: %s" % d.error)
        print(json.dumps({"ok": False, "error": d.error}))
        return 1
    print(json.dumps({"ok": True, "outdir": d.outdir, "signatures": d.resolved_signatures}))
    _eprint("== heimdall decompilation (%s) ==" % d.outdir)
    if d.resolved_signatures:
        _eprint("signatures: %s" % ", ".join(d.resolved_signatures))
    if d.solidity:
        _eprint("---- decompiled.sol ----")
        _eprint(d.solidity)
    return 0


def _parse_optimizer(spec: Optional[str]) -> Optional[Settings]:
    """--optimizer off | on:RUNS ; returns partial Settings (evm/viaIR applied by caller)."""
    if spec is None:
        return None
    if spec == "off":
        return Settings(optimizer_enabled=False)
    if spec.startswith("on"):
        runs = int(spec.split(":", 1)[1]) if ":" in spec else 200
        return Settings(optimizer_enabled=True, optimizer_runs=runs)
    raise SystemExit("invalid --optimizer %r (use off | on:RUNS)" % spec)


def _iter_settings(args, version: str, evm_floor: Optional[str], via_ir_first: bool = False, optimizer_first: str = "off"):
    forced = _parse_optimizer(args.optimizer)
    if args.sweep and forced is None and args.evm is None and not args.via_ir:
        yield from settings_sweep(
            version, evm_floor=evm_floor, via_ir_first=via_ir_first, optimizer_first=optimizer_first
        )
        return
    base = forced or Settings()
    yield Settings(
        optimizer_enabled=base.optimizer_enabled,
        optimizer_runs=base.optimizer_runs,
        evm_version=args.evm,
        via_ir=args.via_ir,
    )


def cmd_verify(args) -> int:
    target, target_label = _resolve_source(args.target, args.rpc_url, args.no_cache)
    with open(args.solfile) as f:
        source = f.read()

    a = analyze(target)
    _resolve_analysis(a, use_network=not args.offline)
    version = args.solc or a.metadata.solc
    if not version:
        _eprint("no solc version in metadata; pass --solc <version>")
        return 2
    evm_floor = a.evm_floor

    best: Optional[Comparison] = None
    best_settings: Optional[Settings] = None
    best_contract = None
    tried = 0
    compile_errors: List[str] = []

    settings_iter = _iter_settings(
        args,
        version,
        evm_floor,
        via_ir_first=(a.via_ir_guess == "likely"),
        optimizer_first=("on" if a.optimizer_guess == "on" else "off"),
    )
    for st in settings_iter:
        tried += 1
        res: CompileResult = compile_standard(source, version, st, source_name="source.sol")
        if not res.ok:
            compile_errors = res.errors
            if tried >= (200 if args.sweep else 1):
                break
            continue
        contract = res.pick(contract_name=args.contract, target_len=len(target))
        if contract is None:
            continue
        cmp = compare(target, contract)
        if cmp.match:
            best, best_settings, best_contract = cmp, st, contract
            break
        # keep the closest candidate (fewest differing bytes, then closest length)
        if best is None or (cmp.diff_bytes or 1 << 30) < (best.diff_bytes or 1 << 30) or (
            best.reason.startswith("length") and not cmp.reason.startswith("length")
        ):
            best, best_settings, best_contract = cmp, st, contract
        if not args.sweep:
            break

    unresolved = [s.selector for s in a.selectors if not s.signature]

    if best is None:
        _eprint("verify: no candidate compiled. errors:")
        for e in compile_errors[:5]:
            _eprint("  " + e.strip().splitlines()[0])
        print(json.dumps({"match": False, "compile_errors": compile_errors[:5]}))
        return 1

    matched = best.match
    report = build_report(
        input_path=target_label,
        version=version,
        settings=best_settings,
        contract_name=best_contract.name if best_contract else None,
        comparison=best,
        metadata_dict=a.metadata.to_dict(),
        unresolved_selectors=unresolved,
    )

    if matched:
        outdir = args.out or os.path.join("runs", "verify")
        paths = write_artifacts(outdir, source, version, best_settings, best_contract.name, report)
        _eprint("== verify: ✅ MATCH ==")
        _eprint("settings: %s | contract: %s | solc %s" % (best_settings.describe(), best_contract.name, version))
        if best.masked_immutables:
            _eprint("recovered %d immutable(s): %s" % (
                len(best.masked_immutables),
                ", ".join("0x%s@0x%x" % (im["value"], im["offset"]) for im in best.masked_immutables),
            ))
        if best.masked_links:
            _eprint("recovered %d library address(es)" % len(best.masked_links))
        if unresolved:
            _eprint("⚠ unresolved selectors (names may be wrong): %s" % ", ".join(unresolved))
        _eprint("artifacts: %s" % paths["report_md"])
        print(json.dumps({"match": True, "settings": best_settings.describe(), "contract": best_contract.name, "artifacts": paths}))
        return 0

    # mismatch: emit normalized, function-attributed diff for the next iteration
    tstrip, _ = metadata.strip_trailing(target)
    cstrip = best.compiled_image if best.compiled_image else b""
    nd = diff(best.input_image or tstrip, cstrip, a.selectors) if cstrip else None
    _eprint("== verify: ❌ NO MATCH ==")
    _eprint("closest settings: %s | contract: %s" % (best_settings.describe(), best_contract.name if best_contract else "?"))
    _eprint(best.reason)
    if nd:
        _eprint(nd.summary())
    print(json.dumps({
        "match": False,
        "reason": best.reason,
        "closest_settings": best_settings.describe(),
        "contract": best_contract.name if best_contract else None,
        "length_delta_opcodes": nd.length_delta if nd else None,
        "regions": [
            {"tag": r.tag, "pc": r.target_pc, "function": r.function, "expected": r.expected[:16], "got": r.got[:16]}
            for r in (nd.regions[:8] if nd else [])
        ],
        "unresolved_selectors": unresolved,
    }, indent=2))
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="verifyoor", description="Verify Solidity source against EVM runtime bytecode.")
    sub = p.add_subparsers(dest="cmd", required=True)

    src_help = "'<network> <address>' to fetch runtime code, or a single hex file / hex string"

    pa = sub.add_parser("analyze", help="static analysis + selector/event resolution")
    pa.add_argument("target", nargs="+", help=src_help)
    pa.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pa.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pa.add_argument("--offline", action="store_true", help="skip openchain network lookups")
    pa.set_defaults(func=cmd_analyze)

    pd = sub.add_parser("decompile", help="heimdall decompile wrapper")
    pd.add_argument("target", nargs="+", help=src_help)
    pd.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pd.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pd.add_argument("--out", help="output directory")
    pd.add_argument("--timeout", type=int, default=120)
    pd.add_argument("--skip-resolving", action="store_true")
    pd.set_defaults(func=cmd_decompile)

    pv = sub.add_parser("verify", help="compile a candidate source and compare to target bytecode")
    pv.add_argument("solfile", help="candidate Solidity source file")
    pv.add_argument("target", nargs="+", help=src_help)
    pv.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pv.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pv.add_argument("--contract", help="contract name to select from the source")
    pv.add_argument("--solc", help="solc version (defaults to metadata)")
    pv.add_argument("--optimizer", help="off | on:RUNS")
    pv.add_argument("--evm", help="evmVersion override")
    pv.add_argument("--via-ir", action="store_true")
    pv.add_argument("--sweep", action="store_true", help="sweep optimizer/evm/viaIR until match")
    pv.add_argument("--out", help="artifacts output directory (on match)")
    pv.add_argument("--offline", action="store_true", help="skip openchain network lookups")
    pv.set_defaults(func=cmd_verify)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
