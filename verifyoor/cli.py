"""verifyoor CLI: analyze | lift | mine-selector | verify | submit.

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
from .cfg import Cfg
from .disasm import disassemble, render_range
from .fetch import fetch_code, fetch_creation
from .lift import Lifter
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


def _parse_range(spec: Optional[str]):
    """'0xLO-0xHI' | '0xLO..0xHI' | '0xLO' -> (lo, hi). None -> (None, None)."""
    if not spec:
        return None, None
    sep = ".." if ".." in spec else "-"
    parts = spec.split(sep, 1)
    lo = int(parts[0], 0)
    hi = int(parts[1], 0) if len(parts) == 2 and parts[1] else None
    return lo, hi


def _etherscan_key(args) -> Optional[str]:
    return getattr(args, "api_key", None) or os.environ.get("ETHERSCAN_API_KEY")


def _fmt_writes(writes) -> str:
    out = []
    for w in writes:
        val = ("0x%x" % w.value) if w.value is not None else w.value_expr
        out.append("slot %d = %s" % (w.slot, val))
    return ", ".join(out) if out else "(none)"


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
    creation_lines = _analyze_creation(args, code, out) if getattr(args, "creation", False) else []
    print(json.dumps(out, indent=2))

    _eprint("== analyze ==")
    md = a.metadata
    _eprint(
        "solc (metadata): %s   evm floor: %s   optimizer: %s   viaIR: %s"
        % (md.solc, a.evm_floor, a.optimizer_guess, a.via_ir_guess)
    )
    _eprint("functions:%s" % ("" if a.evmole_available else "  (evmole unavailable for this bytecode — fell back to the dispatcher walk)"))
    for s in a.selectors:
        name = s.signature or "??? UNRESOLVED"
        args = "(%s)" % s.arguments if s.arguments is not None else "(?)"
        mut = "  %s" % s.state_mutability if s.state_mutability else ""
        _eprint("  0x%s -> %s  args=%s%s  (body @ 0x%x)" % (s.selector, name, args, mut, s.body_offset))
        if not s.signature and s.arguments is not None:
            _eprint("      → unresolved; mint: verifyoor mine-selector 0x%s \"%s\"" % (s.selector, s.mint_signature()))
    if a.has_receive_or_fallback:
        _eprint("  + receive()/fallback() present")
    if a.storage:
        _eprint("storage layout (declare state vars in this order):")
        for v in a.storage:
            at = "slot %d" % v.slot + (" @byte %d" % v.offset if v.offset else "")
            writers = ("  written by %s" % ", ".join("0x" + w for w in v.writes)) if v.writes else "  (read-only)"
            _eprint("  %-8s %s%s" % (at, v.type, writers))
    if a.strings:
        _eprint("strings: %s" % ", ".join(repr(x) for x in a.strings))
    for h, names in out["resolved_events"].items():
        _eprint("event topic 0x%s… -> %s" % (h[:12], names))
    for h, names in out["resolved_errors"].items():
        _eprint("error 0x%s -> %s" % (h, names))
    for line in creation_lines:
        _eprint(line)
    return 0


def _analyze_creation(args, runtime: bytes, out) -> List[str]:
    """Fetch the deploy tx's creation code, populate out["creation"], return log lines.

    Constructor storage writes never appear in runtime code, so a runtime-only
    analysis can't see e.g. a reentrancy-guard `_status = 1` init — which is exactly
    what makes a runtime match fail Etherscan's creation-code verification.
    """
    from .creation import constructor_writes, split_creation

    if len(args.target) != 2:
        return ["--creation needs '<network> <address>' (creation code isn't in a local hex)"]
    key = _etherscan_key(args)
    if not key:
        return ["--creation needs an Etherscan key (--api-key or ETHERSCAN_API_KEY)"]
    network, address = args.target
    try:
        creation = fetch_creation(network, address, key, use_cache=not args.no_cache)
    except (RuntimeError, ValueError) as e:
        return ["creation: %s" % e]
    split = split_creation(creation, runtime)
    if split is None:
        out["creation"] = {"creation_len": len(creation), "runtime_located": False}
        return ["creation: could not locate runtime within creation code (factory/CREATE2?)"]
    writes = constructor_writes(split.init)
    out["creation"] = {
        "creation_len": len(creation),
        "init_len": len(split.init),
        "ctor_args_len": len(split.ctor_args),
        "ctor_args_hex": split.ctor_args.hex(),
        "runtime_located": True,
        "constructor_writes": [
            {"slot": w.slot, "value": w.value, "value_expr": w.value_expr, "pc": w.pc} for w in writes
        ],
    }
    return [
        "constructor: init %d bytes, %d byte(s) of constructor args" % (len(split.init), len(split.ctor_args)),
        "  storage writes: %s" % _fmt_writes(writes),
        "  (declare these initial values in your constructor — they gate Etherscan creation-code verification)",
    ]


def cmd_mine_selector(args) -> int:
    from .mine import find_external_miner, mine
    from .util import selector_of

    sel = args.selector.lower().removeprefix("0x")
    argtypes = args.argtypes if args.argtypes.startswith("(") else "(%s)" % args.argtypes
    backend = "python" if args.python else "auto"
    used = "python" if args.python else ("external" if find_external_miner() else "python")
    _eprint("== mine-selector == 0x%s %s  [backend: %s]" % (sel, argtypes, used))
    name = mine(sel, argtypes, workers=args.threads, prefix=args.prefix, backend=backend)
    sig = "%s%s" % (name, argtypes)
    assert selector_of(sig) == sel
    _eprint("found: %s" % sig)
    print(json.dumps({"selector": sel, "name": name, "signature": sig, "backend": used}))
    return 0


def cmd_lift(args) -> int:
    code, _label = _resolve_source(args.target, args.rpc_url, args.no_cache)
    a = analyze(code)
    _resolve_analysis(a, use_network=not args.offline)
    md = a.metadata
    stripped = code[: md.start] if md.present else code
    cfg = Cfg.from_code(stripped)
    lifter = Lifter(disassemble(stripped), cfg=cfg)
    lines = lifter.listing(selectors=a.selectors)
    text = "\n".join(lines) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            f.write(text)
        _eprint("== lift == %d line(s)%s -> %s"
                % (len(lines), " (CFG edges resolved)" if cfg else "", args.out))
    else:
        _eprint("== lift ==")
        _eprint(text)
    print(json.dumps({
        "ok": True,
        "lines": len(lines),
        "cfg": cfg is not None,
        "out": args.out,
        "functions": [s.signature or ("selector 0x%s" % s.selector) for s in a.selectors],
    }))
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
        result = {"match": True, "settings": best_settings.describe(), "contract": best_contract.name, "artifacts": paths}
        rc = 0
        if getattr(args, "creation", False):
            cres = _verify_creation(args, target, best_contract, a.selectors)
            result["creation"] = cres
            rc = 0 if cres.get("match") else 1
        print(json.dumps(result))
        return rc

    # mismatch: emit normalized, function-attributed diff for the next iteration
    tstrip, _ = metadata.strip_trailing(target)
    cstrip = best.compiled_image if best.compiled_image else b""
    nd = diff(best.input_image or tstrip, cstrip, a.selectors) if cstrip else None
    _eprint("== verify: ❌ NO MATCH ==")
    _eprint("closest settings: %s | contract: %s" % (best_settings.describe(), best_contract.name if best_contract else "?"))
    _eprint(best.reason)
    if nd:
        _eprint(nd.summary())
    cap = args.max_regions
    total = nd.region_count if nd else 0
    mismatch = {
        "match": False,
        "reason": best.reason,
        "closest_settings": best_settings.describe(),
        "contract": best_contract.name if best_contract else None,
        "length_delta_opcodes": nd.length_delta if nd else None,
        "total_regions": total,
        "regions_truncated": total > cap,
        "regions": [
            {"tag": r.tag, "pc": r.target_pc, "function": r.function, "expected": r.expected[:16], "got": r.got[:16],
             "expected_ir": r.expected_ir, "got_ir": r.got_ir}
            for r in (nd.regions[:cap] if nd else [])
        ],
        "unresolved_selectors": unresolved,
    }
    # Persist the mismatch report so iterating doesn't require redirecting stdout.
    if args.out:
        try:
            os.makedirs(args.out, exist_ok=True)
            with open(os.path.join(args.out, "diff.json"), "w") as f:
                json.dump(mismatch, f, indent=2)
            _eprint("diff written: %s" % os.path.join(args.out, "diff.json"))
        except OSError:
            pass
    print(json.dumps(mismatch, indent=2))
    return 1


def _verify_creation(args, target: bytes, contract, selectors) -> dict:
    """Compare the constructor init-code against the on-chain deploy tx (post runtime match).

    A runtime match doesn't imply Etherscan will accept the source: Etherscan verifies
    the creation bytecode, whose constructor segment isn't present in runtime. This
    fetches that segment and diffs it, surfacing the exact constructor divergence
    (typically a missing storage init) before a submit round-trip.
    """
    from .creation import compare_init

    if len(args.target) != 2:
        _eprint("⚠ --creation needs '<network> <address>'; skipping creation check")
        return {"checked": False, "reason": "no network/address"}
    key = _etherscan_key(args)
    if not key:
        _eprint("⚠ --creation needs an Etherscan key (--api-key or ETHERSCAN_API_KEY); skipping")
        return {"checked": False, "reason": "no api key"}
    if not contract or not contract.creation_object:
        return {"checked": False, "reason": "no compiled creation bytecode"}
    network, address = args.target
    try:
        onchain = fetch_creation(network, address, key, use_cache=not args.no_cache)
    except (RuntimeError, ValueError) as e:
        _eprint("⚠ creation fetch failed: %s" % e)
        return {"checked": False, "reason": str(e)}

    compiled = bytes.fromhex(contract.creation_object)
    ic = compare_init(onchain, compiled, target, selectors)
    result = {
        "checked": True,
        "match": ic.match,
        "reason": ic.reason,
        "ctor_args_len": ic.ctor_args_len,
        "onchain_constructor_writes": [
            {"slot": w.slot, "value": w.value, "value_expr": w.value_expr} for w in ic.onchain_writes],
        "compiled_constructor_writes": [
            {"slot": w.slot, "value": w.value, "value_expr": w.value_expr} for w in ic.compiled_writes],
    }
    if ic.match:
        _eprint("== creation: ✅ constructor init-code matches ==")
        _eprint("  %s" % ic.reason)
    else:
        _eprint("== creation: ❌ constructor init-code DIFFERS ==")
        _eprint("  %s" % ic.reason)
        _eprint("  on-chain constructor writes: %s" % _fmt_writes(ic.onchain_writes))
        _eprint("  your constructor writes:     %s" % _fmt_writes(ic.compiled_writes))
        missing = _missing_writes(ic.onchain_writes, ic.compiled_writes)
        if missing:
            _eprint("  → add to your constructor: %s" % _fmt_writes(missing))
        if ic.diff is not None:
            result["init_length_delta"] = ic.diff.length_delta
            result["init_diff"] = [
                {"tag": r.tag, "pc": r.target_pc, "expected": r.expected[:16], "got": r.got[:16]}
                for r in ic.diff.regions[:8]
            ]
            _eprint("  init diff: %s" % ic.diff.summary(max_regions=4))
    return result


def _missing_writes(onchain, compiled):
    have = {(w.slot, w.value_expr) for w in compiled}
    have_slots = {w.slot for w in compiled}
    # a write is "missing" if neither the exact (slot,value) nor the slot appears
    return [w for w in onchain if (w.slot, w.value_expr) not in have and w.slot not in have_slots]


def cmd_sweep(args) -> int:
    """Compile a templated candidate across all source variants x compiler settings,
    stopping at the first byte-exact match. Automates the manual edit-verify grind."""
    from .template import count_variants, expand, marker_count

    target, target_label = _resolve_source(args.target, args.rpc_url, args.no_cache)
    with open(args.solfile) as f:
        template = f.read()
    a = analyze(target)
    _resolve_analysis(a, use_network=not args.offline)
    version = args.solc or a.metadata.solc
    if not version:
        _eprint("no solc version in metadata; pass --solc <version>")
        return 2

    nvar = count_variants(template)
    forced = _parse_optimizer(args.optimizer)
    if forced is None and args.evm is None and not args.via_ir:
        settings_list = list(settings_sweep(
            version, evm_floor=a.evm_floor,
            via_ir_first=(a.via_ir_guess == "likely"),
            optimizer_first=("on" if a.optimizer_guess == "on" else "off")))
    else:
        base = forced or Settings()
        settings_list = [Settings(base.optimizer_enabled, base.optimizer_runs, args.evm, args.via_ir)]

    _eprint("== sweep == %d marker(s) -> %d variant(s) x %d setting(s) = %d compiles (max)"
            % (marker_count(template), nvar, len(settings_list), nvar * len(settings_list)))
    if nvar > args.max_variants:
        _eprint("refusing: %d variants exceeds --max-variants %d" % (nvar, args.max_variants))
        return 2

    best = None  # (key, cmp, settings, contract, source, combo)
    unresolved = [s.selector for s in a.selectors if not s.signature]
    tstrip, _ = metadata.strip_trailing(target)
    for combo, source in expand(template):
        for st in settings_list:
            res = compile_standard(source, version, st, source_name="source.sol")
            if not res.ok:
                continue
            contract = res.pick(contract_name=args.contract, target_len=len(target))
            if contract is None:
                continue
            cmp = compare(target, contract)
            if cmp.match:
                outdir = args.out or os.path.join("runs", "sweep")
                report = build_report(target_label, version, st, contract.name, cmp,
                                      a.metadata.to_dict(), unresolved)
                paths = write_artifacts(outdir, source, version, st, contract.name, report)
                _eprint("== sweep: ✅ MATCH == variant %s | %s | contract %s"
                        % (list(combo), st.describe(), contract.name))
                _eprint("artifacts: %s" % paths["report_md"])
                print(json.dumps({"match": True, "variant": list(combo),
                                  "settings": st.describe(), "artifacts": paths}))
                return 0
            # rank by normalized-diff region count — the true "closeness" (diff_bytes
            # is 0 on any length mismatch, so it can't rank near-misses). lift_ir=False
            # keeps this cheap (region count only, no IR). Ties break on byte length.
            nd = diff(cmp.input_image or tstrip, cmp.compiled_image, a.selectors,
                      lift_ir=False) if cmp.compiled_image else None
            clen = len(cmp.compiled_image) if cmp.compiled_image else 0
            key = (nd.region_count if nd else 1 << 30, abs(clen - len(tstrip)))
            if best is None or key < best[0]:
                best = (key, cmp, st, contract, source, combo)

    if best is None:
        _eprint("sweep: no variant compiled")
        print(json.dumps({"match": False, "error": "no variant compiled"}))
        return 1

    _, cmp, st, contract, source, combo = best
    tstrip, _ = metadata.strip_trailing(target)
    nd = diff(cmp.input_image or tstrip, cmp.compiled_image, a.selectors) if cmp.compiled_image else None
    _eprint("== sweep: ❌ no exact match; closest variant ==")
    _eprint("variant %s | %s | diff_bytes=%s | regions=%s"
            % (list(combo), st.describe(), cmp.diff_bytes, nd.region_count if nd else "?"))
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "closest.sol"), "w") as f:
            f.write(source)
        _eprint("wrote closest variant -> %s/closest.sol" % args.out)
    print(json.dumps({
        "match": False,
        "closest_variant": list(combo),
        "closest_settings": st.describe(),
        "diff_bytes": cmp.diff_bytes,
        "regions": nd.region_count if nd else None,
    }, indent=2))
    return 1


def cmd_identify_library(args) -> int:
    """Sweep a known library's versions x compiler settings; score by basic-block
    fingerprint overlap against the target. Recovers large verbatim chunks and pins
    settings before hand-authoring the rest — see verifyoor/libmatch.py."""
    from .compile import Settings, settings_sweep
    from .libmatch import npm_versions, sweep_versions

    target, _label = _resolve_source(args.target, args.rpc_url, args.no_cache)
    with open(args.probe) as f:
        probe_template = f.read()
    a = analyze(target)
    version = args.solc or a.metadata.solc
    if not version:
        _eprint("no solc version in metadata; pass --solc <version>")
        return 2

    versions = args.versions.split(",") if args.versions else npm_versions(args.package, args.max_versions)
    if not versions:
        _eprint("identify-library: no versions found for %s (network issue, or pass --versions)" % args.package)
        return 2

    forced = _parse_optimizer(args.optimizer)
    if forced is None and args.evm is None and not args.via_ir:
        settings_list = list(settings_sweep(version, evm_floor=a.evm_floor))
    else:
        base = forced or Settings()
        settings_list = [Settings(base.optimizer_enabled, base.optimizer_runs, args.evm, args.via_ir)]

    _eprint("== identify-library == %s across %d version(s) x %d setting(s)"
            % (args.package, len(versions), len(settings_list)))
    results = sweep_versions(target, probe_template, args.contract, args.package, args.path,
                             version, versions, settings_list)
    if not results:
        _eprint("identify-library: no version compiled (network issue, bad --path/--contract, or solc error)")
        print(json.dumps({"ok": False}))
        return 1

    best = results[0]
    tstrip, _ = metadata.strip_trailing(target)
    _eprint("best: %s %s | %d/%d blocks matched (%.0f%%) | ~%d bytes of %d recovered"
            % (args.package, best.version, best.hit, best.total, 100 * best.fraction,
               best.matched_bytes, len(tstrip)))
    _eprint("settings: %s" % best.settings.describe())
    top = results[:10]
    for r in top[1:]:
        _eprint("  runner-up: %s %s | %d/%d (%.0f%%)" % (args.package, r.version, r.hit, r.total, 100 * r.fraction))
    if best.fraction < 0.5:
        _eprint("⚠ low match fraction — likely the wrong library/path, or the wrong solc version")
    print(json.dumps({
        "ok": True,
        "best": {"version": best.version, "settings": best.settings.describe(),
                 "hit": best.hit, "total": best.total, "fraction": best.fraction,
                 "matched_bytes": best.matched_bytes},
        "runners_up": [{"version": r.version, "settings": r.settings.describe(),
                        "hit": r.hit, "total": r.total} for r in top[1:]],
    }, indent=2))
    return 0


def cmd_submit(args) -> int:
    from .submit import build_standard_input, chain_id_for, etherscan_submit, solc_long_version, sourcify_submit

    run_dir = args.rundir
    try:
        meta = json.loads(open(os.path.join(run_dir, "settings.json")).read())
        source = open(os.path.join(run_dir, "source.sol")).read()
    except OSError as e:
        _eprint("submit: %s (expected a verify run dir with settings.json + source.sol)" % e)
        return 2

    version = meta["solcVersion"]
    source_name = meta.get("sourceName", "source.sol")
    contract_name = args.contract or meta["contractName"]
    identifier = "%s:%s" % (source_name, contract_name)
    std = build_standard_input(source, meta["settings"], source_name)
    try:
        chainid = chain_id_for(args.network)
        long_version = solc_long_version(version)
    except (ValueError, RuntimeError) as e:
        _eprint("submit: %s" % e)
        return 2

    poll = not args.no_wait
    results: Dict[str, Any] = {}
    overall_ok = True

    if args.verifier in ("etherscan", "both"):
        key = args.api_key or os.environ.get("ETHERSCAN_API_KEY")
        if not key:
            _eprint("submit: no Etherscan API key (--api-key or ETHERSCAN_API_KEY)")
            return 2
        ok, msg = etherscan_submit(chainid, args.address, std, identifier, long_version, key, args.constructor_args or "", poll=poll)
        _eprint("etherscan: %s — %s" % ("✅" if ok else "❌", msg))
        results["etherscan"] = {"ok": ok, "message": msg}
        overall_ok = overall_ok and ok
        # Etherscan matches the CREATION bytecode, whose constructor segment isn't in
        # runtime — so a runtime-verified source can still be rejected here. On that
        # specific failure, diagnose the constructor divergence instead of dead-ending.
        if not ok and "deployment bytecode" in msg.lower():
            diag = _diagnose_creation_mismatch(args, source, meta, version, contract_name, key)
            if diag:
                results["etherscan"]["creation_diagnosis"] = diag

    if args.verifier in ("sourcify", "both"):
        ok, msg = sourcify_submit(chainid, args.address, std, identifier, long_version, poll=poll)
        _eprint("sourcify: %s — %s" % ("✅" if ok else "❌", msg))
        results["sourcify"] = {"ok": ok, "message": msg}
        overall_ok = overall_ok and ok

    print(json.dumps({"address": args.address, "chainid": chainid, "compiler": "v" + long_version, "contract": identifier, "results": results}, indent=2))
    return 0 if overall_ok else 1


def _settings_from_meta(settings_block) -> Settings:
    opt = settings_block.get("optimizer", {}) or {}
    return Settings(
        optimizer_enabled=bool(opt.get("enabled", False)),
        optimizer_runs=int(opt.get("runs", 200)),
        evm_version=settings_block.get("evmVersion"),
        via_ir=bool(settings_block.get("viaIR", False)),
    )


def _diagnose_creation_mismatch(args, source, meta, version, contract_name, key):
    """After an Etherscan 'deployment bytecode does not match', pinpoint the cause.

    Recompiles the submitted source, fetches the on-chain creation + runtime, and
    diffs the constructor init-code — turning an opaque rejection into "add a write to
    slot N". Best-effort: any failure here just returns None (the submit result stands).
    """
    from .creation import compare_init

    try:
        st = _settings_from_meta(meta["settings"])
        res = compile_standard(source, version, st, source_name=meta.get("sourceName", "source.sol"))
        contract = res.pick(contract_name=contract_name)
        if not contract or not contract.creation_object:
            return None
        runtime = fetch_code(args.network, args.address, use_cache=not getattr(args, "no_cache", False))
        onchain = fetch_creation(args.network, args.address, key, use_cache=not getattr(args, "no_cache", False))
        ic = compare_init(onchain, bytes.fromhex(contract.creation_object), runtime)
    except Exception as e:  # noqa: BLE001 — diagnosis must never mask the real result
        _eprint("  (creation diagnosis unavailable: %s)" % e)
        return None

    if ic.match:
        _eprint("  creation init-code actually matches — mismatch is elsewhere "
                "(constructor args? wrong contract name? metadata settings?)")
        return {"init_match": True, "reason": ic.reason}
    _eprint("  → likely cause: constructor init-code differs — %s" % ic.reason)
    _eprint("    on-chain constructor writes: %s" % _fmt_writes(ic.onchain_writes))
    _eprint("    your constructor writes:     %s" % _fmt_writes(ic.compiled_writes))
    missing = _missing_writes(ic.onchain_writes, ic.compiled_writes)
    if missing:
        _eprint("    add to your constructor: %s" % _fmt_writes(missing))
    return {
        "init_match": False,
        "reason": ic.reason,
        "onchain_constructor_writes": [{"slot": w.slot, "value": w.value, "value_expr": w.value_expr} for w in ic.onchain_writes],
        "compiled_constructor_writes": [{"slot": w.slot, "value": w.value, "value_expr": w.value_expr} for w in ic.compiled_writes],
        "missing_writes": [{"slot": w.slot, "value": w.value, "value_expr": w.value_expr} for w in missing],
    }


def cmd_disasm(args) -> int:
    """Plain `pc: OPCODE imm` disassembly of a bytecode source, optionally a pc range."""
    code, _label = _resolve_source(args.target, args.rpc_url, args.no_cache)
    if not args.raw:
        stripped, md = metadata.strip_trailing(code)
        if md.present:
            code = stripped
    lo, hi = _parse_range(args.range)
    for line in render_range(code, lo, hi):
        print(line)
    return 0


def cmd_diff_asm(args) -> int:
    """Normalized, function-attributed opcode diff between two bytecode images.

    Same offset-stable diff `verify` runs, but over an arbitrary candidate hex instead
    of a compile — the fast way to localize a single divergent instruction between two
    bytecodes (e.g. a hand-tweaked compile vs the target). `--function` scopes to one
    function's regions; `--range` to a target pc window.
    """
    target, _tl = _resolve_source(args.target, args.rpc_url, args.no_cache)
    candidate = load_bytecode(args.candidate)
    a = analyze(target)
    _resolve_analysis(a, use_network=not args.offline)
    tstrip, _ = metadata.strip_trailing(target)
    cstrip, _ = metadata.strip_trailing(candidate)
    nd = diff(tstrip, cstrip, a.selectors, lift_ir=not args.no_ir)

    lo, hi = _parse_range(args.range)
    regions = nd.regions
    if args.function:
        regions = [r for r in regions if args.function in r.function]
    if lo is not None:
        regions = [r for r in regions if lo <= r.target_pc < (hi if hi is not None else 1 << 30)]

    _eprint("== diff-asm == candidate length delta = %+d opcodes; %d region(s)%s"
            % (nd.length_delta, len(regions),
               (" of %d (filtered)" % nd.region_count) if len(regions) != nd.region_count else ""))
    if args.json:
        print(json.dumps({
            "match": nd.match,
            "length_delta_opcodes": nd.length_delta,
            "total_regions": nd.region_count,
            "shown_regions": len(regions),
            "regions": [
                {"tag": r.tag, "pc": r.target_pc, "function": r.function,
                 "expected": r.expected[:16], "got": r.got[:16],
                 "expected_ir": r.expected_ir, "got_ir": r.got_ir}
                for r in regions[:args.max_regions]
            ],
        }, indent=2))
    else:
        if nd.match:
            print("normalized opcode streams are identical (any residual diff is data/immediates only)")
        for r in regions[:args.max_regions]:
            print(r.render(ctx=args.context))
        if len(regions) > args.max_regions:
            print("... %d more region(s) (raise --max-regions)" % (len(regions) - args.max_regions))
    return 0 if nd.match else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="verifyoor", description="Verify Solidity source against EVM runtime bytecode.")
    sub = p.add_subparsers(dest="cmd", required=True)

    src_help = "'<network> <address>' to fetch runtime code, or a single hex file / hex string"

    pa = sub.add_parser("analyze", help="static analysis + selector/event resolution")
    pa.add_argument("target", nargs="+", help=src_help)
    pa.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pa.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pa.add_argument("--offline", action="store_true", help="skip Sourcify 4byte name lookups")
    pa.add_argument("--creation", action="store_true", help="also fetch the deploy tx and report constructor storage writes (needs Etherscan key)")
    pa.add_argument("--api-key", help="Etherscan API key for --creation (else $ETHERSCAN_API_KEY)")
    pa.set_defaults(func=cmd_analyze)

    pm = sub.add_parser("mine-selector", help="mint a func name whose selector matches exactly (for unrecoverable names)")
    pm.add_argument("selector", help="target 4-byte selector (0x + 8 hex, or 8 hex)")
    pm.add_argument("argtypes", help="canonical arg types, e.g. '(address[],uint256[])'")
    pm.add_argument("--threads", type=int, help="worker/thread count (default: all cores)")
    pm.add_argument("--prefix", help="candidate name prefix (default: func_<selector>_)")
    pm.add_argument("--python", action="store_true", help="force the pure-Python backend (skip the external miner)")
    pm.set_defaults(func=cmd_mine_selector)

    pl = sub.add_parser("lift", help="deterministic intra-block IR lift of the runtime code")
    pl.add_argument("target", nargs="+", help=src_help)
    pl.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pl.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pl.add_argument("--offline", action="store_true", help="skip Sourcify 4byte name lookups")
    pl.add_argument("--out", help="write the listing to a file (else stderr)")
    pl.set_defaults(func=cmd_lift)

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
    pv.add_argument("--out", help="artifacts output directory (report on match; diff.json on mismatch)")
    pv.add_argument("--offline", action="store_true", help="skip Sourcify 4byte name lookups")
    pv.add_argument("--creation", action="store_true", help="on match, also verify the constructor init-code against the deploy tx (what Etherscan checks; needs Etherscan key)")
    pv.add_argument("--api-key", help="Etherscan API key for --creation (else $ETHERSCAN_API_KEY)")
    pv.add_argument("--max-regions", type=int, default=8, help="max divergent regions to emit in diff JSON (default 8)")
    pv.set_defaults(func=cmd_verify)

    pw = sub.add_parser("sweep", help="compile a templated candidate across all source variants x settings until a match")
    pw.add_argument("solfile", help="templated candidate: mark choices with <<< a ||| b >>>")
    pw.add_argument("target", nargs="+", help=src_help)
    pw.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pw.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pw.add_argument("--contract", help="contract name to select from the source")
    pw.add_argument("--solc", help="solc version (defaults to metadata)")
    pw.add_argument("--optimizer", help="pin optimizer (off | on:RUNS); default sweeps all")
    pw.add_argument("--evm", help="pin evmVersion; default sweeps candidates")
    pw.add_argument("--via-ir", action="store_true", help="pin viaIR on")
    pw.add_argument("--max-variants", type=int, default=256, help="refuse templates expanding past this (default 256)")
    pw.add_argument("--out", help="output dir (artifacts on match; closest.sol otherwise)")
    pw.add_argument("--offline", action="store_true", help="skip Sourcify 4byte name lookups")
    pw.set_defaults(func=cmd_sweep)

    pl2 = sub.add_parser("identify-library", help="sweep a known library's versions x settings; score by block-fingerprint overlap")
    pl2.add_argument("probe", help="Solidity file importing the library, e.g. 'import \"@openzeppelin/contracts/access/Ownable2Step.sol\";'")
    pl2.add_argument("target", nargs="+", help=src_help)
    pl2.add_argument("--package", required=True, help="npm package name, e.g. @openzeppelin/contracts")
    pl2.add_argument("--path", required=True, help="path within the package to the probe's imported root file")
    pl2.add_argument("--contract", required=True, help="contract name to select from the probe compile output")
    pl2.add_argument("--versions", help="comma-separated versions to sweep (default: fetched from the npm registry)")
    pl2.add_argument("--max-versions", type=int, default=30, help="cap when versions are auto-fetched (default 30, newest-first)")
    pl2.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pl2.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pl2.add_argument("--solc", help="solc version (defaults to metadata)")
    pl2.add_argument("--optimizer", help="pin optimizer (off | on:RUNS); default sweeps the standard grid")
    pl2.add_argument("--evm", help="pin evmVersion; default sweeps candidates")
    pl2.add_argument("--via-ir", action="store_true", help="pin viaIR on")
    pl2.set_defaults(func=cmd_identify_library)

    ps = sub.add_parser("submit", help="submit a verified run dir to Etherscan/Sourcify (standard-json)")
    ps.add_argument("rundir", help="a verify --out directory (with settings.json + source.sol)")
    ps.add_argument("network", help="network alias or numeric chain id")
    ps.add_argument("address", help="deployed contract address (0x…)")
    ps.add_argument("--verifier", choices=["etherscan", "sourcify", "both"], default="etherscan")
    ps.add_argument("--api-key", help="Etherscan API key (else $ETHERSCAN_API_KEY)")
    ps.add_argument("--constructor-args", help="ABI-encoded constructor args hex (if any)")
    ps.add_argument("--contract", help="contract name override")
    ps.add_argument("--no-wait", action="store_true", help="submit without polling for the result")
    ps.set_defaults(func=cmd_submit)

    pd = sub.add_parser("disasm", help="disassemble a bytecode source (pc: OPCODE imm), optionally a pc range")
    pd.add_argument("target", nargs="+", help=src_help)
    pd.add_argument("--range", help="pc window, e.g. 0x5ae-0x8f2 (or 0x5ae for open-ended)")
    pd.add_argument("--raw", action="store_true", help="keep the trailing metadata (default strips it)")
    pd.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pd.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pd.set_defaults(func=cmd_disasm)

    pda = sub.add_parser("diff-asm", help="normalized, function-attributed opcode diff between a target and a candidate hex")
    pda.add_argument("target", nargs="+", help=src_help)
    pda.add_argument("--candidate", required=True, help="candidate bytecode: a hex file or 0x-hex string (e.g. a solc deployedBytecode object)")
    pda.add_argument("--function", help="only show regions attributed to functions matching this substring")
    pda.add_argument("--range", help="only show regions whose target pc is in this window, e.g. 0x5ae-0x8f2")
    pda.add_argument("--context", type=int, default=8, help="opcodes of expected/got to show per region (default 8)")
    pda.add_argument("--max-regions", type=int, default=20, help="max regions to print (default 20)")
    pda.add_argument("--no-ir", action="store_true", help="skip the lifted-IR block for each region (faster)")
    pda.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of the rendered diff")
    pda.add_argument("--rpc-url", help="explicit RPC URL (overrides the network alias)")
    pda.add_argument("--no-cache", action="store_true", help="do not use cached fetched bytecode")
    pda.add_argument("--offline", action="store_true", help="skip Sourcify 4byte name lookups")
    pda.set_defaults(func=cmd_diff_asm)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
