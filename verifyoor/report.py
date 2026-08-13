"""Emit verification artifacts: source.sol, settings.json, report.{json,md}."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .compare import Comparison
from .compile import Settings


def build_settings_json(version: str, settings: Settings, contract_name: str, source_name: str = "source.sol") -> Dict[str, Any]:
    """A standard-json settings block reusable for Sourcify/Etherscan submission."""
    return {
        "solcVersion": version,
        "contractName": contract_name,
        "sourceName": source_name,
        "settings": settings.to_solc(version),
    }


def build_report(
    input_path: str,
    version: str,
    settings: Optional[Settings],
    contract_name: Optional[str],
    comparison: Optional[Comparison],
    metadata_dict: Dict[str, Any],
    unresolved_selectors: Optional[List[str]] = None,
    iterations: Optional[int] = None,
) -> Dict[str, Any]:
    matched = bool(comparison and comparison.match)
    return {
        "input": input_path,
        "match": matched,
        "match_type": "partial (metadata-stripped)" if matched else "no match",
        "solc_version": version,
        "settings": settings.describe() if settings else None,
        "contract_name": contract_name,
        "iterations": iterations,
        "metadata": metadata_dict,
        "comparison": comparison.to_dict() if comparison else None,
        "recovered_immutables": comparison.masked_immutables if comparison else [],
        "recovered_libraries": comparison.masked_links if comparison else [],
        "embedded_metadata_masked": (comparison.masked_embedded_meta if comparison else []),
        "unresolved_selectors": unresolved_selectors or [],
    }


def _md(report: Dict[str, Any]) -> str:
    L = []
    status = "✅ MATCH" if report["match"] else "❌ NO MATCH"
    L.append("# verifyoor report — %s" % status)
    L.append("")
    L.append("- **Input:** `%s`" % report["input"])
    L.append("- **Match type:** %s" % report["match_type"])
    L.append("- **solc:** %s" % report["solc_version"])
    L.append("- **Settings:** %s" % (report["settings"] or "n/a"))
    L.append("- **Contract:** %s" % (report["contract_name"] or "n/a"))
    if report.get("iterations") is not None:
        L.append("- **Iterations:** %d" % report["iterations"])
    md = report.get("metadata") or {}
    if md.get("present"):
        L.append("- **Embedded metadata:** solc %s, %s hash `%s`" % (md.get("solc"), md.get("hash_kind"), (md.get("hash") or "")[:16] + "…"))
    if report.get("recovered_immutables"):
        L.append("")
        L.append("## Recovered immutables")
        for im in report["recovered_immutables"]:
            L.append("- offset 0x%x (%d bytes): `0x%s`" % (im["offset"], im["length"], im["value"]))
    if report.get("recovered_libraries"):
        L.append("")
        L.append("## Recovered library addresses")
        for lb in report["recovered_libraries"]:
            L.append("- `%s` at offset 0x%x: `0x%s`" % (lb.get("placeholder", "?"), lb["offset"], lb["value"]))
    if report.get("unresolved_selectors"):
        L.append("")
        L.append("## ⚠ Unresolved selectors")
        L.append("These dispatcher entries lack a verified signature; their function names may not match:")
        for s in report["unresolved_selectors"]:
            L.append("- `0x%s`" % s)
    return "\n".join(L) + "\n"


def write_artifacts(
    outdir: str,
    source: str,
    version: str,
    settings: Settings,
    contract_name: str,
    report: Dict[str, Any],
) -> Dict[str, str]:
    os.makedirs(outdir, exist_ok=True)
    paths = {
        "source": os.path.join(outdir, "source.sol"),
        "settings": os.path.join(outdir, "settings.json"),
        "standard_input": os.path.join(outdir, "standard-input.json"),
        "report_json": os.path.join(outdir, "report.json"),
        "report_md": os.path.join(outdir, "report.md"),
    }
    with open(paths["source"], "w") as f:
        f.write(source)
    with open(paths["settings"], "w") as f:
        json.dump(build_settings_json(version, settings, contract_name), f, indent=2)
    # ready-to-submit Etherscan/Sourcify standard-json input (evmVersion embedded)
    from .submit import build_standard_input

    with open(paths["standard_input"], "w") as f:
        json.dump(build_standard_input(source, settings.to_solc(version)), f, indent=2)
    with open(paths["report_json"], "w") as f:
        json.dump(report, f, indent=2)
    with open(paths["report_md"], "w") as f:
        f.write(_md(report))
    return paths
