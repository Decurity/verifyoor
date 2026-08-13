"""Emit the Etherscan/Sourcify standard-json input for a verified match and submit it.

Standard-json is the reliable submission format: the evmVersion (and optimizer /
viaIR) are embedded in the JSON, so the verifier can't silently default them — the
failure mode that trips up single-file/flatten submissions when a contract was
built for a non-default EVM target.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from .compile import ensure_solc
from .util import run

# network alias -> EVM chain id (Etherscan v2 + Sourcify both key on chain id)
CHAIN_IDS = {
    "ethereum": 1, "mainnet": 1, "eth": 1,
    "sepolia": 11155111, "holesky": 17000,
    "base": 8453, "base-sepolia": 84532,
    "arbitrum": 42161, "arbitrum-one": 42161, "arb": 42161,
    "optimism": 10, "op": 10,
    "polygon": 137, "matic": 137,
    "bsc": 56, "bnb": 56,
    "avalanche": 43114, "avax": 43114,
    "gnosis": 100, "linea": 59144, "scroll": 534352, "blast": 81457,
    "zksync": 324, "celo": 42220, "fantom": 250, "ftm": 250,
}

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
SOURCIFY_SERVER = "https://sourcify.dev/server"


def chain_id_for(network: str) -> int:
    if network.isdigit():
        return int(network)
    cid = CHAIN_IDS.get(network.lower())
    if cid is None:
        raise ValueError(
            "unknown network %r for verification; pass a numeric chain id or one of: %s"
            % (network, ", ".join(sorted(set(CHAIN_IDS))))
        )
    return cid


def solc_long_version(version: str) -> str:
    """Full solc version with commit hash, e.g. '0.8.26+commit.8a97fa7a' — required
    by both Etherscan (as 'v<long>') and Sourcify."""
    out = run([ensure_solc(version), "--version"]).stdout
    m = re.search(r"(\d+\.\d+\.\d+\+commit\.[0-9a-f]+)", out)
    if not m:
        raise RuntimeError("could not parse solc long version from: %s" % out.strip()[:200])
    return m.group(1)


def build_standard_input(source: str, settings_block: Dict[str, Any], source_name: str = "source.sol") -> Dict[str, Any]:
    """The solc Standard-JSON-Input that Etherscan and Sourcify both accept. The
    outputSelection is broadened to what verifiers expect; it does not affect the
    produced bytecode."""
    settings = dict(settings_block)
    settings["outputSelection"] = {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode", "metadata"], "": ["ast"]}}
    return {"language": "Solidity", "sources": {source_name: {"content": source}}, "settings": settings}


def _post(url: str, data: bytes, headers: Optional[Dict[str, str]] = None, timeout: int = 60) -> Any:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def etherscan_submit(
    chainid: int,
    address: str,
    standard_input: Dict[str, Any],
    contract_name: str,
    long_version: str,
    api_key: str,
    constructor_args: str = "",
    poll: bool = True,
    timeout: int = 30,
) -> Tuple[bool, str]:
    """Submit standard-json to Etherscan v2 and (optionally) poll to completion.
    contract_name is '<sourceName>:<ContractName>'."""
    body = urllib.parse.urlencode({
        "chainid": str(chainid), "module": "contract", "action": "verifysourcecode", "apikey": api_key,
        "codeformat": "solidity-standard-json-input", "sourceCode": json.dumps(standard_input),
        "contractaddress": address, "contractname": contract_name,
        "compilerversion": "v" + long_version, "constructorArguements": constructor_args.removeprefix("0x"),
    }).encode()
    resp = _post(ETHERSCAN_V2 + "?chainid=%d" % chainid, body, timeout=timeout)
    if str(resp.get("status")) != "1":
        msg = str(resp.get("result") or resp.get("message"))
        # already-verified is a success from the user's point of view
        return ("already verified" in msg.lower(), msg)
    guid = resp.get("result")
    if not poll:
        return True, "submitted (guid=%s)" % guid
    for _ in range(20):
        time.sleep(6)
        q = urllib.parse.urlencode({"chainid": str(chainid), "module": "contract", "action": "checkverifystatus", "guid": guid, "apikey": api_key})
        r = _post_get(ETHERSCAN_V2 + "?" + q, timeout=timeout)
        result = str(r.get("result"))
        if result != "Pending in queue":
            return result.startswith("Pass") or "already verified" in result.lower(), result
    return False, "timed out polling (guid=%s)" % guid


def _post_get(url: str, timeout: int = 30) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


def sourcify_submit(
    chainid: int,
    address: str,
    standard_input: Dict[str, Any],
    contract_name: str,
    long_version: str,
    poll: bool = True,
    timeout: int = 60,
) -> Tuple[bool, str]:
    """Submit standard-json to Sourcify's v2 API. Sourcify matches runtime bytecode
    and is metadata-tolerant, so a partial (metadata-stripped) match verifies."""
    url = "%s/v2/verify/%d/%s" % (SOURCIFY_SERVER, chainid, address)
    payload = json.dumps({
        "stdJsonInput": standard_input,
        "compilerVersion": long_version,
        "contractIdentifier": contract_name,
    }).encode()
    try:
        resp = _post(url, payload, headers={"Content-Type": "application/json"}, timeout=timeout)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        if e.code == 409 or "already" in detail.lower():
            return True, "already verified on Sourcify"
        return False, "HTTP %d: %s" % (e.code, detail)
    vid = resp.get("verificationId")
    if not vid:
        return bool(resp.get("isVerified")), json.dumps(resp)[:200]
    if not poll:
        return True, "submitted (verificationId=%s)" % vid
    for _ in range(20):
        time.sleep(4)
        r = _post_get("%s/v2/verify/%s" % (SOURCIFY_SERVER, vid), timeout=timeout)
        if not r.get("isJobCompleted"):
            continue
        err = r.get("error")
        if err:
            code = err.get("customCode", "")
            if code == "already_verified":
                return True, "already verified on Sourcify"
            return False, err.get("message", code) or json.dumps(err)[:200]
        contract = r.get("contract") or {}
        match = contract.get("match") or contract.get("runtimeMatch")
        return match is not None, "match=%s (runtime=%s, creation=%s)" % (
            match, contract.get("runtimeMatch"), contract.get("creationMatch"),
        )
    return False, "timed out polling (verificationId=%s)" % vid
