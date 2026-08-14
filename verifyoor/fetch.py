"""Fetch runtime (deployed) bytecode for an address via JSON-RPC eth_getCode.

Network aliases resolve to keyless public RPC endpoints; a full http(s) URL may be
passed in place of an alias, and VERIFYOOR_RPC_<NETWORK> / --rpc-url override.
Fetched code is cached under ~/.cache/verifyoor/bytecode so the skill's repeated
analyze/lift/verify calls on one address hit the network only once.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Optional

# Keyless public endpoints (publicnode.com uses a consistent, reliable scheme).
NETWORKS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "mainnet": "https://ethereum-rpc.publicnode.com",
    "eth": "https://ethereum-rpc.publicnode.com",
    "sepolia": "https://ethereum-sepolia-rpc.publicnode.com",
    "holesky": "https://ethereum-holesky-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
    "base-sepolia": "https://base-sepolia-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    "arbitrum-one": "https://arbitrum-one-rpc.publicnode.com",
    "arb": "https://arbitrum-one-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "op": "https://optimism-rpc.publicnode.com",
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    "matic": "https://polygon-bor-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
    "bnb": "https://bsc-rpc.publicnode.com",
    "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
    "avax": "https://avalanche-c-chain-rpc.publicnode.com",
    "gnosis": "https://gnosis-rpc.publicnode.com",
    "linea": "https://linea-rpc.publicnode.com",
    "scroll": "https://scroll-rpc.publicnode.com",
    "blast": "https://blast-rpc.publicnode.com",
    "zksync": "https://mainnet.era.zksync.io",
    "celo": "https://celo-rpc.publicnode.com",
    "fantom": "https://fantom-rpc.publicnode.com",
    "ftm": "https://fantom-rpc.publicnode.com",
}

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_CACHE_DIR = os.path.expanduser("~/.cache/verifyoor/bytecode")


def is_address(s: str) -> bool:
    return bool(_ADDR_RE.match(s))


def rpc_url_for(network: str, rpc_url: Optional[str] = None) -> str:
    if rpc_url:
        return rpc_url
    if network.startswith(("http://", "https://")):
        return network
    env = os.environ.get("VERIFYOOR_RPC_" + network.upper().replace("-", "_"))
    if env:
        return env
    url = NETWORKS.get(network.lower())
    if not url:
        known = ", ".join(sorted(set(NETWORKS)))
        raise ValueError(
            "unknown network %r. Pass a full RPC URL, set VERIFYOOR_RPC_%s, or use one of: %s"
            % (network, network.upper().replace("-", "_"), known)
        )
    return url


def _cache_path(network: str, address: str) -> str:
    safe_net = re.sub(r"[^a-zA-Z0-9]+", "_", network.lower())[:40]
    return os.path.join(_CACHE_DIR, "%s-%s.hex" % (safe_net, address.lower()))


def _rpc_get_code(url: str, address: str, timeout: int) -> str:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]}
    ).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "verifyoor"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)
    if "error" in data:
        raise RuntimeError("RPC error: %s" % data["error"])
    return data.get("result", "0x")


def fetch_code(
    network: str,
    address: str,
    rpc_url: Optional[str] = None,
    timeout: int = 20,
    use_cache: bool = True,
) -> bytes:
    """Return runtime bytecode at `address` on `network`. Raises if no code there."""
    if not is_address(address):
        raise ValueError("invalid address %r (expected 0x + 40 hex chars)" % address)
    url = rpc_url_for(network, rpc_url)

    cache = _cache_path(network, address)
    if use_cache and os.path.isfile(cache):
        with open(cache) as f:
            hexstr = f.read().strip()
        if hexstr and hexstr != "0x":
            return bytes.fromhex(hexstr[2:] if hexstr.startswith("0x") else hexstr)

    result = _rpc_get_code(url, address, timeout)
    if not result or result == "0x":
        raise RuntimeError(
            "no code at %s on %s — is it an EOA, an unverified/pre-deploy address, or wrong network?"
            % (address, network)
        )
    code = bytes.fromhex(result[2:] if result.startswith("0x") else result)
    if use_cache:
        try:
            os.makedirs(_CACHE_DIR, exist_ok=True)
            with open(cache, "w") as f:
                f.write("0x" + code.hex())
        except OSError:
            pass
    return code
