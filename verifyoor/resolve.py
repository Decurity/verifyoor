"""Resolve function selectors and event topics via Sourcify's 4byte signature DB.

Uses `api.4byte.sourcify.dev` — the Sourcify-maintained public-good database that
took over openchain.xyz's 4byte API (same schema, same domain). It exposes a
`hasVerifiedContract` flag per signature; we rank those first, since a name that
appears in a verified contract is far likelier to be the real one than 4byte spam.
Every hit is still rehash-verified (keccak(sig)[:4/full] must equal the queried
hash). Results are cached on disk so repeat runs and tests are offline-fast.
Override the endpoint with $VERIFYOOR_SIGDB_URL (e.g. the api.openchain.xyz mirror).
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional

from .util import keccak256

_CACHE_DIR = os.path.expanduser("~/.cache/verifyoor")
_CACHE_FILE = os.path.join(_CACHE_DIR, "signatures.json")
_API = os.environ.get("VERIFYOOR_SIGDB_URL",
                      "https://api.4byte.sourcify.dev/signature-database/v1/lookup")


def _load_cache() -> Dict[str, Dict[str, List[str]]]:
    try:
        with open(_CACHE_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"function": {}, "event": {}}


def _save_cache(cache: Dict[str, Dict[str, List[str]]]) -> None:
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cache, f)
        os.replace(tmp, _CACHE_FILE)
    except OSError:
        pass


def _rehash_ok(kind: str, sig: str, want_hex: str) -> bool:
    try:
        digest = keccak256(sig.encode()).hex()
    except Exception:
        return False
    return digest[:8] == want_hex if kind == "function" else digest == want_hex


def _normalize(kind: str, h: str) -> str:
    h = h.lower().removeprefix("0x")
    return h.zfill(8) if kind == "function" else h.zfill(64)


def _query_sigdb(kind: str, hashes: List[str], timeout: int) -> Dict[str, List[str]]:
    param = "function" if kind == "function" else "event"
    prefixed = ["0x" + h for h in hashes]
    url = _API + "?" + urllib.parse.urlencode({param: ",".join(prefixed)})
    req = urllib.request.Request(url, headers={"User-Agent": "verifyoor"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)
    result = data.get("result", {}).get(param, {}) or {}
    out: Dict[str, List[str]] = {}
    for key, matches in result.items():
        ms = [m for m in (matches or []) if m.get("name")]
        # verified-contract names first (stable within groups) — best real-name signal
        ms.sort(key=lambda m: not m.get("hasVerifiedContract", False))
        out[key.lower().removeprefix("0x")] = [m["name"] for m in ms]
    return out


def resolve(kind: str, hashes: Iterable[str], timeout: int = 15, use_network: bool = True) -> Dict[str, Optional[str]]:
    """kind in {"function","event"}. Returns hash -> best rehash-verified signature (or None)."""
    assert kind in ("function", "event")
    wanted = [_normalize(kind, h) for h in hashes]
    if not wanted:
        return {}

    cache = _load_cache()
    bucket = cache.setdefault(kind, {})
    missing = [h for h in wanted if h not in bucket]

    if missing and use_network:
        try:
            fetched = _query_sigdb(kind, missing, timeout)
            for h in missing:
                bucket[h] = fetched.get(h, [])
            _save_cache(cache)
        except Exception:
            for h in missing:
                bucket.setdefault(h, [])

    resolved: Dict[str, Optional[str]] = {}
    for h in wanted:
        pick = None
        for sig in bucket.get(h, []):
            if _rehash_ok(kind, sig, h):
                pick = sig
                break
        resolved[h] = pick
    return resolved


def resolve_selectors(selectors: Iterable[str], **kw) -> Dict[str, Optional[str]]:
    return resolve("function", selectors, **kw)


def resolve_topics(topics: Iterable[str], **kw) -> Dict[str, Optional[str]]:
    return resolve("event", topics, **kw)
