import pytest

from verifyoor import fetch


def test_known_alias_resolves():
    assert fetch.rpc_url_for("ethereum").startswith("https://")
    assert fetch.rpc_url_for("base") != fetch.rpc_url_for("ethereum")


def test_full_url_passthrough():
    assert fetch.rpc_url_for("https://my.node/rpc") == "https://my.node/rpc"


def test_explicit_rpc_wins():
    assert fetch.rpc_url_for("ethereum", rpc_url="https://x") == "https://x"


def test_env_override(monkeypatch):
    monkeypatch.setenv("VERIFYOOR_RPC_FOOCHAIN", "https://foo.rpc")
    assert fetch.rpc_url_for("foochain") == "https://foo.rpc"


def test_unknown_network_lists_options():
    with pytest.raises(ValueError) as e:
        fetch.rpc_url_for("nonesuch-chain")
    assert "ethereum" in str(e.value)


def test_address_validation():
    assert fetch.is_address("0x" + "ab" * 20)
    assert not fetch.is_address("0x123")
    assert not fetch.is_address("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")  # no 0x


def test_fetch_rejects_bad_address():
    with pytest.raises(ValueError):
        fetch.fetch_code("ethereum", "0xnothex")
