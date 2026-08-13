import pytest

from verifyoor.submit import build_standard_input, chain_id_for, solc_long_version


def test_chain_id_for():
    assert chain_id_for("ethereum") == 1
    assert chain_id_for("mainnet") == 1
    assert chain_id_for("base") == 8453
    assert chain_id_for("137") == 137  # numeric passthrough
    with pytest.raises(ValueError):
        chain_id_for("nonesuch-chain")


def test_build_standard_input_embeds_settings():
    std = build_standard_input(
        "contract C {}", {"optimizer": {"enabled": True, "runs": 200}, "evmVersion": "paris"}
    )
    assert std["language"] == "Solidity"
    assert std["sources"]["source.sol"]["content"] == "contract C {}"
    # the whole point: evmVersion/optimizer are embedded so a verifier can't default them
    assert std["settings"]["evmVersion"] == "paris"
    assert std["settings"]["optimizer"] == {"enabled": True, "runs": 200}
    assert "outputSelection" in std["settings"]


def test_solc_long_version_has_commit():
    # needs an installed solc (0.8.20 is a fixture dependency)
    v = solc_long_version("0.8.20")
    assert v.startswith("0.8.20+commit.")
