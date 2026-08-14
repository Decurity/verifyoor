"""evmole enrichment: per-selector argument types + state mutability."""
import importlib.util
import unittest

from verifyoor.analyze import SelectorEntry, analyze
from verifyoor.util import load_bytecode

_HAS_EVMOLE = importlib.util.find_spec("evmole") is not None


class TestMintSignature(unittest.TestCase):
    """mint_signature is pure logic — no evmole needed."""

    def test_mint_signature(self):
        e = SelectorEntry("2247831f", 0x10c, arguments="address[],uint256[],uint256[],uint256[]")
        self.assertEqual(e.mint_signature(), "(address[],uint256[],uint256[],uint256[])")

    def test_mint_signature_no_args(self):
        self.assertEqual(SelectorEntry("12065fe0", 0xe2, arguments="").mint_signature(), "()")


@unittest.skipUnless(_HAS_EVMOLE, "evmole not installed")
class TestEvmoleEnrichment(unittest.TestCase):
    def test_enriches_args_and_mutability(self):
        a = analyze(load_bytecode("tests/fixtures/sample.hex"))
        self.assertTrue(a.evmole_available)
        by_sel = {s.selector: s for s in a.selectors}
        init = by_sel["c4d66de8"]  # initialize(address)
        self.assertEqual(init.arguments, "address")
        self.assertIn(init.state_mutability, ("nonpayable", "payable", "view", "pure"))
        getter = by_sel["b269681d"]  # destination() getter
        self.assertEqual(getter.arguments, "")
        self.assertEqual(getter.state_mutability, "view")

    def test_to_dict_carries_evmole_fields(self):
        a = analyze(load_bytecode("tests/fixtures/sample.hex"))
        d = a.selectors[0].to_dict()
        for k in ("arguments", "state_mutability"):
            self.assertIn(k, d)

    def test_storage_layout_types_and_slots(self):
        # counter_unopt: slot 0 uint256 (the counter), slot 1 address
        a = analyze(load_bytecode("tests/fixtures/counter_unopt.hex"))
        layout = {v.slot: v for v in a.storage}
        self.assertEqual(layout[0].type, "uint256")
        self.assertEqual(layout[1].type, "address")
        # sorted in declaration order (slot, then packing offset)
        self.assertEqual([v.slot for v in a.storage], sorted(v.slot for v in a.storage))
        # writers are recorded as selectors
        self.assertTrue(layout[0].writes)
        self.assertIn("slot", layout[0].to_dict())

    def test_storage_recovers_nested_mappings(self):
        a = analyze(load_bytecode("tests/fixtures/vault.hex"))
        types = {v.slot: v.type for v in a.storage}
        self.assertEqual(types[0], "mapping(address => uint128)")
        self.assertEqual(types[1], "mapping(address => mapping(address => uint256))")


if __name__ == "__main__":
    unittest.main()
