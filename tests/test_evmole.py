"""evmole enrichment: arg types + mutability, and DB-name collision detection."""
import importlib.util
import unittest

from verifyoor.analyze import SelectorEntry, analyze
from verifyoor.util import load_bytecode

_HAS_EVMOLE = importlib.util.find_spec("evmole") is not None


class TestConflictLogic(unittest.TestCase):
    """db_name_conflict / mint_signature are pure logic — no evmole needed."""

    def test_conflict_when_arg_types_disagree(self):
        # openchain resolved transfer(address,uint256) but evmole decoded more args
        e = SelectorEntry("a9059cbb", 0x206, signature="transfer(address,uint256)",
                          arguments="address,uint256,(uint256,uint256,uint256)")
        self.assertTrue(e.db_name_conflict)

    def test_no_conflict_when_args_match(self):
        e = SelectorEntry("2e1a7d4d", 0x128, signature="withdraw(uint256)", arguments="uint256")
        self.assertFalse(e.db_name_conflict)

    def test_no_conflict_for_no_arg_getter(self):
        e = SelectorEntry("8da5cb5b", 0x1b4, signature="owner()", arguments="")
        self.assertFalse(e.db_name_conflict)

    def test_whitespace_insensitive(self):
        e = SelectorEntry("00000000", 0, signature="f(address, uint256)", arguments="address,uint256")
        self.assertFalse(e.db_name_conflict)

    def test_no_conflict_without_name_or_without_evmole(self):
        self.assertFalse(SelectorEntry("0", 0, signature=None, arguments="address").db_name_conflict)
        self.assertFalse(SelectorEntry("0", 0, signature="f(address)", arguments=None).db_name_conflict)

    def test_mint_signature(self):
        e = SelectorEntry("2247831f", 0x10c, arguments="address[],uint256[],uint256[],uint256[]")
        self.assertEqual(e.mint_signature(), "(address[],uint256[],uint256[],uint256[])")


@unittest.skipUnless(_HAS_EVMOLE, "evmole not installed (optional dependency)")
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
        for k in ("arguments", "state_mutability", "db_name_conflict"):
            self.assertIn(k, d)


if __name__ == "__main__":
    unittest.main()
