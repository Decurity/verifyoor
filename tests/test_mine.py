"""Selector-name minting: any name that hashes to the selector is byte-equivalent."""
import unittest

from verifyoor.mine import _mine_external, find_external_miner, mine
from verifyoor.util import selector_of


class TestMine(unittest.TestCase):
    def test_mines_name_for_known_small_target(self):
        # Construct a target reachable within a few iterations of a fixed prefix,
        # so the parallel search plumbing is exercised without a 2^32 wait.
        # backend="python" pins the pure-Python scan (which starts at nonce 0),
        # so this is deterministic whether or not an external miner is installed.
        argtypes = "(address[],uint256[])"
        target = selector_of("t_7" + argtypes)
        name = mine(target, argtypes, prefix="t_", backend="python")
        # Some n <= 7 hits (an earlier collision is fine); the selector must match.
        self.assertEqual(selector_of(name + argtypes), target)
        self.assertTrue(name.startswith("t_"))

    def test_default_prefix_is_selector_scoped(self):
        argtypes = "(uint256)"
        target = selector_of("pfx_3" + argtypes)
        name = mine(target, argtypes, prefix="pfx_", backend="python")
        self.assertEqual(selector_of(name + argtypes), target)

    def test_canonicalizes_bare_argtypes(self):
        # argtypes given without surrounding parens still works
        target = selector_of("t_2(address)")
        name = mine(target, "address", prefix="t_", backend="python")
        self.assertEqual(selector_of(name + "(address)"), target)


@unittest.skipIf(find_external_miner() is None,
                 "external function-selector-miner not found (set $VERIFYOOR_SELECTOR_MINER)")
class TestExternalBackend(unittest.TestCase):
    def test_external_miner_hits_and_verifies(self):
        argtypes = "(address[],uint256[])"
        target = selector_of("t_100000" + argtypes)  # easy target under prefix "t_"
        name = _mine_external(find_external_miner(), target, argtypes, "t_", 4)
        self.assertEqual(selector_of(name + argtypes), target)

    def test_auto_backend_prefers_external(self):
        argtypes = "(uint256)"
        target = selector_of("t_50000" + argtypes)
        name = mine(target, argtypes, prefix="t_", backend="external")
        self.assertEqual(selector_of(name + argtypes), target)


if __name__ == "__main__":
    unittest.main()
