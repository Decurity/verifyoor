"""evmole CFG: successor parsing, block graph, and lift edge-resolution."""
import importlib.util
import unittest

from verifyoor.cfg import Cfg, _succs_of
from verifyoor.disasm import disassemble
from verifyoor.lift import Lifter, split_blocks
from verifyoor.util import load_bytecode

_HAS_EVMOLE = importlib.util.find_spec("evmole") is not None


class _Jump:
    def __init__(self, to): self.to = to


class _Jumpi:
    def __init__(self, t, f): self.true_to, self.false_to = t, f


class _E:
    def __init__(self, to): self.to = to


class _Dyn:
    def __init__(self, tos): self.to = [_E(t) for t in tos]


class TestSuccsParsing(unittest.TestCase):
    """_succs_of handles each evmole block-type shape — pure logic, no evmole."""

    def test_static_jump(self):
        self.assertEqual(_succs_of(_Jump(0x2a5)), {0x2a5})

    def test_conditional(self):
        self.assertEqual(_succs_of(_Jumpi(0x33, 0x1b4)), {0x33, 0x1b4})

    def test_dynamic_jump_list(self):
        self.assertEqual(_succs_of(_Dyn([167, 491, 167])), {167, 491})


@unittest.skipUnless(_HAS_EVMOLE, "evmole not installed")
class TestCfgFromCode(unittest.TestCase):
    def _stripped(self, name):
        from verifyoor import metadata
        code = load_bytecode("tests/fixtures/%s.hex" % name)
        md = metadata.parse_trailing(code)
        return code[: md.start] if md.present else code

    def test_blocks_and_lookup(self):
        cfg = Cfg.from_code(self._stripped("sample"))
        self.assertTrue(cfg.blocks)
        # block_at finds the containing block; succs are resolved starts
        some = next(iter(cfg.blocks.values()))
        self.assertIs(cfg.block_at(some.start), some)
        self.assertIsNone(cfg.block_at(-1))

    def test_boundaries_align_with_lift(self):
        # every evmole block boundary must be a lift block boundary, so a dynamic
        # jump's pc maps cleanly onto its CFG block
        stripped = self._stripped("vault")
        cfg = Cfg.from_code(stripped)
        lift_starts = {b[0].pc for b in split_blocks(disassemble(stripped))}
        self.assertTrue(set(cfg.blocks) <= lift_starts)

    def test_reachable_includes_entry(self):
        cfg = Cfg.from_code(self._stripped("sample"))
        entry = min(cfg.blocks)
        self.assertIn(entry, cfg.reachable(entry))


@unittest.skipUnless(_HAS_EVMOLE, "evmole not installed")
class TestLiftEdgeResolution(unittest.TestCase):
    def _lifter(self, name):
        from verifyoor import metadata
        code = load_bytecode("tests/fixtures/%s.hex" % name)
        md = metadata.parse_trailing(code)
        stripped = code[: md.start] if md.present else code
        ops = disassemble(stripped)
        return Lifter(ops, cfg=Cfg.from_code(stripped))

    def test_dynamic_jumps_get_resolved(self):
        lifter = self._lifter("sample")
        resolved = [lifter._lifted(i) for i in range(len(lifter._blocks))]
        resolved = [b for b in resolved if b.resolved_succs]
        self.assertTrue(resolved, "expected at least one CFG-resolved dynamic jump")
        for b in resolved:
            self.assertIsNotNone(b.dyn_jump_pc)
            # the resolved-successor annotation renders
            self.assertTrue(any("resolved by evmole" in ln for ln in b.render()))

    def test_shared_helper_resolves_to_multiple_targets(self):
        # rescuer_viair has a shared helper reached from >1 caller
        lifter = self._lifter("rescuer_viair")
        multi = [b for i in range(len(lifter._blocks))
                 for b in [lifter._lifted(i)] if b.resolved_succs and len(b.resolved_succs) > 1]
        self.assertTrue(multi, "expected a shared helper with multiple resolved targets")

    def test_without_cfg_no_resolution(self):
        from verifyoor import metadata
        code = load_bytecode("tests/fixtures/sample.hex")
        md = metadata.parse_trailing(code)
        stripped = code[: md.start] if md.present else code
        lifter = Lifter(disassemble(stripped))  # no cfg
        self.assertTrue(all(lifter._lifted(i).resolved_succs is None
                            for i in range(len(lifter._blocks))))


if __name__ == "__main__":
    unittest.main()
