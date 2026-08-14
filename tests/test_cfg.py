"""evmole CFG: successor parsing, block graph, and lift edge-resolution."""
import importlib.util
import unittest

from verifyoor.cfg import Cfg, _edges_of
from verifyoor.disasm import disassemble
from verifyoor.lift import Lifter, split_blocks
from verifyoor.util import load_bytecode

_HAS_EVMOLE = importlib.util.find_spec("evmole") is not None


class _Jump:
    def __init__(self, to): self.to = to


class _Jumpi:
    def __init__(self, t, f): self.true_to, self.false_to = t, f


class _E:
    def __init__(self, path, to): self.path, self.to = path, to


class _Dyn:
    def __init__(self, edges): self.to = [_E(p, t) for p, t in edges]


class TestEdgeParsing(unittest.TestCase):
    """_edges_of splits static edges from dynamic (path, to) edges — no evmole."""

    def test_static_jump(self):
        self.assertEqual(_edges_of(_Jump(0x2a5)), ({0x2a5}, []))

    def test_conditional(self):
        static, dyn = _edges_of(_Jumpi(0x33, 0x1b4))
        self.assertEqual((static, dyn), ({0x33, 0x1b4}, []))

    def test_dynamic_edges_keep_path(self):
        static, dyn = _edges_of(_Dyn([((0x2ec, 0x2f3), 0x2fc), ((0x2ec, 0x31f), 0x328)]))
        self.assertEqual(static, set())
        self.assertEqual(dyn, [((0x2ec, 0x2f3), 0x2fc), ((0x2ec, 0x31f), 0x328)])


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


@unittest.skipUnless(_HAS_EVMOLE, "evmole not installed")
class TestContextSensitiveAttribution(unittest.TestCase):
    def _setup(self, name):
        from verifyoor import metadata
        from verifyoor.analyze import analyze
        code = load_bytecode("tests/fixtures/%s.hex" % name)
        md = metadata.parse_trailing(code)
        stripped = code[: md.start] if md.present else code
        return analyze(code), Cfg.from_code(stripped)

    def test_function_specific_block_not_leaked_to_other_function(self):
        # sample block 0x374 holds initialize's "Invalid destination" string. The flat
        # CFG leaked it to destination() via the shared revert helper's return fan-out;
        # context-sensitive reach must keep it to initialize only.
        a, cfg = self._setup("sample")
        dest = next(s for s in a.selectors if s.selector == "b269681d").body_offset
        init = next(s for s in a.selectors if s.selector == "c4d66de8").body_offset
        tgt = cfg.block_at(0x374).start
        self.assertIn(tgt, cfg.reachable(cfg.block_at(init).start))
        self.assertNotIn(tgt, cfg.reachable(cfg.block_at(dest).start))

    def test_attributor_labels_function_and_shared(self):
        from verifyoor.cfg import Attributor
        a, cfg = self._setup("sample")
        for s in a.selectors:
            s.signature = {"b269681d": "destination()", "c4d66de8": "initialize(address)"}.get(s.selector)
        att = Attributor(cfg, a.selectors)
        self.assertEqual(att.attribute(0x374), "initialize(address)")  # not "shared helper"
        self.assertEqual(att.attribute(0x00), "dispatcher/prologue")   # falls back off-CFG

    def test_shared_helper_detected(self):
        # a contract with genuinely shared codegen has >=1 block owned by multiple funcs
        from verifyoor.cfg import Attributor
        a, cfg = self._setup("counter_unopt")
        att = Attributor(cfg, a.selectors)
        labels = {att.attribute(b) for b in cfg.blocks}
        self.assertIn("shared helper", labels)

    def test_attribution_without_cfg_uses_offset_heuristic(self):
        from verifyoor.cfg import Attributor
        a, _ = self._setup("sample")
        for s in a.selectors:
            s.signature = {"b269681d": "destination()", "c4d66de8": "initialize(address)"}.get(s.selector)
        att = Attributor(None, a.selectors)  # no cfg -> offset fallback still names a function
        self.assertIn("initialize", att.attribute(0x160))


if __name__ == "__main__":
    unittest.main()
