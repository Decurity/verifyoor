"""Intra-block IR lift: stack semantics, temp/let policy, block splitting, diff integration."""
import unittest

from verifyoor.disasm import disassemble
from verifyoor.lift import Lifter, lift_block, split_blocks
from verifyoor.normdiff import diff


def _lift_one(hexcode: str):
    blocks = split_blocks(disassemble(bytes.fromhex(hexcode)))
    assert len(blocks) == 1, "expected a single block"
    return lift_block(blocks[0])


class TestLiftBlock(unittest.TestCase):
    def test_mstore_simple(self):
        # PUSH1 0x80 PUSH1 0x40 MSTORE — the free-pointer init
        b = _lift_one("6080604052")
        self.assertEqual(b.lines, ["0x4: mstore(0x40, 0x80)"])
        self.assertEqual(b.n_inputs, 0)
        self.assertEqual(b.exit_stack, [])

    def test_underflow_becomes_inputs(self):
        # bare ADD: both operands come from the entry stack, in0 = entry top
        b = _lift_one("01")
        self.assertEqual(b.lines, [])
        self.assertEqual(b.n_inputs, 2)
        self.assertEqual(b.exit_stack, ["add(in0, in1)"])

    def test_dup_pure_inlines(self):
        # PUSH1 05 DUP1 MUL — pure value duplicated inline, no temp
        b = _lift_one("60058002")
        self.assertEqual(b.exit_stack, ["mul(0x05, 0x05)"])
        self.assertEqual(b.lines, [])

    def test_swap_order(self):
        # PUSH1 01 PUSH1 02 SWAP1 SUB — args render in pop order (top first)
        b = _lift_one("6001600290 03".replace(" ", ""))
        self.assertEqual(b.exit_stack, ["sub(0x01, 0x02)"])

    def test_swap_deep_underflow(self):
        # bare SWAP2 reveals three entry slots and reorders them
        b = _lift_one("91")
        self.assertEqual(b.n_inputs, 3)
        self.assertEqual(b.exit_stack, ["in2", "in1", "in0"])

    def test_sload_inlines_without_interference(self):
        # PUSH1 00 SLOAD PUSH1 01 SSTORE — single use, nothing clobbers storage before it
        b = _lift_one("6000546001 55".replace(" ", ""))
        self.assertEqual(b.lines, ["0x5: sstore(0x01, sload(0x00))"])

    def test_mload_gets_temp_on_interference(self):
        # PUSH1 00 MLOAD, then MSTORE(0,0x2a), then the loaded value is stored:
        # the intervening memory write forces a let at the MLOAD's own pc.
        b = _lift_one("600051602a600052602052")
        self.assertEqual(b.lines, [
            "0x2: let t0 := mload(0x00)",
            "0x7: mstore(0x00, 0x2a)",
            "0xa: mstore(0x20, t0)",
        ])

    def test_impure_multiuse_gets_temp(self):
        # PUSH1 00 SLOAD DUP1 MUL STOP — sload used twice must not be duplicated
        b = _lift_one("6000548002 00".replace(" ", ""))
        self.assertEqual(b.lines, ["0x2: let t0 := sload(0x00)", "0x5: stop()"])
        self.assertEqual(b.exit_stack, ["mul(t0, t0)"])

    def test_discarded_call_renders_as_pop(self):
        b = _lift_one("600060006000600060006000fa5000")
        self.assertEqual(b.lines, [
            "0xc: pop(staticcall(0x00, 0x00, 0x00, 0x00, 0x00, 0x00))",
            "0xe: stop()",
        ])

    def test_used_call_gets_let(self):
        # STATICCALL result consumed by SSTORE
        b = _lift_one("600060006000600060006000fa60005500")
        self.assertEqual(b.lines, [
            "0xc: let t0 := staticcall(0x00, 0x00, 0x00, 0x00, 0x00, 0x00)",
            "0xf: sstore(0x00, t0)",
            "0x10: stop()",
        ])

    def test_pc_folds_to_constant(self):
        # PUSH1 00 PC ADD — PC is a fixed number at its site
        b = _lift_one("600058 01".replace(" ", ""))
        self.assertEqual(b.exit_stack, ["add(0x02, 0x00)"])

    def test_ascii_note_on_string_word(self):
        # PUSH32 "insufficient" left-aligned — decoded inline for the reader
        word = b"insufficient".ljust(32, b"\x00").hex()
        b = _lift_one("7f" + word)
        self.assertIn('/* "insufficient" */', b.exit_stack[0])

    def test_unknown_opcode_terminates(self):
        b = _lift_one("60010c")  # 0x0c is unassigned
        self.assertEqual(b.lines, ["0x2: unknown_0x0c()"])
        self.assertFalse(b.falls_through)


class TestBlocksAndLifter(unittest.TestCase):
    def test_split_on_jumpdest_and_terminator(self):
        # JUMPDEST PUSH1 00 JUMP | JUMPDEST STOP
        blocks = split_blocks(disassemble(bytes.fromhex("5b6000565b00")))
        self.assertEqual([b[0].pc for b in blocks], [0, 4])
        lifted = lift_block(blocks[0])
        self.assertEqual(lifted.lines, ["0x3: jump(0x00)"])
        self.assertTrue(lifted.is_jumpdest)
        self.assertFalse(lifted.falls_through)

    def test_jumpi_falls_through(self):
        # PUSH1 00 PUSH1 01 JUMPI STOP — JUMPI ends the block but falls through
        blocks = split_blocks(disassemble(bytes.fromhex("6000600157" "00")))
        self.assertEqual(len(blocks), 2)
        lifted = lift_block(blocks[0])
        self.assertEqual(lifted.lines, ["0x4: jumpi(0x01, 0x00)"])
        self.assertTrue(lifted.falls_through)
        self.assertEqual(lifted.next_pc, 5)

    def test_lift_range_covers_enclosing_block(self):
        code = bytes.fromhex("5b6000565b6001600155" "00")
        lifter = Lifter(disassemble(code))
        # pc 8 is inside the second block (starts at 4)
        lines = lifter.lift_range(8, 8)
        self.assertTrue(lines[0].startswith("block 0x4"))
        self.assertIn("0x9: sstore(0x01, 0x01)", [l.strip() for l in lines])


class TestNormdiffIntegration(unittest.TestCase):
    def test_regions_carry_lifted_ir(self):
        # identical except ADD (target) vs MUL (candidate) feeding an SSTORE
        target = bytes.fromhex("5b60016002 01 600055 00".replace(" ", ""))
        candidate = bytes.fromhex("5b60016002 02 600055 00".replace(" ", ""))
        nd = diff(target, candidate)
        self.assertFalse(nd.match)
        region = nd.regions[0]
        self.assertIn("sstore(0x00, add(0x02, 0x01))", " ".join(region.expected_ir))
        self.assertIn("sstore(0x00, mul(0x02, 0x01))", " ".join(region.got_ir))
        rendered = region.render()
        self.assertIn("expected IR", rendered)
        self.assertIn("got IR", rendered)

    def test_match_has_no_regions(self):
        code = bytes.fromhex("5b600160020160005500")
        nd = diff(code, code)
        self.assertTrue(nd.match)
        self.assertEqual(nd.regions, [])


if __name__ == "__main__":
    unittest.main()
