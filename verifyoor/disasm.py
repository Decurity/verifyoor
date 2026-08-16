"""Pure-python EVM disassembler (linear scan, push-data aware — EVM jumpdest semantics)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set

_NAMES: Dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
    0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE",
    0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR", 0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
    0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
    0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
    0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE",
    0x5A: "GAS", 0x5B: "JUMPDEST", 0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY", 0x5F: "PUSH0",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
for _n in range(1, 33):
    _NAMES[0x5F + _n] = "PUSH%d" % _n
for _n in range(1, 17):
    _NAMES[0x7F + _n] = "DUP%d" % _n
    _NAMES[0x8F + _n] = "SWAP%d" % _n
for _n in range(5):
    _NAMES[0xA0 + _n] = "LOG%d" % _n


@dataclass
class Op:
    pc: int
    opcode: int
    name: str
    imm: Optional[bytes] = None  # push immediate, if any

    @property
    def imm_int(self) -> Optional[int]:
        return int.from_bytes(self.imm, "big") if self.imm is not None else None

    def __str__(self) -> str:
        if self.imm is not None:
            return "%s 0x%s" % (self.name, self.imm.hex())
        return self.name


def disassemble(code: bytes) -> List[Op]:
    ops: List[Op] = []
    pc = 0
    n = len(code)
    while pc < n:
        b = code[pc]
        name = _NAMES.get(b, "UNKNOWN_%02x" % b)
        if 0x60 <= b <= 0x7F:
            width = b - 0x5F
            imm = code[pc + 1 : pc + 1 + width]
            if len(imm) < width:  # truncated push at end of code
                imm = imm + b"\x00" * (width - len(imm))
            ops.append(Op(pc, b, name, imm))
            pc += 1 + width
        else:
            ops.append(Op(pc, b, name))
            pc += 1
    return ops


def jumpdests(code: bytes) -> Set[int]:
    """Valid JUMPDEST pcs under EVM semantics (push-data excluded)."""
    return {op.pc for op in disassemble(code) if op.opcode == 0x5B}


def render_range(code: bytes, lo: Optional[int] = None, hi: Optional[int] = None) -> List[str]:
    """`pc: OPCODE [imm]` lines for ops whose pc is in [lo, hi) (defaults: whole code)."""
    lo = 0 if lo is None else lo
    hi = len(code) if hi is None else hi
    return ["0x%04x  %s" % (op.pc, op) for op in disassemble(code) if lo <= op.pc < hi]
