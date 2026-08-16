"""render_range() windowing and the CLI pc-range parser."""
from verifyoor.cli import _parse_range
from verifyoor.disasm import render_range

# PUSH1 0x01 (0-1), PUSH1 0x02 (2-3), ADD (4), STOP (5)
CODE = bytes.fromhex("6001" "6002" "01" "00")


def test_render_range_full():
    lines = render_range(CODE)
    assert lines[0] == "0x0000  PUSH1 0x01"
    assert lines[-1] == "0x0005  STOP"
    assert len(lines) == 4


def test_render_range_window_excludes_out_of_range():
    lines = render_range(CODE, 0x02, 0x05)  # PUSH1 0x02, ADD  (STOP at 0x05 excluded)
    assert lines == ["0x0002  PUSH1 0x02", "0x0004  ADD"]


def test_render_range_open_ended():
    lines = render_range(CODE, 0x04, None)
    assert lines == ["0x0004  ADD", "0x0005  STOP"]


def test_parse_range_dash():
    assert _parse_range("0x5ae-0x8f2") == (0x5AE, 0x8F2)


def test_parse_range_dotdot():
    assert _parse_range("0x10..0x20") == (0x10, 0x20)


def test_parse_range_open():
    assert _parse_range("0x5ae") == (0x5AE, None)


def test_parse_range_none():
    assert _parse_range(None) == (None, None)


def test_parse_range_decimal():
    assert _parse_range("16-32") == (16, 32)
