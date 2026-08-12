"""Deterministic end-to-end gate (no LLM): the oracle source must verify against
its bytecode, and each harder fixture must round-trip through the settings sweep."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")


def run_verify(solfile, hexfile, *extra):
    cmd = [sys.executable, "-m", "verifyoor", "verify", solfile, hexfile, "--sweep", "--offline", *extra]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def test_sample_verifies():
    r = run_verify(os.path.join(ROOT, "test.sol"), os.path.join(ROOT, "test.hex"), "--out", "/tmp/vy_sample")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["match"] is True
    assert out["contract"] == "Test"


def _fixture_names():
    mani = os.path.join(FIX, "manifest.json")
    if not os.path.exists(mani):
        return []
    return list(json.load(open(mani)).keys())


@pytest.mark.parametrize("name", _fixture_names())
def test_fixture_roundtrip(name):
    sol = os.path.join(FIX, name + ".sol")
    hexf = os.path.join(FIX, name + ".hex")
    r = run_verify(sol, hexf, "--out", "/tmp/vy_" + name)
    assert r.returncode == 0, "%s did not verify:\n%s" % (name, r.stderr)
    assert json.loads(r.stdout)["match"] is True


def test_wrong_source_does_not_match():
    # a materially different contract must NOT falsely verify
    bad = os.path.join("/tmp", "vy_bad.sol")
    with open(bad, "w") as f:
        f.write("pragma solidity 0.8.20;\ncontract X { uint256 public y; function f() external { y = 1; } }\n")
    r = run_verify(bad, os.path.join(ROOT, "test.hex"))
    assert r.returncode == 1
