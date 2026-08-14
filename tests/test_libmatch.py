"""Library-version/settings sweep by basic-block fingerprint. Pure logic tested with
an injected in-memory fetcher — no live network calls."""
import unittest

from verifyoor.compile import Settings
from verifyoor.libmatch import (
    _normalize_path,
    block_bytes,
    block_fingerprint,
    resolve_package_files,
)
from verifyoor.util import load_bytecode


def _fake_fetcher(files):
    """files: {version: {path: source}}"""
    def fetch(version, path):
        return files.get(version, {}).get(path)
    return fetch


class TestPathNormalization(unittest.TestCase):
    def test_relative_dot_slash(self):
        self.assertEqual(_normalize_path("access/Ownable2Step.sol", "./Ownable.sol"), "access/Ownable.sol")

    def test_relative_dotdot(self):
        self.assertEqual(_normalize_path("access/Ownable2Step.sol", "../utils/Context.sol"), "utils/Context.sol")

    def test_no_base(self):
        self.assertEqual(_normalize_path("", "utils/Context.sol"), "utils/Context.sol")


class TestResolvePackageFiles(unittest.TestCase):
    def test_transitive_relative_imports(self):
        fetcher = _fake_fetcher({
            "5.3.0": {
                "access/Ownable2Step.sol": 'import "./Ownable.sol";\ncontract Ownable2Step {}',
                "access/Ownable.sol": 'import "../utils/Context.sol";\ncontract Ownable {}',
                "utils/Context.sol": "abstract contract Context {}",
            }
        })
        files = resolve_package_files(fetcher, "5.3.0", "access/Ownable2Step.sol", "@openzeppelin/contracts/")
        self.assertEqual(set(files), {"access/Ownable2Step.sol", "access/Ownable.sol", "utils/Context.sol"})

    def test_transitive_absolute_package_imports(self):
        fetcher = _fake_fetcher({
            "5.3.0": {
                "access/Ownable2Step.sol": 'import "@openzeppelin/contracts/access/Ownable.sol";\ncontract A {}',
                "access/Ownable.sol": "contract Ownable {}",
            }
        })
        files = resolve_package_files(fetcher, "5.3.0", "access/Ownable2Step.sol", "@openzeppelin/contracts/")
        self.assertEqual(set(files), {"access/Ownable2Step.sol", "access/Ownable.sol"})

    def test_missing_file_returns_none(self):
        fetcher = _fake_fetcher({"5.3.0": {"access/Ownable2Step.sol": 'import "./Missing.sol";'}})
        self.assertIsNone(resolve_package_files(fetcher, "5.3.0", "access/Ownable2Step.sol", "@openzeppelin/contracts/"))

    def test_ignores_unrelated_external_package(self):
        # an import from a different package (no prefix match, no relative path) is
        # left alone — out of scope for a single-package sweep, not an error
        fetcher = _fake_fetcher({
            "1.0.0": {"A.sol": 'import "some-other-lib/Thing.sol";\ncontract A {}'},
        })
        files = resolve_package_files(fetcher, "1.0.0", "A.sol", "@openzeppelin/contracts/")
        self.assertEqual(set(files), {"A.sol"})


class TestBlockFingerprint(unittest.TestCase):
    def test_context_independent_block_matches_across_programs(self):
        # the same getter core (SLOAD, mask, AND, JUMP) compiled standalone vs
        # embedded after unrelated preceding code must fingerprint identically —
        # this is the property the whole technique depends on.
        core = bytes.fromhex("5b5f5473ffffffffffffffffffffffffffffffffffffffff1660015700")
        # core prefixed by unrelated code (own JUMPDEST/STOP) — different pc, same block content
        embedded = bytes.fromhex("5b00") + core
        fp_a = block_fingerprint(core)
        fp_b = block_fingerprint(embedded)
        self.assertTrue(fp_a & fp_b, "identical block content must produce a shared fingerprint")

    def test_trivial_blocks_excluded(self):
        # a single STOP is a 1-token block — below the length floor
        fp = block_fingerprint(bytes.fromhex("00"))
        self.assertEqual(fp, set())

    def test_real_fixture_has_blocks(self):
        code = load_bytecode("tests/fixtures/sample.hex")
        fp = block_fingerprint(code)
        self.assertTrue(fp)
        self.assertTrue(all(len(b) >= 3 for b in fp))

    def test_block_bytes_positive_for_nonempty(self):
        code = load_bytecode("tests/fixtures/sample.hex")
        fp = block_fingerprint(code)
        self.assertGreater(block_bytes(fp), 0)
        self.assertEqual(block_bytes(set()), 0)


class TestSettingsDescribe(unittest.TestCase):
    def test_settings_has_describe(self):
        # sanity: sweep_versions ranks/reports via Settings.describe()
        s = Settings(optimizer_enabled=True, optimizer_runs=10000)
        self.assertIn("10000", s.describe())


if __name__ == "__main__":
    unittest.main()
