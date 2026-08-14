"""Templated-candidate expansion for the variant sweep."""
import unittest

from verifyoor.template import count_variants, expand, marker_count


class TestTemplate(unittest.TestCase):
    def test_no_markers_is_identity(self):
        t = "contract A {}"
        self.assertEqual(marker_count(t), 0)
        self.assertEqual(count_variants(t), 1)
        self.assertEqual(list(expand(t)), [((), t)])

    def test_single_marker(self):
        t = "x = <<< a ||| b ||| c >>>;"
        self.assertEqual(count_variants(t), 3)
        got = [s for _, s in expand(t)]
        self.assertEqual(got, ["x = a;", "x = b;", "x = c;"])

    def test_cartesian_product(self):
        t = "<<< a ||| b >>>-<<< x ||| y >>>"
        self.assertEqual(count_variants(t), 4)
        combos = [(c, s) for c, s in expand(t)]
        self.assertEqual([s for _, s in combos], ["a-x", "a-y", "b-x", "b-y"])
        self.assertEqual([c for c, _ in combos], [(0, 0), (0, 1), (1, 0), (1, 1)])

    def test_multiline_options_and_stripping(self):
        t = "f() {\n<<<\n  inline;\n|||\n  helper();\n>>>\n}"
        variants = [s for _, s in expand(t)]
        self.assertEqual(len(variants), 2)
        self.assertIn("inline;", variants[0])
        self.assertIn("helper();", variants[1])
        # options are stripped of surrounding whitespace
        self.assertNotIn("|||", variants[0])


if __name__ == "__main__":
    unittest.main()
