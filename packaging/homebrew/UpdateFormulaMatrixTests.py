#!/usr/bin/env python3

import unittest

from UpdateFormulaMatrix import add_formula


class UpdateFormulaMatrixTests(unittest.TestCase):
    def matrix(self):
        return {
            "schema": 1,
            "binjadVersion": "0.2.0",
            "formulaRevision": 0,
            "stable": "6.0.10601",
            "latestDev": None,
            "formulas": {
                "6.0.10601": {
                    "channel": "stable",
                    "apiRevision": "1" * 40,
                    "sourceRevision": "2" * 40,
                }
            },
        }

    def test_adds_and_selects_latest_development_formula(self):
        matrix = self.matrix()
        self.assertTrue(add_formula(matrix, "dev", "6.1.10811", "3" * 40, "4" * 40, "0.2.0"))
        self.assertEqual(matrix["latestDev"], "6.1.10811")
        self.assertEqual(matrix["formulas"]["6.1.10811"]["channel"], "dev")

    def test_identical_record_is_idempotent(self):
        matrix = self.matrix()
        add_formula(matrix, "dev", "6.1.10811", "3" * 40, "4" * 40, "0.2.0")
        self.assertFalse(add_formula(matrix, "dev", "6.1.10811", "3" * 40, "4" * 40, "0.2.0"))

    def test_rejects_mixed_binjad_versions(self):
        with self.assertRaisesRegex(ValueError, "different binjad version"):
            add_formula(self.matrix(), "dev", "6.1.10811", "3" * 40, "4" * 40, "0.2.1")


if __name__ == "__main__":
    unittest.main()
