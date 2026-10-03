#!/usr/bin/env python3

from pathlib import Path
import unittest

from RenderFormula import render_formula


class RenderFormulaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = (Path(__file__).parent / "binjad.rb.in").read_text(encoding="utf-8")

    def test_stable_formula(self):
        rendered = render_formula(self.template, "6.0.10601", "1" * 40, "0.2.0", "stable")
        self.assertIn("class BinjadAT6010601 < Formula", rendered)
        self.assertIn('revision: "' + "1" * 40 + '"', rendered)
        self.assertIn('version "0.2.0"', rendered)
        self.assertIn("requires Binary Ninja 6.0.10601 and", rendered)
        self.assertNotIn("development formula", rendered)
        self.assertNotRegex(rendered, r"@BINJAD_[A-Z0-9_]+@")

    def test_development_formula(self):
        rendered = render_formula(self.template, "6.1.10811", "2" * 40, "0.2.0", "dev")
        self.assertIn("class BinjadAT6110811 < Formula", rendered)
        self.assertIn("requires Binary Ninja 6.1.10811 development build", rendered)
        self.assertIn("shares its service and configuration with stable binjad", rendered)

    def test_invalid_source_revision(self):
        with self.assertRaisesRegex(ValueError, "full lowercase Git SHA"):
            render_formula(self.template, "6.1.10811", "abc", "0.2.0", "dev")


if __name__ == "__main__":
    unittest.main()
