"""Tests del benchmark — scoring de cobertura, carga de targets, agregados.

Sin red: usan reportes de prueba. Corré:
    python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import benchmark as bench  # noqa: E402


def _finding(title="", category="", evidence=""):
    return {"title": title, "category": category, "evidence": evidence}


def _report(findings, **extra):
    rep = {"findings": findings, "reachable": True, "score": 70,
           "grade": "C", "steps": 5, "usage": {"est_cost_usd": 0.0}}
    rep.update(extra)
    return rep


VULNS = [
    {"id": "sqli", "match": ["sql"]},
    {"id": "xss", "match": ["xss", "cross-site script"]},
    {"id": "hsts", "match": ["hsts", "strict-transport"]},
]


class TestScoring(unittest.TestCase):
    def test_detects_by_keyword(self):
        rep = _report([_finding(title="SQL Injection error-based"),
                       _finding(title="HSTS faltante")])
        sc = bench.score_report(rep, VULNS)
        self.assertIn("sqli", sc["detected"])
        self.assertIn("hsts", sc["detected"])
        self.assertIn("xss", sc["missed"])

    def test_match_is_case_insensitive_and_bilingual(self):
        # 'XSS' en mayúscula y 'Strict-Transport' deben matchear
        rep = _report([_finding(title="Reflected XSS"),
                       _finding(category="missing Strict-Transport-Security")])
        sc = bench.score_report(rep, VULNS)
        self.assertIn("xss", sc["detected"])
        self.assertIn("hsts", sc["detected"])

    def test_searches_all_text_fields(self):
        # la keyword aparece solo en evidence
        rep = _report([_finding(title="hallazgo", evidence="payload sql ' inyectado")])
        sc = bench.score_report(rep, VULNS)
        self.assertIn("sqli", sc["detected"])

    def test_coverage_math(self):
        rep = _report([_finding(title="sql"), _finding(title="xss")])
        sc = bench.score_report(rep, VULNS)
        self.assertEqual(sc["n_expected"], 3)
        self.assertAlmostEqual(sc["coverage"], 2 / 3)

    def test_extra_counts_unmatched_findings(self):
        rep = _report([_finding(title="sql"),
                       _finding(title="directory listing"),
                       _finding(title="server banner leak")])
        sc = bench.score_report(rep, VULNS)
        self.assertEqual(sc["extra"], 2)  # 2 hallazgos no mapean a ningún ground-truth

    def test_one_finding_matches_one_vuln(self):
        # un solo hallazgo no debe contar para dos vulns distintas
        rep = _report([_finding(title="sql and xss in one line")])
        sc = bench.score_report(rep, VULNS)
        # matchea el primero que encuentra; el otro queda missed; extra=0
        self.assertEqual(len(sc["detected"]) + len(sc["missed"]), 3)
        self.assertEqual(sc["extra"], 0)

    def test_empty_findings_zero_coverage(self):
        sc = bench.score_report(_report([]), VULNS)
        self.assertEqual(sc["coverage"], 0.0)
        self.assertEqual(sc["detected"], [])


class TestTargets(unittest.TestCase):
    def test_load_all(self):
        targets = bench.load_targets()
        self.assertTrue(len(targets) >= 1)
        for t in targets:
            self.assertIn("url", t)
            self.assertIn("vulns", t)

    def test_filter_by_name(self):
        targets = bench.load_targets(only=["ginandjuice"])
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["name"], "ginandjuice")

    def test_filter_no_match(self):
        self.assertEqual(bench.load_targets(only=["no-existe-xyz"]), [])


class TestAggregate(unittest.TestCase):
    def test_average_coverage_per_brain(self):
        results = [
            {"brain": "engine", "coverage": 0.5, "time": 10, "cost": 0.0},
            {"brain": "engine", "coverage": 1.0, "time": 20, "cost": 0.0},
            {"brain": "ollama", "coverage": 0.0, "time": 100, "cost": 0.0},
            {"brain": "x", "error": "boom"},  # se ignora
        ]
        agg = bench._aggregate(results)
        self.assertAlmostEqual(agg["engine"]["avg_cov"], 0.75)
        self.assertEqual(agg["engine"]["n"], 2)
        self.assertAlmostEqual(agg["ollama"]["avg_cov"], 0.0)
        self.assertNotIn("x", agg)

    def test_bar_fills_proportionally(self):
        self.assertEqual(bench._bar(0.0, 10), "░" * 10)
        self.assertEqual(bench._bar(1.0, 10), "█" * 10)
        self.assertEqual(bench._bar(0.5, 10), "█" * 5 + "░" * 5)


if __name__ == "__main__":
    unittest.main()
