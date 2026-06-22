"""Tests del cerebro entrenable (core/mind.py) — sin red, deterministas."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import mind  # noqa: E402


class TestFeaturize(unittest.TestCase):
    def test_vector_length_and_order(self):
        v = mind.featurize({})
        self.assertEqual(len(v), len(mind.FEATURES))
        self.assertTrue(all(x == 0.0 for x in v))

    def test_reads_known_signals(self):
        sig = {"reflected": True, "sql_error": 1, "len_delta": 0.5}
        v = mind.featurize(sig)
        self.assertEqual(v[mind.FEATURES.index("reflected")], 1.0)
        self.assertEqual(v[mind.FEATURES.index("sql_error")], 1.0)
        self.assertEqual(v[mind.FEATURES.index("len_delta")], 0.5)

    def test_name_hint(self):
        self.assertEqual(mind.name_hint("id"), 1.0)
        self.assertEqual(mind.name_hint("productId"), 0.6)
        self.assertEqual(mind.name_hint("zzz"), 0.0)


class TestLearning(unittest.TestCase):
    def test_learns_separable_pattern(self):
        # Patrón sintético: inyectable si hay sql_error O (reflected y error_on_quote).
        ie = mind.FEATURES.index("sql_error")
        ir = mind.FEATURES.index("reflected")
        iq = mind.FEATURES.index("error_on_quote")
        X, y = [], []
        rng = __import__("random").Random(1)
        for _ in range(300):
            v = [0.0] * len(mind.FEATURES)
            v[ie] = rng.choice([0.0, 1.0])
            v[ir] = rng.choice([0.0, 1.0])
            v[iq] = rng.choice([0.0, 1.0])
            label = 1 if (v[ie] == 1.0 or (v[ir] == 1.0 and v[iq] == 1.0)) else 0
            X.append(v)
            y.append(label)
        m = mind.LogisticModel()
        metrics = m.train(X, y, epochs=300, lr=0.3, seed=0)
        self.assertGreater(metrics["accuracy"], 0.9)
        # debe predecir inyectable cuando hay error SQL
        sig = {"sql_error": 1}
        self.assertEqual(m.predict(mind.featurize(sig)), 1)
        # y NO inyectable cuando no hay ninguna señal
        self.assertEqual(m.predict(mind.featurize({})), 0)

    def test_empty_training_raises(self):
        with self.assertRaises(ValueError):
            mind.LogisticModel().train([], [])

    def test_weight_report_sorted(self):
        m = mind.LogisticModel(weights=[0.1, -5.0, 0.0, 2.0, 0, 0, 0, 0], bias=0)
        rep = m.weight_report()
        self.assertEqual(rep[0][0], "sql_error")  # |−5| es el mayor


class TestPersistence(unittest.TestCase):
    def test_save_load_roundtrip(self):
        m = mind.LogisticModel(weights=[1.0] * len(mind.FEATURES), bias=0.5)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.json")
            m.save(p)
            m2 = mind.LogisticModel.load(p)
            self.assertEqual(m2.w, m.w)
            self.assertEqual(m2.b, m.b)
            x = mind.featurize({"reflected": 1})
            self.assertAlmostEqual(m2.predict_proba(x), m.predict_proba(x))

    def test_load_rejects_mismatched_features(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"features": ["otra"], "weights": [1.0], "bias": 0}, fh)
            with self.assertRaises(ValueError):
                mind.LogisticModel.load(p)


if __name__ == "__main__":
    unittest.main()
