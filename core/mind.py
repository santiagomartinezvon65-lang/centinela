"""Centinela Mind — el cerebro entrenable, en Python puro (sin dependencias).

No es un LLM rentado: es un modelo que ENTRENAMOS nosotros. Una regresión
logística (perceptrón con sigmoide) que aprende, a partir de señales de una
request/response, qué tan probable es que un parámetro sea explotable. Se
entrena con datos de las propias corridas del scanner y se guarda en un .json.

Cuanto más corre el scanner, más datos juntás, mejor predice → la "IA propia"
que mejora sola. Solo usa `math` de la librería estándar.
"""
from __future__ import annotations

import json
import math
import random

# Señales (features) que describen un parámetro candidato. Orden fijo: es el
# vector de entrada del modelo. Agregar features = reentrenar.
FEATURES = [
    "reflected",        # el valor se refleja en la respuesta (eco)
    "sql_error",        # apareció una firma de error SQL al inyectar '
    "status_changed",   # cambió el status HTTP respecto del baseline
    "len_delta",        # cambio normalizado del tamaño del body [0..1]
    "content_type_html",# la respuesta es HTML (más superficie XSS)
    "name_hint",        # el nombre del parámetro sugiere consulta (id, q, cat…) [0..1]
    "numeric_value",    # el valor original es numérico (típico de id de DB)
    "error_on_quote",   # 5xx o traza al inyectar una comilla
]

_HINT_WORDS = ("id", "cat", "category", "q", "query", "search", "s", "page",
               "user", "name", "item", "product", "pid", "uid", "order", "sort")


def featurize(signal: dict) -> list[float]:
    """dict de señales → vector de floats en el orden de FEATURES (tolerante)."""
    return [float(signal.get(name, 0) or 0) for name in FEATURES]


def name_hint(param: str) -> float:
    """Heurística [0..1]: ¿el nombre del parámetro huele a consulta de DB?"""
    p = (param or "").lower()
    if p in _HINT_WORDS:
        return 1.0
    if any(w in p for w in _HINT_WORDS):
        return 0.6
    return 0.0


def _sigmoid(z: float) -> float:
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


class LogisticModel:
    """Regresión logística entrenada por descenso de gradiente. Pura stdlib."""

    def __init__(self, n_features: int | None = None,
                 weights: list[float] | None = None, bias: float = 0.0):
        n = n_features if n_features is not None else len(FEATURES)
        self.w = list(weights) if weights is not None else [0.0] * n
        self.b = bias

    def predict_proba(self, x: list[float]) -> float:
        z = self.b + sum(wi * xi for wi, xi in zip(self.w, x))
        return _sigmoid(z)

    def predict(self, x: list[float], threshold: float = 0.5) -> int:
        return int(self.predict_proba(x) >= threshold)

    def train(self, X: list[list[float]], y: list[int], *, epochs: int = 400,
              lr: float = 0.3, l2: float = 0.001, seed: int = 0) -> dict:
        """Entrena in-place. Devuelve métricas finales (loss, accuracy)."""
        if not X:
            raise ValueError("no hay datos de entrenamiento")
        n = len(X[0])
        if len(self.w) != n:
            self.w = [0.0] * n
        rnd = random.Random(seed)
        idx = list(range(len(X)))
        for _ in range(epochs):
            rnd.shuffle(idx)
            for i in idx:
                x, target = X[i], y[i]
                pred = self.predict_proba(x)
                err = pred - target
                for j in range(n):
                    self.w[j] -= lr * (err * x[j] + l2 * self.w[j])
                self.b -= lr * err
        return self.evaluate(X, y)

    def evaluate(self, X: list[list[float]], y: list[int]) -> dict:
        loss = 0.0
        correct = 0
        tp = fp = fn = 0
        for x, target in zip(X, y):
            p = self.predict_proba(x)
            eps = 1e-12
            loss -= target * math.log(p + eps) + (1 - target) * math.log(1 - p + eps)
            pred = int(p >= 0.5)
            correct += int(pred == target)
            if pred == 1 and target == 1:
                tp += 1
            elif pred == 1 and target == 0:
                fp += 1
            elif pred == 0 and target == 1:
                fn += 1
        n = len(X)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)
        return {"loss": round(loss / n, 4), "accuracy": round(correct / n, 4),
                "precision": round(precision, 4), "recall": round(recall, 4),
                "f1": round(f1, 4), "n": n}

    def weight_report(self) -> list[tuple[str, float]]:
        """Pesos por feature, ordenados por importancia (para interpretarlo)."""
        pairs = list(zip(FEATURES, self.w))
        return sorted(pairs, key=lambda kv: -abs(kv[1]))

    # ── persistencia ────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {"features": FEATURES, "weights": self.w, "bias": self.b}

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> "LogisticModel":
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        if d.get("features") != FEATURES:
            raise ValueError("el modelo guardado tiene features distintas; reentrená")
        return cls(weights=d["weights"], bias=d.get("bias", 0.0))
