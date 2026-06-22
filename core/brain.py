"""Centinela Brain — el pentester con cerebro PROPIO (sin LLM, sin API, sin deps).

No renta un modelo: usa el motor de reglas como base y le suma una capa de
inteligencia que construimos nosotros:
  • descubrimiento de puntos de inyección (parámetros de URL + campos de forms),
  • técnicas que el engine no tiene: SQLi boolean-blind y canary de XSS,
  • un modelo entrenable (core/mind) que puntúa/prioriza cada candidato,
  • registro de muestras etiquetadas para que el modelo APRENDA de cada corrida.

Cuanto más corre, más datos junta → reentrenás → mejor predice. Esa es la
"IA propia que mejora sola". Solo librería estándar.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse

from . import mind
from .engine import LocalPentester, _SQL_ERRORS
from .http import fetch, normalize
from .report import PENALTY, _grade

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MODEL_PATH = os.path.join(DATA_DIR, "mind.json")
SAMPLES_PATH = os.path.join(DATA_DIR, "samples.jsonl")

C = {"crit": "\033[91m", "high": "\033[93m", "ok": "\033[92m", "blue": "\033[96m",
     "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}

_CANARY = "cEnTiNeLa9z"   # token improbable para detectar reflejo/XSS
_COMMON_PARAMS = ("id", "cat", "category", "q", "query", "search", "page",
                  "file", "user", "item", "product", "pid", "sort", "name")
_MAX_PROBE = 18   # tope de candidatos validados a fondo (controla tiempo/requests)


def _say(m: str) -> None:
    print(f"{C['blue']}▸{C['x']} {m}")


# ── parser de forms (compacto, mismo criterio que el engine) ────────
def parse_forms(body: str, page_url: str) -> list[dict]:
    forms = []
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        mm = re.search(r'method\s*=\s*["\']?(\w+)', attrs, re.I)
        method = (mm.group(1).lower() if mm else "get")
        am = re.search(r'action\s*=\s*["\']([^"\']*)', attrs, re.I)
        action = urljoin(page_url, am.group(1)) if am and am.group(1) else page_url
        fields = []
        for im in re.finditer(r'<(input|textarea|select)\b([^>]*)', inner, re.I):
            a = im.group(2)
            nm = re.search(r'name\s*=\s*["\']([^"\']+)', a, re.I)
            if not nm:
                continue
            tm = re.search(r'type\s*=\s*["\']([^"\']+)', a, re.I)
            vm = re.search(r'value\s*=\s*["\']([^"\']*)', a, re.I)
            ftype = (tm.group(1).lower() if tm else "text")
            fields.append({"name": nm.group(1), "type": ftype,
                           "value": vm.group(1) if vm else ""})
        if fields:
            forms.append({"method": method, "action": action, "fields": fields})
    return forms


class _Cand:
    """Un punto de inyección: una request reconstruible cambiando un parámetro."""
    def __init__(self, url, method, param, params, via):
        self.url = url
        self.method = method            # "get" | "post"
        self.param = param              # parámetro a atacar
        self.params = dict(params)      # todos los campos/params con su valor base
        self.via = via                  # "query" | "form"

    @property
    def origin(self):
        return self.params.get(self.param, "")

    def key(self):
        return (self.method, self.url, self.param)


def _is_numeric(v: str) -> bool:
    return bool(v) and v.strip().lstrip("-").isdigit()


class BrainPentester:
    def __init__(self, target: str, lab: bool = False, budget: int = 110,
                 model_path: str = MODEL_PATH, log_samples: bool = True):
        self.target = normalize(target)
        self.lab = lab
        self.budget = budget
        self.findings: list[dict] = []
        self.pages: list[str] = []
        self.reachable = True
        self.notice = None
        self.http_status = 200
        self.steps = 0
        self.log_samples = log_samples
        self.model = None
        if os.path.exists(model_path):
            try:
                self.model = mind.LogisticModel.load(model_path)
            except (ValueError, json.JSONDecodeError):
                self.model = None

    # ── request con un parámetro reemplazado ────────────────────────
    def _send(self, cand: "_Cand", payload: str):
        params = dict(cand.params)
        params[cand.param] = payload
        self.budget -= 1
        self.steps += 1
        if cand.method == "post":
            return fetch(cand.url, method="POST", data=params)
        sep = "&" if urlparse(cand.url).query else "?"
        return fetch(cand.url + sep + urlencode(params))

    # ── descubrir candidatos de inyección ───────────────────────────
    def _discover(self) -> list["_Cand"]:
        cands: dict = {}

        def add(c: "_Cand"):
            cands.setdefault(c.key(), c)

        # 1) parámetros que ya viven en URLs crawleadas
        for p in self.pages:
            qs = parse_qs(urlparse(p).query)
            if qs:
                base = urlunparse(urlparse(p)._replace(query=""))
                vals = {k: v[0] for k, v in qs.items()}
                for param in qs:
                    add(_Cand(base, "get", param, vals, "query"))

        # 2) traer bodies de las páginas top una vez (reusados para forms + JS)
        bodies = []
        for page in self.pages[:8]:
            if self.budget <= 6:
                break
            r = fetch(page)
            self.budget -= 1
            if not r.error and r.body:
                bodies.append((page, r.body))

        for page, body in bodies:
            # 2a) campos de texto de formularios
            for form in parse_forms(body, page):
                base_vals = {f["name"]: (f["value"] or "1") for f in form["fields"]}
                for f in form["fields"]:
                    if f["type"] in ("hidden", "submit", "checkbox", "radio", "file"):
                        continue
                    add(_Cand(form["action"], form["method"], f["name"],
                              base_vals, "form"))
            # 2b) endpoints con query embebidos en el HTML/JS (fetch, ?a=b, etc.)
            for url, vals in self._endpoints_in(body, page):
                base = urlunparse(urlparse(url)._replace(query=""))
                for param in vals:
                    add(_Cand(base, "get", param, vals, "js"))

        # 3) adivinar nombres de parámetros comunes (con chequeo de "está vivo")
        self._guess_common(bodies, add)
        return list(cands.values())

    def _endpoints_in(self, body: str, page: str) -> list[tuple[str, dict]]:
        """Extrae URLs con query embebidas en HTML/JS, same-origin."""
        host = urlparse(self.target).netloc
        out, seen = [], set()
        for m in re.finditer(r'''["'(]([^"'()\s<>]+\?[^"'()\s<>]+=[^"'()\s<>]*)["')]''', body):
            url = urljoin(page, m.group(1).replace("&amp;", "&"))
            pu = urlparse(url)
            if pu.netloc and pu.netloc != host:
                continue
            qs = parse_qs(pu.query)
            if qs and url not in seen:
                seen.add(url)
                out.append((url, {k: v[0] for k, v in qs.items()}))
            if len(out) >= 20:
                break
        return out

    def _guess_common(self, bodies: list, add) -> None:
        endpoints = [p for p in self.pages if not urlparse(p).query]
        # endpoints dinámicos referenciados en el body (.php/.aspx/.jsp/…)
        host = urlparse(self.target).netloc
        for page, body in bodies:
            for m in re.finditer(r'''["'(]([^"'()\s<>]+\.(?:php|aspx|asp|jsp|do|action|cgi))\b''', body):
                url = urljoin(page, m.group(1))
                if urlparse(url).netloc in ("", host) and url not in endpoints:
                    endpoints.append(url)
        for ep in endpoints[:5]:
            if self.budget <= 8:
                break
            base = fetch(ep)
            self.budget -= 1
            if base.error:
                continue
            bl, bs = len(base.body or ""), base.status
            for param in _COMMON_PARAMS:
                if self.budget <= 6:
                    break
                sep = "&" if urlparse(ep).query else "?"
                r = fetch(ep + sep + urlencode({param: _CANARY}))
                self.budget -= 1
                if r.error:
                    continue
                live = (_CANARY in (r.body or "") or r.status != bs
                        or abs(len(r.body or "") - bl) > 30)
                if live:
                    add(_Cand(ep, "get", param, {param: "1"}, "guess"))

    # ── probar un candidato con varias técnicas → señales ───────────
    def _probe(self, cand: "_Cand") -> dict:
        orig = cand.origin or "1"
        base = self._send(cand, orig)
        if base.error:
            return {}
        base_body = base.body or ""
        base_err = bool(_SQL_ERRORS.search(base_body))
        ct_html = "html" in (base.headers.get("content-type", "") if base.headers else "")

        # comilla (error-based)
        q = self._send(cand, orig + "'")
        q_body = q.body or ""
        sql_error = bool(_SQL_ERRORS.search(q_body)) and not base_err
        error_on_quote = (q.status >= 500) and not (base.status >= 500)
        status_changed = q.status != base.status
        len_delta = (abs(len(q_body) - len(base_body)) / max(len(base_body), 1))

        # reflejo / XSS canary
        canary = _CANARY + "<x>"
        rfl = self._send(cand, canary) if self.budget > 0 else None
        reflected_raw = bool(rfl and rfl.body and (_CANARY + "<x>") in rfl.body)
        reflected = bool(rfl and rfl.body and _CANARY in rfl.body)

        # boolean-blind con confirmación (mata falsos positivos de páginas dinámicas)
        boolean_diff = self._boolean_blind(cand, orig, len(base_body))

        return {
            "reflected": reflected, "sql_error": sql_error,
            "status_changed": status_changed, "len_delta": min(len_delta, 1.0),
            "content_type_html": ct_html, "name_hint": mind.name_hint(cand.param),
            "numeric_value": _is_numeric(orig), "error_on_quote": error_on_quote,
            # señales "duras" (confirmación, no entran al modelo):
            "_reflected_raw": reflected_raw, "_boolean_diff": boolean_diff,
        }

    def _boolean_blind(self, cand: "_Cand", orig: str, base_len: int) -> bool:
        """SQLi ciego confirmado (3 requests): 'verdadero'≈baseline, 'falso'
        difiere claramente, y el 'falso' es REPRODUCIBLE (no ruido aleatorio)."""
        if self.budget < 4:
            return False
        if _is_numeric(orig):
            t_pl, f_pl = f"{orig} AND 1=1", f"{orig} AND 1=2"
        else:
            t_pl, f_pl = f"{orig}' AND '1'='1", f"{orig}' AND '1'='2"
        rt, rf = self._send(cand, t_pl), self._send(cand, f_pl)
        if rt.error or rf.error:
            return False
        lt, lf = len(rt.body or ""), len(rf.body or "")
        true_like_base = abs(lt - base_len) <= max(0.05 * base_len, 40)
        false_differs = abs(lt - lf) > max(0.08 * max(lt, 1), 80)
        if not (true_like_base and false_differs):
            return False
        rf2 = self._send(cand, f_pl)  # reproducibilidad → descarta páginas random
        if rf2.error:
            return False
        return abs(len(rf2.body or "") - lf) <= max(0.05 * max(lf, 1), 40)

    def _confirm(self, sig: dict) -> str | None:
        if sig.get("sql_error") or sig.get("_boolean_diff"):
            return "sqli"
        if sig.get("_reflected_raw") and sig.get("content_type_html"):
            return "xss"
        return None

    def _score(self, sig: dict) -> float:
        if self.model:
            return self.model.predict_proba(mind.featurize(sig))
        # sin modelo entrenado: heurística suave (señales sumadas)
        return min(1.0, 0.5 * sig.get("sql_error", 0) + 0.3 * sig.get("reflected", 0)
                   + 0.2 * sig.get("error_on_quote", 0) + 0.2 * sig.get("name_hint", 0))

    # ── loop principal ──────────────────────────────────────────────
    def run(self) -> dict:
        print(f"{C['b']}🧠 Centinela Brain → {self.target}{C['x']}  "
              f"{C['dim']}[cerebro propio · "
              f"{'modelo entrenado' if self.model else 'heurística (sin entrenar)'}]{C['x']}\n")

        # base: corremos el motor de reglas (config + sus probes) en silencio
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            base = LocalPentester(self.target, lab=self.lab).run()
        self.findings = list(base["findings"])
        self.pages = base.get("pages") or [self.target]
        self.reachable = base.get("reachable", True)
        self.notice = base.get("notice")
        self.http_status = base.get("http_status", 200)
        self.steps = base.get("steps", 0)
        if not self.reachable:
            _say(self.notice or "objetivo inalcanzable")
            return self._build_report()
        _say(f"Base (motor de reglas): {len(self.findings)} hallazgo(s), "
             f"{len(self.pages)} página(s).")

        cands = self._discover()
        _say(f"Capa de cerebro: {len(cands)} punto(s) de inyección descubierto(s). "
             "Priorizo y valido…")

        confirmed = 0
        # texto de los hallazgos base por categoría, para no re-reportar lo que el
        # motor de reglas ya encontró (su valor es lo que el engine SE PIERDE).
        base_text = {"injection": "", "xss": ""}
        for f in self.findings:
            cat = "injection" if f.get("category") == "injection" else (
                "xss" if f.get("category") == "xss" else None)
            if cat:
                base_text[cat] += (f.get("title", "") + " " + f.get("evidence", "")).lower()
        added: set = set()
        # priorizamos por name_hint (proxy barato) y acotamos cuántos validamos a
        # fondo, para no dispararnos en requests sobre targets remotos lentos.
        cands.sort(key=lambda c: -mind.name_hint(c.param))
        for cand in cands[:_MAX_PROBE]:
            if self.budget <= 2:
                break
            sig = self._probe(cand)
            if not sig:
                continue
            kind = self._confirm(sig)
            score = self._score(sig)
            if self.log_samples:
                self._log_sample(cand, sig, label=1 if kind else 0)
            if kind:
                cat = "injection" if kind == "sqli" else "xss"
                dedup = (cat, cand.param)
                already = f"'{cand.param.lower()}'" in base_text[cat]
                if dedup in added or already:
                    continue
                added.add(dedup)
                confirmed += 1
                self._add_finding(kind, cand, sig, score)

        _say(f"Cerebro: {confirmed} vuln(s) confirmada(s) además de la base. "
             f"(score promedio del modelo {'activo' if self.model else 'heurístico'})")
        return self._build_report()

    def _add_finding(self, kind: str, cand: "_Cand", sig: dict, score: float) -> None:
        if kind == "sqli":
            tech = "boolean-blind" if sig.get("_boolean_diff") else "error-based"
            f = {
                "id": f"brain-sqli-{cand.param}",
                "title": f"SQL injection en '{cand.param}' ({tech})",
                "severity": "high", "category": "injection",
                "evidence": f"{cand.method.upper()} {cand.url} — parámetro "
                            f"'{cand.param}': {tech}. score modelo={score:.2f}",
                "remediation": "Usá consultas parametrizadas (prepared statements). "
                               "Nunca concatenes input en el SQL.",
                "confidence": "confirmed", "owasp": "A03:2021 Inyección",
                "passed": False, "page": cand.url, "param": cand.param,
            }
        else:
            f = {
                "id": f"brain-xss-{cand.param}",
                "title": f"XSS reflejado en '{cand.param}'",
                "severity": "high", "category": "xss",
                "evidence": f"{cand.method.upper()} {cand.url} — el canary "
                            f"'{_CANARY}<x>' se reflejó sin escapar. score={score:.2f}",
                "remediation": "Escapá la salida según contexto (HTML/atributo/JS) "
                               "y aplicá Content-Security-Policy.",
                "confidence": "confirmed", "owasp": "A03:2021 Inyección",
                "passed": False, "page": cand.url, "param": cand.param,
            }
        self.findings.append(f)
        print(f"  {C['crit']}✚ {f['severity'].upper()}{C['x']} {f['title']}")

    def _log_sample(self, cand: "_Cand", sig: dict, label: int) -> None:
        rec = {"target": self.target, "param": cand.param, "via": cand.via,
               "label": label,
               "signal": {k: sig[k] for k in mind.FEATURES if k in sig}}
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SAMPLES_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _build_report(self) -> dict:
        score = 100
        counts = {s: 0 for s in PENALTY}
        for f in self.findings:
            score -= PENALTY.get(f["severity"], 0)
            counts[f["severity"]] += 1
        score = max(0, min(100, score))
        order = list(PENALTY)
        findings = sorted(self.findings, key=lambda f: order.index(f["severity"]))
        owasp: dict = {}
        for f in findings:
            owasp[f.get("owasp", "—")] = owasp.get(f.get("owasp", "—"), 0) + 1
        risk = ("critical" if counts["critical"] else "high" if counts["high"]
                else "medium" if counts["medium"] else "low" if counts["low"]
                else "minimal")
        return {
            "kind": "agent", "provider": "brain",
            "model": "cerebro propio (logística entrenable)",
            "target": self.target,
            "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "score": score, "grade": _grade(score), "counts": counts,
            "total_checks": len(self.findings), "passed": 0,
            "pages": self.pages, "profile": {}, "http_status": self.http_status,
            "reachable": self.reachable, "notice": self.notice, "lab": self.lab,
            "steps": self.steps, "overall_risk": risk, "owasp": owasp,
            "summary": f"Cerebro propio: {len(findings)} hallazgo(s), riesgo {risk}.",
            "usage": {"input_tokens": 0, "output_tokens": 0, "est_cost_usd": 0.0},
            "findings": findings,
        }


# ── entrenamiento (lee muestras → entrena modelo → guarda) ──────────
def train_from_samples(samples_path: str = SAMPLES_PATH,
                       model_path: str = MODEL_PATH, **kw) -> dict:
    if not os.path.exists(samples_path):
        raise FileNotFoundError(
            f"No hay muestras en {samples_path}. Corré el brain sobre algún lab primero.")
    X, y = [], []
    with open(samples_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            X.append(mind.featurize(rec.get("signal", {})))
            y.append(int(rec.get("label", 0)))
    if not X:
        raise ValueError("el archivo de muestras está vacío")
    model = mind.LogisticModel()
    metrics = model.train(X, y, **kw)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save(model_path)
    return {"metrics": metrics, "n_samples": len(X),
            "positives": sum(y), "weights": model.weight_report(),
            "model_path": model_path}
