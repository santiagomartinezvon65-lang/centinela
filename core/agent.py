"""Centinela Agent — pentester con IA (Claude) sobre el toolkit de Centinela.

Loop agéntico: Claude razona como pentester y usa herramientas (http_request,
run_checks, list_links, record_finding, finish) acotadas al host autorizado.
Uso ÉTICO: sólo sitios propios o labs intencionalmente vulnerables.
"""
from __future__ import annotations

import json
import os
import time
from urllib.parse import urlparse

from .crawler import crawl as crawl_site
from .http import TIMEOUT, fetch, normalize
from .report import PENALTY, _grade
from .scanner import scan as deterministic_scan

DEFAULT_MODEL = os.environ.get("CENTINELA_MODEL", "claude-opus-4-8")
# precio aprox USD por 1M tokens (input, output) para estimar costo
PRICING = {
    "claude-opus-4-8": (5.0, 25.0), "claude-opus-4-7": (5.0, 25.0),
    "claude-sonnet-4-6": (3.0, 15.0), "claude-haiku-4-5": (1.0, 5.0),
}
C = {"crit": "\033[91m", "high": "\033[93m", "ok": "\033[92m", "blue": "\033[96m",
     "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}

SYSTEM = """\
Sos Centinela Agent, un pentester web autónomo y ético. Tu trabajo: analizar un \
objetivo AUTORIZADO, encontrar vulnerabilidades reales y validarlas con evidencia \
concreta, igual que un pentester humano.

METODOLOGÍA:
1. Reconocimiento: usá run_checks para un barrido determinístico inicial (headers, \
TLS, cookies, CORS, fugas, etc.) y list_links para mapear el sitio.
2. Hipótesis: a partir de lo que encontrás, pensá qué podría ser explotable.
3. Validación: usá http_request para probar tus hipótesis con requests concretas \
(manipular headers, parámetros, métodos). Confirmá con evidencia, no asumas.
4. Documentá cada vuln confirmada con record_finding (con evidencia reproducible \
y remediación accionable). No reportes falsos positivos.
5. Cuando terminaste, llamá finish con un resumen ejecutivo.

REGLAS ÉTICAS (innegociables):
- Solo actuás sobre el host objetivo. No salgas de scope.
- NADA destructivo: no borres datos, no hagas DoS, no spamees requests, no subas \
shells. Detección y validación de bajo impacto solamente.
- En modo normal: probes pasivos/seguros (marcadores benignos, reflejos, headers).
- En modo lab (target intencionalmente vulnerable): podés probar payloads de \
detección (XSS canary, error-based SQLi) pero siempre no destructivos.

ESTILO: sé conciso entre pasos. Explicá brevemente qué vas a probar y por qué \
antes de cada herramienta. Priorizá hallazgos de alto impacto.\
"""

TOOLS = [
    {
        "name": "run_checks",
        "description": "Corre el escaneo determinístico de Centinela (headers de "
        "seguridad, TLS, cookies, CORS, métodos HTTP, fugas de info, reflejo de "
        "parámetros) sobre una URL del objetivo. Buen primer paso de reconocimiento.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "URL a escanear (debe ser del host objetivo). Por defecto, la raíz del objetivo."}
        }},
    },
    {
        "name": "list_links",
        "description": "Crawlea y devuelve los links same-origin de una página del "
        "objetivo, para mapear superficie de ataque.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "URL desde la que crawlear. Por defecto la raíz."},
            "max": {"type": "integer", "description": "Máx. de páginas (1-20, default 10)."}
        }},
    },
    {
        "name": "http_request",
        "description": "Hace una request HTTP arbitraria al host objetivo y devuelve "
        "status, headers y un fragmento del body. Tu herramienta principal para "
        "validar hipótesis (manipular headers como Origin/Referer, métodos, "
        "parámetros de query). Acotada al host autorizado.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "URL completa al host objetivo."},
            "method": {"type": "string", "description": "GET, POST, OPTIONS, etc. Default GET."},
            "headers": {"type": "object", "description": "Headers extra (ej. {\"Origin\": \"https://evil.example\"})."},
        }, "required": ["url"]},
    },
    {
        "name": "record_finding",
        "description": "Registra una vulnerabilidad CONFIRMADA con evidencia. Solo "
        "hallazgos validados, no especulación.",
        "input_schema": {"type": "object", "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "category": {"type": "string", "description": "ej. xss, cors, headers, disclosure, auth, injection"},
            "evidence": {"type": "string", "description": "Prueba concreta y reproducible (request/respuesta)."},
            "remediation": {"type": "string", "description": "Cómo arreglarlo."},
            "confidence": {"type": "string", "enum": ["confirmed", "likely", "needs-review"]},
        }, "required": ["title", "severity", "category", "evidence"]},
    },
    {
        "name": "finish",
        "description": "Terminá el pentest. Llamá esto cuando cubriste la superficie "
        "relevante o agotaste hipótesis.",
        "input_schema": {"type": "object", "properties": {
            "summary": {"type": "string", "description": "Resumen ejecutivo del pentest."},
            "overall_risk": {"type": "string", "enum": ["critical", "high", "medium", "low", "minimal"]},
        }, "required": ["summary"]},
    },
]


class _Scope:
    def __init__(self, target: str, lab: bool, budget: int):
        self.host = urlparse(normalize(target)).hostname or ""
        self.lab = lab
        self.remaining = budget

    def allows(self, url: str) -> bool:
        h = urlparse(normalize(url)).hostname or ""
        return h == self.host or h.endswith("." + self.host) or h == ""


def _truncate(s: str, n: int = 1500) -> str:
    return s if len(s) <= n else s[:n] + f"\n…[+{len(s)-n} chars]"


class CentinelaAgent:
    def __init__(self, target: str, lab: bool = False, provider: str = "auto",
                 model: str | None = None, max_steps: int = 20,
                 request_budget: int = 60):
        from .llm import make_backend
        self.target = normalize(target)
        self.lab = lab
        self.max_steps = max_steps
        self.scope = _Scope(target, lab, request_budget)
        self.findings: list[dict] = []
        self.summary = ""
        self.overall_risk = ""
        self.reachable = True
        self.notice: str | None = None
        self.http_status = 200
        self.backend = make_backend(provider, model, SYSTEM, TOOLS)
        self.provider = self.backend.name
        self.model = self.backend.model

    # ── tool dispatch ───────────────────────────────────────────────
    def _dispatch(self, name: str, inp: dict) -> tuple[str, bool]:
        if name == "finish":
            self.summary = inp.get("summary", "")
            self.overall_risk = inp.get("overall_risk", "")
            return "ok", False

        if name == "record_finding":
            f = {
                "id": f"agent-{len(self.findings)+1}",
                "title": inp.get("title", "(sin título)"),
                "severity": inp.get("severity", "info"),
                "category": inp.get("category", "agent"),
                "evidence": inp.get("evidence", ""),
                "remediation": inp.get("remediation", ""),
                "confidence": inp.get("confidence", "likely"),
                "passed": False, "page": "",
            }
            self.findings.append(f)
            print(f"  {C['crit']}✚ hallazgo:{C['x']} [{f['severity']}] {f['title']}")
            return f"registrado (#{len(self.findings)})", False

        url = inp.get("url") or self.target
        if not self.scope.allows(url):
            return (f"FUERA DE SCOPE: solo podés tocar {self.scope.host}. "
                    "Rechazado por seguridad.", True)
        if self.scope.remaining <= 0:
            return "Presupuesto de requests agotado. Cerrá con finish.", True

        if name == "run_checks":
            self.scope.remaining -= 8
            report, err = deterministic_scan(url, crawl=False)
            if err:
                return f"error: {err}", True
            return self._fmt_checks(report), False

        if name == "list_links":
            self.scope.remaining -= min(int(inp.get("max", 10)), 20)
            pages = crawl_site(url, max_pages=min(int(inp.get("max", 10)), 20))
            urls = [p.final_url for p in pages if not p.error]
            return json.dumps(urls, ensure_ascii=False), False

        if name == "http_request":
            self.scope.remaining -= 1
            method = (inp.get("method") or "GET").upper()
            r = fetch(url, method=method, headers=inp.get("headers"))
            if r.error:
                return f"error de red: {r.error}", False
            hdrs = {k: r.headers[k] for k in list(r.headers)[:25]}
            out = {"status": r.status, "final_url": r.final_url,
                   "headers": hdrs, "body": _truncate(r.body)}
            return json.dumps(out, ensure_ascii=False), False

        return f"herramienta desconocida: {name}", True

    def _fmt_checks(self, report: dict) -> str:
        lines = [f"grade={report['grade']} score={report['score']} "
                 f"http={report.get('http_status')}"]
        for f in report["findings"]:
            if not f["passed"]:
                lines.append(f"- [{f['severity']}] {f['title']} :: {f['evidence'][:120]}")
        return "\n".join(lines) or "sin hallazgos determinísticos"

    # ── loop principal (provider-agnóstico) ─────────────────────────
    def run(self) -> dict:
        mode = "LAB (vulnerable a propósito)" if self.lab else "normal (no destructivo)"
        # Chequeo de conectividad: si el objetivo no responde, no gastamos pasos
        # del LLM — lo marcamos inalcanzable (igual que el motor de reglas).
        probe = fetch(self.target)
        if probe.error:
            self.reachable = False
            self.notice = f"No se pudo conectar: {probe.error}"
            print(f"{C['b']}🛡  Centinela Agent → {self.target}{C['x']}  "
                  f"{C['dim']}[{self.provider}:{self.model}]{C['x']}")
            print(f"{C['crit']}▸ {self.notice}{C['x']}")
            return self._build_report(0)
        self.http_status = probe.status
        task = (f"Objetivo autorizado: {self.target}\nModo: {mode}\n\n"
                "Hacé un pentest completo: reconocé, formá hipótesis, validá con "
                "requests reales y documentá las vulns confirmadas. Empezá por "
                "run_checks sobre la raíz.")
        self.backend.add_user(task)
        print(f"{C['b']}🛡  Centinela Agent → {self.target}{C['x']}  "
              f"{C['dim']}[{self.provider}:{self.model}, modo {mode}]{C['x']}\n")

        step = 0
        nudges = 2  # tolerancia a turnos sin tool-call (modelos chicos "piensan en voz alta")
        for step in range(1, self.max_steps + 1):
            turn = self.backend.step()
            if turn.text:
                print(f"{C['blue']}▸{C['x']} {turn.text}")

            done = False
            tool_results = []
            for tc in turn.tool_calls:
                arg = tc["input"].get("url") or tc["input"].get("title") or ""
                print(f"  {C['dim']}↳ {tc['name']}({str(arg)[:70]}){C['x']}")
                content, is_err = self._dispatch(tc["name"], tc["input"])
                tool_results.append({"id": tc["id"], "name": tc["name"],
                                     "content": content, "is_error": is_err})
                if tc["name"] == "finish":
                    done = True

            if done:
                if not self.summary:
                    self.summary = turn.text
                break

            if not turn.tool_calls:
                # El modelo no usó herramientas. En vez de matar el loop (un modelo
                # chico puede narrar sin emitir tool-call), lo empujamos a seguir o
                # cerrar con finish. Sólo cerramos si se agotan los nudges.
                if nudges > 0:
                    nudges -= 1
                    print(f"{C['dim']}  ↳ (nudge: pedí que continúe o cierre){C['x']}")
                    self.backend.add_user(
                        "No llamaste ninguna herramienta. Si ya terminaste, llamá "
                        "`finish` con tu resumen ejecutivo. Si no, seguí: usá "
                        "run_checks / http_request para validar hipótesis y "
                        "record_finding para documentar cada vuln confirmada.")
                    continue
                if not self.summary:
                    self.summary = turn.text
                break

            self.backend.add_tool_results(tool_results)
            nudges = 2  # hubo progreso: recargamos la tolerancia
        else:
            print(f"{C['high']}⚠ alcancé el máximo de pasos ({self.max_steps}){C['x']}")

        return self._build_report(step)

    def _build_report(self, steps: int) -> dict:
        score = 100
        counts = {s: 0 for s in PENALTY}
        for f in self.findings:
            score -= PENALTY.get(f["severity"], 0)
            counts[f["severity"]] += 1
        score = max(0, min(100, score))
        in_t, out_t = self.backend.usage()
        if self.provider == "anthropic":
            pin, pout = PRICING.get(self.model, (5.0, 25.0))
            cost = round(in_t / 1e6 * pin + out_t / 1e6 * pout, 4)
        else:
            cost = 0.0  # local = gratis
        from datetime import datetime, timezone
        return {
            "kind": "agent", "target": self.target,
            "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "score": score, "grade": _grade(score), "counts": counts,
            "total_checks": len(self.findings),
            "passed": 0, "pages": [self.target], "profile": {},
            "http_status": self.http_status, "reachable": self.reachable,
            "notice": self.notice,
            "summary": self.summary, "overall_risk": self.overall_risk,
            "model": self.model, "provider": self.provider,
            "steps": steps, "lab": self.lab,
            "usage": {"input_tokens": in_t, "output_tokens": out_t,
                      "est_cost_usd": cost},
            "findings": sorted(self.findings,
                               key=lambda f: list(PENALTY).index(f["severity"])),
        }
