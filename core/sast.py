"""Centinela SAST — análisis estático de código local (secretos + patrones peligrosos).

Complementa el escaneo dinámico (DAST) con análisis de código fuente, como hacen las
plataformas serias. Diseñado para ALTA PRECISIÓN: los secretos se detectan con regex
específicas (cero/casi-cero falsos positivos), y los patrones de riesgo se filtran
(se ignoran comentarios y placeholders). Sin dependencias.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from .report import PENALTY, _grade

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist",
              "build", ".next", "vendor", ".idea", ".vscode", "coverage", ".pytest_cache"}
_TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php", ".go", ".rs",
             ".cs", ".kt", ".swift", ".c", ".cpp", ".sh", ".yml", ".yaml", ".json",
             ".env", ".cfg", ".ini", ".conf", ".properties", ".tf", ".xml", ".vue", ".txt"}
_MAX_BYTES = 1_500_000

# secretos: patrones específicos → casi cero falsos positivos
_SECRET_PATTERNS = [
    ("AWS Access Key", "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe live key", "critical", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("GitHub token", "critical", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Clave privada", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Google API Key", "high", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", "high", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google OAuth client secret", "high",
     re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
]
# credencial genérica: nombre-de-variable = "valor". Captura nombres con prefijo
# (db_password, AWS_SECRET_KEY, …) y filtra placeholders para evitar falsos positivos.
_GENERIC = re.compile(
    r"""(?i)([a-z0-9_.]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|"""
    r"""secret[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)[a-z0-9_]*)"""
    r"""\s*[:=]\s*['"]([^'"\n]{8,})['"]""")
_PLACEHOLDER = re.compile(
    r"(?i)(change.?me|your[_-]|example|xxx+|\*{3,}|placeholder|<[^>]+>|\{\{|\$\{|"
    r"process\.env|os\.environ|getenv|sample|dummy|redacted|todo|^n/?a$|^none$|"
    r"^null$|^true$|^false$|^\.{3}|^\$\(|^%[A-Z_]+%$)")

# patrones de código peligroso (conservadores; se ignoran comentarios)
_DANGER = [
    ("subprocess con shell habilitado (riesgo de command injection)", "medium",
     re.compile(r"shell\s*=\s*True")),
    ("Deserialización insegura (pickle)", "medium", re.compile(r"\bpickle\.loads?\s*\(")),
    ("yaml.load sin SafeLoader (RCE)", "medium",
     re.compile(r"yaml\.load\s*\((?![^)]*Loader)")),
    ("Verificación de certificado TLS deshabilitada", "medium",
     re.compile(r"verify\s*=\s*False")),
    ("os.system con posible input de usuario", "low", re.compile(r"\bos\.system\s*\(")),
    ("Uso de eval()", "low", re.compile(r"\beval\s*\(")),
    ("Modo debug activado", "low", re.compile(r"(?i)\bdebug\s*=\s*True\b")),
]
_COMMENT = re.compile(r"^\s*(#|//|\*|/\*|<!--|--)")


def _redact(s: str) -> str:
    s = s.strip()
    return s if len(s) <= 12 else s[:6] + "…" + s[-4:]


def _f(fid, title, sev, cat, ev, fix, conf="confirmed"):
    return {"id": fid, "title": title, "severity": sev, "category": cat,
            "evidence": ev, "remediation": fix, "confidence": conf,
            "owasp": "A05:2021 Configuración de seguridad incorrecta", "passed": False, "page": ""}


def _scan_line(rel: str, i: int, line: str, out: list, seen: set):
    for name, sev, rx in _SECRET_PATTERNS:
        m = rx.search(line)
        if m:
            key = ("secret", rel, name, i)
            if key in seen:
                continue
            seen.add(key)
            out.append(_f(f"sast-secret-{name}-{rel}-{i}", f"Secreto hardcodeado: {name}",
                          sev, "secrets", f"{rel}:{i}  {_redact(m.group(0))}",
                          "Sacá el secreto del código, rotalo, y usá variables de "
                          "entorno o un gestor de secretos."))
    gm = _GENERIC.search(line)
    if gm and not _PLACEHOLDER.search(gm.group(2)) and not _COMMENT.match(line):
        out.append(_f(f"sast-cred-{rel}-{i}", "Posible credencial hardcodeada", "high",
                      "secrets", f"{rel}:{i}  {gm.group(1)}=***",
                      "Movela a una variable de entorno; nunca commitees credenciales.",
                      conf="likely"))
    if _COMMENT.match(line):
        return
    if "re.compile" in line or "re.search" in line or "re.match" in line:
        return  # líneas que DEFINEN regex no son código peligroso (evita FP)
    for name, sev, rx in _DANGER:
        if rx.search(line):
            out.append(_f(f"sast-danger-{name[:8]}-{rel}-{i}", name, sev, "injection",
                          f"{rel}:{i}  {line.strip()[:90]}",
                          "Revisá esta línea: no ejecutes/deserialices input no confiable.",
                          conf="needs-review"))


def scan_dir(path: str, say=lambda *_: None):
    findings: list = []
    seen: set = set()
    n_files = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext and ext not in _TEXT_EXT and not fn.startswith(".env"):
                continue
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > _MAX_BYTES:
                    continue
                with open(fp, encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            n_files += 1
            rel = os.path.relpath(fp, path).replace("\\", "/")
            for i, line in enumerate(lines, 1):
                if len(line) <= 600:
                    _scan_line(rel, i, line, findings, seen)
    return findings, n_files


def scan(path: str, say=lambda *_: None) -> dict:
    findings, n_files = scan_dir(path, say)
    order = list(PENALTY)
    score, counts = 100, {s: 0 for s in PENALTY}
    for f in findings:
        score -= PENALTY.get(f["severity"], 0)
        counts[f["severity"]] += 1
    score = max(0, min(100, score))
    findings.sort(key=lambda f: order.index(f["severity"]))
    risk = next((s for s in order[:4] if counts[s]), "minimal")
    sec = sum(1 for f in findings if f["category"] == "secrets")
    summary = (f"Análisis estático de {n_files} archivo(s): {len(findings)} hallazgo(s)"
               + (f", incluyendo {sec} secreto(s) hardcodeado(s)." if sec else "."))
    return {
        "kind": "sast", "provider": "sast", "model": "análisis estático de código",
        "target": os.path.abspath(path),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "score": score, "grade": _grade(score), "counts": counts,
        "total_checks": len(findings), "passed": 0, "pages": [os.path.abspath(path)],
        "profile": {}, "http_status": 200, "reachable": True, "notice": None,
        "overall_risk": risk, "summary": summary,
        "usage": {"input_tokens": 0, "output_tokens": 0, "est_cost_usd": 0.0,
                  "files": n_files}, "findings": findings,
    }
