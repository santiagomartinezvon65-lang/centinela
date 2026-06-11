"""Centinela Remediate — modo defensa: genera la config lista para arreglar.

A partir de los hallazgos, arma la configuración concreta para corregir los
headers de seguridad faltantes, en varios formatos (Vercel, nginx, Apache,
Netlify). Convierte a Centinela de "encontrar problemas" a "arreglarlos". Stdlib.
"""
from __future__ import annotations

import json

# id de hallazgo (checks.py) → (Header, valor recomendado)
_HEADER_FIX = {
    "strict-transport-security": (
        "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    "content-security-policy": (
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"),
    "x-frame-options": ("X-Frame-Options", "DENY"),
    "x-content-type-options": ("X-Content-Type-Options", "nosniff"),
    "referrer-policy": ("Referrer-Policy", "strict-origin-when-cross-origin"),
    "permissions-policy": ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
}
FORMATS = ("vercel", "nginx", "apache", "netlify")


def missing_headers(report: dict) -> list[tuple[str, str]]:
    fails = {f["id"] for f in report.get("findings", []) if not f.get("passed")}
    return [v for k, v in _HEADER_FIX.items() if k in fails]


def _extra_advice(report: dict) -> list[str]:
    fails = {f["id"] for f in report.get("findings", []) if not f.get("passed")}
    tips = []
    if any(i.startswith("cookie-") for i in fails):
        tips.append("Cookies: agregá los flags  Secure; HttpOnly; SameSite=Lax  a tus cookies.")
    if "cors" in fails:
        tips.append("CORS: no reflejes el Origin; usá una allowlist fija de dominios.")
    if "redirect" in fails or "https" in fails:
        tips.append("HTTPS: forzá la redirección 301 de http→https.")
    return tips


def generate(report: dict, fmt: str = "vercel") -> str:
    headers = missing_headers(report)
    advice = _extra_advice(report)
    if not headers and not advice:
        return "# Centinela: no faltan headers de seguridad. Nada que arreglar acá. ✓"
    cfg = _render(headers, fmt) if headers else "# (no faltan headers de seguridad)"
    out = [f"# Centinela — remediación para {report.get('target', '')} (formato: {fmt})", cfg]
    if advice:
        out.append("\n# Además:")
        out += [f"#  - {t}" for t in advice]
    out.append("\n# Nota: la CSP es un punto de partida; ajustala a los recursos reales de tu app.")
    return "\n".join(out)


def _render(headers: list[tuple[str, str]], fmt: str) -> str:
    if fmt == "vercel":
        block = {"headers": [{"source": "/(.*)", "headers":
                 [{"key": k, "value": v} for k, v in headers]}]}
        return json.dumps(block, indent=2, ensure_ascii=False)
    if fmt == "nginx":
        return "\n".join(f'add_header {k} "{v}" always;' for k, v in headers)
    if fmt == "apache":
        return "\n".join(f'Header always set {k} "{v}"' for k, v in headers)
    if fmt == "netlify":  # archivo _headers
        return "/*\n" + "\n".join(f"  {k}: {v}" for k, v in headers)
    return _render(headers, "vercel")
