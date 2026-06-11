"""Perfilado de sensibilidad del sitio + ajuste de severidad por contexto.

La idea: un hallazgo no vale lo mismo en una vitrina estática que en un sitio
que maneja login o pagos. Detectamos el perfil y escalamos la severidad.
"""
from __future__ import annotations

import re

from .checks import Finding
from .http import Response

# Tiers de sensibilidad
TIERS = {
    0: ("Vitrina estática", "baja",
        "No maneja datos sensibles: faltar headers de hardening tiene bajo impacto."),
    1: ("Sitio con formularios", "media",
        "Recibe datos de usuarios: conviene endurecer, el riesgo es moderado."),
    2: ("Login / cuentas", "alta",
        "Maneja autenticación y sesiones: los headers y cookies son importantes."),
    3: ("Transaccional / pagos", "máxima",
        "Procesa pagos o datos críticos: máxima exigencia, todo suma."),
}

_SESSION_COOKIE = re.compile(r"\b(session|sess|sid|auth|token|jwt|csrf|connect\.sid)\b", re.I)
_PW = re.compile(r'type\s*=\s*["\']?password', re.I)
_EMAIL = re.compile(r'type\s*=\s*["\']?email', re.I)
_PAYMENT = re.compile(
    r"(stripe|mercadopago|mercado pago|mpago|paypal|checkout\.js|braintree|"
    r"data-checkout|card[-_ ]?number|cvv|cvc|prisma|decidir|ualá|uala)", re.I)
_AUTH_PATH = re.compile(
    r"/(login|signin|sign-in|log-in|account|admin|dashboard|checkout|cart|"
    r"carrito|mi-?cuenta|panel|wp-admin|usuario)", re.I)


def detect(pages: list[Response]) -> dict:
    """Infiere el perfil de sensibilidad a partir de las páginas escaneadas."""
    text = " ".join((p.body or "") for p in pages)
    cookies = [c for p in pages for c in p.set_cookies]
    signals: list[str] = []

    has_form = "<form" in text.lower()
    has_email = bool(_EMAIL.search(text))
    has_pw = bool(_PW.search(text))
    session = any(_SESSION_COOKIE.search(c) for c in cookies)
    payment = bool(_PAYMENT.search(text))
    auth_path = bool(_AUTH_PATH.search(text))

    tier = 0
    if has_form or has_email or cookies:
        tier = max(tier, 1)
    if has_pw or session or auth_path:
        tier = max(tier, 2)
    if payment:
        tier = max(tier, 3)

    if has_pw:
        signals.append("formulario con contraseña")
    if session:
        signals.append("cookies de sesión")
    if payment:
        signals.append("indicios de pagos/checkout")
    if auth_path:
        signals.append("rutas de login/admin")
    if has_email and "campos de email" not in signals:
        signals.append("campos de email")
    if has_form and not signals:
        signals.append("formularios")
    if cookies and "cookies de sesión" not in signals:
        signals.append(f"{len(cookies)} cookie(s)")
    if not signals:
        signals.append("sólo contenido estático")

    label, demand, note = TIERS[tier]
    return {"tier": tier, "label": label, "demand": demand,
            "note": note, "signals": signals, "auto": True}


def profile_for_tier(tier: int, auto: bool = False) -> dict:
    tier = max(0, min(3, tier))
    label, demand, note = TIERS[tier]
    return {"tier": tier, "label": label, "demand": demand,
            "note": note, "signals": ["perfil fijado manualmente"], "auto": auto}


# ── ajuste de severidad por contexto ────────────────────────────────
_SCALE = ["info", "low", "medium", "high", "critical"]

# Hardening: escala fuerte con el perfil (poco grave en vitrina, grave en banco)
_HARDENING = {"strict-transport-security", "content-security-policy",
              "x-frame-options", "x-content-type-options", "referrer-policy",
              "permissions-policy", "sec-txt", "methods", "trace", "tls-version"}
# Datos/sesión: relevante sólo si hay algo que proteger
_DATA = {"cors", "reflect", "mixed", "redirect"}
# Nunca se bajan: siempre graves sin importar el perfil
_FIXED = {"https", "tls-expiry", "tls-conn", "form-pw-http"}
_FIXED_PREFIX = ("path",)  # archivos sensibles expuestos (.env, .git)

_HARD_SHIFT = {0: -2, 1: -1, 2: 0, 3: 1}
_DATA_SHIFT = {0: -1, 1: 0, 2: 0, 3: 1}


def _shift(sev: str, n: int) -> str:
    i = _SCALE.index(sev)
    # Piso: un hallazgo que era al menos 'low' nunca baja a 'info' (0 penalización).
    # Sacar una protección siempre tiene que costar algo, aunque sea poco.
    floor = 1 if i >= 1 else 0
    return _SCALE[max(floor, min(len(_SCALE) - 1, i + n))]


def apply_profile(findings: list[Finding], tier: int) -> list[Finding]:
    """Reescala la severidad de cada hallazgo según el perfil del sitio."""
    for f in findings:
        if f.passed:
            continue
        if f.id in _FIXED or f.id.startswith(_FIXED_PREFIX):
            continue
        if f.id in _HARDENING:
            f.severity = _shift(f.severity, _HARD_SHIFT[tier])
        elif f.id in _DATA or f.id.startswith("cookie-"):
            f.severity = _shift(f.severity, _DATA_SHIFT[tier])
    return findings
