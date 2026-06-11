"""Orquestador de escaneo — usado por la CLI y el servidor web."""
from __future__ import annotations

from .checks import Finding, run_page, run_site
from .crawler import crawl as crawl_site
from .http import fetch
from .profile import apply_profile, detect, profile_for_tier
from .report import build


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Hallazgos OK: uno por id. Hallazgos con problema: uno por (id, página)."""
    seen: set = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.id,) if f.passed else (f.id, f.page)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan(url: str, crawl: bool = False, max_pages: int = 12,
         tier: int | None = None) -> tuple[dict | None, str | None]:
    """Escanea una URL (o todo el sitio si crawl=True).

    tier=None autodetecta el perfil de sensibilidad; un int (0-3) lo fija a mano.
    Devuelve (report, error).
    """
    if crawl:
        pages = crawl_site(url, max_pages=max_pages)
        if not pages or pages[0].error:
            return None, (pages[0].error if pages else "no se pudo conectar")
        base = pages[0]
    else:
        base = fetch(url)
        if base.error:
            return None, base.error
        pages = [base]

    findings: list[Finding] = list(run_site(base))
    for p in pages:
        for f in run_page(p):
            f.page = p.final_url
            findings.append(f)
    findings = _dedupe(findings)

    profile = detect(pages) if tier is None else profile_for_tier(tier)
    findings = apply_profile(findings, profile["tier"])

    notice = _reachability_notice(base.status)
    report = build(base.final_url, findings,
                   pages=[p.final_url for p in pages], profile=profile,
                   http_status=base.status, notice=notice)
    return report, None


def _reachability_notice(status: int) -> str | None:
    """Avisa cuando la respuesta NO es el contenido real del sitio."""
    if status in (401, 407):
        return (f"El sitio respondió HTTP {status}: está detrás de autenticación "
                "(ej. Vercel Deployment Protection, login, VPN). Centinela escaneó "
                "la página de bloqueo, NO tu sitio real — la nota no es válida. "
                "Desactivá la protección o escaneá una URL pública.")
    if status == 403:
        return (f"El sitio respondió HTTP 403 (acceso prohibido): puede haber un WAF "
                "o protección bloqueando el escaneo. El análisis puede no reflejar el sitio real.")
    if status == 404:
        return "El sitio respondió HTTP 404: la URL no existe. Verificá la dirección."
    if status >= 500:
        return f"El sitio respondió HTTP {status} (error de servidor). El análisis puede ser parcial."
    if status == 0 or status < 200:
        return "Respuesta inusual del servidor — el análisis puede ser parcial."
    return None
