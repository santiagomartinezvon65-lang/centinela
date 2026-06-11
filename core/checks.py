"""Security checks. Each returns a list[Finding]. Non-destructive only."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .http import Response, fetch, tls_info

CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"


@dataclass
class Finding:
    id: str
    title: str
    severity: str          # critical|high|medium|low|info
    passed: bool           # True = the site is OK on this check
    category: str
    evidence: str = ""
    remediation: str = ""
    page: str = ""         # URL donde se detectó (para crawl multi-página)

    def dict(self) -> dict:
        return asdict(self)


def _ok(id, title, sev, cat, ev="", fix=""):
    return Finding(id, title, sev, True, cat, ev)


def _bad(id, title, sev, cat, ev="", fix=""):
    return Finding(id, title, sev, False, cat, ev, fix)


# ── Security headers ────────────────────────────────────────────────
_HEADERS = [
    ("strict-transport-security", "HSTS (Strict-Transport-Security)", HIGH,
     "Fuerza HTTPS en el navegador. Agregá: Strict-Transport-Security: "
     "max-age=63072000; includeSubDomains"),
    ("content-security-policy", "Content-Security-Policy", HIGH,
     "Mitiga XSS/inyección. Definí una CSP restrictiva acorde a tu app."),
    ("x-frame-options", "X-Frame-Options / frame-ancestors", MEDIUM,
     "Evita clickjacking. Usá X-Frame-Options: DENY o CSP frame-ancestors."),
    ("x-content-type-options", "X-Content-Type-Options", LOW,
     "Evita MIME-sniffing. Agregá: X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Referrer-Policy", LOW,
     "Controla fuga de URLs por Referer. Ej: Referrer-Policy: no-referrer."),
    ("permissions-policy", "Permissions-Policy", LOW,
     "Restringe APIs del navegador (cámara, geo, etc.)."),
]


def check_headers(resp: Response) -> list[Finding]:
    out = []
    h = resp.headers
    for key, title, sev, fix in _HEADERS:
        if key == "x-frame-options":
            csp = h.get("content-security-policy", "")
            if key in h or "frame-ancestors" in csp:
                out.append(_ok(key, title, sev, "headers", h.get(key, "frame-ancestors")))
                continue
        if key in h:
            out.append(_ok(key, title, sev, "headers", f"{key}: {h[key][:120]}"))
        else:
            out.append(_bad(key, title, sev, "headers", "header ausente", fix))
    return out


# ── Information disclosure ──────────────────────────────────────────
def check_disclosure(resp: Response) -> list[Finding]:
    out = []
    h = resp.headers
    for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if key in h and re.search(r"\d", h[key]):
            out.append(_bad(
                f"leak-{key}", f"Versión expuesta en '{key}'", LOW, "disclosure",
                f"{key}: {h[key]}",
                f"Ocultá o genérico el header '{key}' para no filtrar la versión."))
    return out


SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/.git/config", "/config.php.bak",
                   "/.DS_Store", "/backup.zip", "/wp-config.php.bak"]


def check_exposed_paths(base_url: str) -> list[Finding]:
    out = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        r = fetch(url)
        if r.status == 200 and r.body and "<html" not in r.body[:200].lower():
            out.append(_bad(
                f"path{path}", f"Archivo sensible accesible: {path}", CRITICAL,
                "disclosure", f"{url} → 200 OK ({len(r.body)} bytes)",
                "Bloqueá el acceso público a este archivo en el servidor."))
    if not out:
        out.append(_ok("paths", "Sin archivos sensibles expuestos (probados)",
                       MEDIUM, "disclosure", ", ".join(SENSITIVE_PATHS)))
    return out


# ── Cookies ─────────────────────────────────────────────────────────
def check_cookies(resp: Response) -> list[Finding]:
    out = []
    if not resp.set_cookies:
        return out
    for raw in resp.set_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = [f for f in ("secure", "httponly") if f not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            out.append(_bad(
                f"cookie-{name}", f"Cookie '{name}' con flags faltantes", MEDIUM,
                "cookies", f"faltan: {', '.join(missing)}",
                "Agregá Secure; HttpOnly; SameSite=Lax|Strict a la cookie."))
        else:
            out.append(_ok(f"cookie-{name}", f"Cookie '{name}' bien protegida",
                           LOW, "cookies"))
    return out


# ── TLS / HTTPS ─────────────────────────────────────────────────────
def check_tls(resp: Response) -> list[Finding]:
    out = []
    if resp.scheme != "https":
        out.append(_bad("https", "El sitio no usa HTTPS", CRITICAL, "tls",
                        f"esquema final: {resp.scheme}",
                        "Serví el sitio por HTTPS y redirigí todo el tráfico."))
        return out

    info = tls_info(resp.host)
    if not info.ok:
        out.append(_bad("tls-conn", "No se pudo validar el certificado TLS",
                        HIGH, "tls", info.error or "",
                        "Revisá la cadena del certificado."))
        return out

    out.append(_ok("https", "HTTPS activo", HIGH, "tls",
                   f"{info.protocol}, {info.cipher}"))
    old = info.protocol in ("TLSv1", "TLSv1.1", "SSLv3")
    out.append((_bad if old else _ok)(
        "tls-version", f"Versión TLS: {info.protocol}",
        HIGH if old else INFO, "tls", info.protocol or "",
        "Deshabilitá TLS < 1.2." if old else ""))
    if info.days_left is not None:
        soon = info.days_left < 15
        out.append((_bad if soon else _ok)(
            "tls-expiry", f"Certificado vence en {info.days_left} días",
            HIGH if soon else INFO, "tls",
            f"notAfter={info.not_after}, emisor={info.issuer}",
            "Renová el certificado." if soon else ""))
    return out


def check_https_redirect(resp: Response) -> list[Finding]:
    host = resp.host
    if not host:
        return []
    r = fetch("http://" + host)
    if r.error:
        return []
    if r.scheme == "https":
        return [_ok("redirect", "HTTP redirige a HTTPS", MEDIUM, "tls",
                    " → ".join(r.redirects[-2:]) or r.final_url)]
    return [_bad("redirect", "HTTP no redirige a HTTPS", HIGH, "tls",
                 f"http://{host} responde sin upgrade",
                 "Forzá redirección 301 de http→https.")]


# ── Forms & mixed content ───────────────────────────────────────────
def check_forms(resp: Response) -> list[Finding]:
    out = []
    body = resp.body or ""
    forms = re.findall(r"<form[^>]*>.*?</form>", body, re.I | re.S)
    for f in forms:
        action = re.search(r'action\s*=\s*["\']([^"\']*)', f, re.I)
        has_pw = re.search(r'type\s*=\s*["\']password', f, re.I)
        act = action.group(1) if action else ""
        if has_pw and act.startswith("http://"):
            out.append(_bad("form-pw-http", "Formulario de password sobre HTTP",
                            CRITICAL, "forms", f"action={act}",
                            "Enviá credenciales solo por HTTPS."))
    if resp.scheme == "https":
        mixed = re.findall(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)', body, re.I)
        if mixed:
            out.append(_bad("mixed", f"Contenido mixto ({len(mixed)} recursos http)",
                            MEDIUM, "forms", mixed[0][:120],
                            "Cargá todos los recursos por HTTPS."))
    return out


# ── CORS misconfiguration ───────────────────────────────────────────
def check_cors(resp: Response) -> list[Finding]:
    probe = "https://centinela-probe.example"
    r = fetch(resp.final_url, headers={"Origin": probe})
    acao = r.headers.get("access-control-allow-origin")
    if not acao:
        return []
    creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao == probe and creds:
        return [_bad("cors", "CORS reflejado con credenciales", CRITICAL, "cors",
                     f"ACAO refleja '{probe}' + Allow-Credentials: true",
                     "No reflejes el Origin con credenciales; usá una allowlist.")]
    if acao == "*" and creds:
        return [_bad("cors", "CORS '*' junto a credenciales", HIGH, "cors",
                     "ACAO: * con Allow-Credentials: true",
                     "Combinación inválida/insegura; restringí el origen.")]
    if acao == probe or acao == "*":
        return [_bad("cors", "CORS permisivo", MEDIUM, "cors",
                     f"ACAO: {acao}", "Limitá Access-Control-Allow-Origin a tus dominios.")]
    return [_ok("cors", "CORS restringido", LOW, "cors", f"ACAO: {acao}")]


# ── HTTP methods ────────────────────────────────────────────────────
def check_methods(resp: Response) -> list[Finding]:
    r = fetch(resp.final_url, method="OPTIONS")
    allow = (r.headers.get("allow", "") + " " +
             r.headers.get("access-control-allow-methods", "")).upper()
    risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow]
    if "TRACE" in allow:
        return [_bad("trace", "Método TRACE habilitado", MEDIUM, "methods",
                     f"Allow: {allow.strip()}", "Deshabilitá TRACE (riesgo XST).")]
    if risky:
        return [_bad("methods", f"Métodos sensibles habilitados: {', '.join(risky)}",
                     LOW, "methods", f"Allow: {allow.strip()}",
                     "Permití solo los métodos que tu app realmente necesita.")]
    return []


# ── security.txt ────────────────────────────────────────────────────
def check_security_txt(base_url: str) -> list[Finding]:
    r = fetch(base_url.rstrip("/") + "/.well-known/security.txt")
    if r.status == 200 and "contact" in r.body.lower():
        return [_ok("sec-txt", "Tiene security.txt (buena práctica)", INFO,
                    "disclosure", "/.well-known/security.txt")]
    return [_bad("sec-txt", "Sin security.txt", INFO, "disclosure",
                 "no se encontró /.well-known/security.txt",
                 "Publicá un security.txt con un contacto para reportes.")]


# ── Reflected input (heurística, revisión manual) ───────────────────
def check_reflection(resp: Response) -> list[Finding]:
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
    parts = urlparse(resp.final_url)
    if not parts.query:
        return []
    marker = 'cstnl"><svg9173'
    qs = {k: marker for k in parse_qs(parts.query)}
    probe_url = urlunparse(parts._replace(query=urlencode(qs)))
    r = fetch(probe_url)
    if marker in (r.body or ""):
        return [_bad("reflect", "Parámetro reflejado sin sanitizar (posible XSS)",
                     HIGH, "injection",
                     f"el marcador se reflejó crudo en {', '.join(qs)} — revisar manualmente",
                     "Escapá/encodeá toda entrada de usuario antes de renderizarla.")]
    return [_ok("reflect", "Parámetros no reflejados sin sanitizar", LOW, "injection",
                f"probados: {', '.join(qs)}")]


def run_site(resp: Response) -> list[Finding]:
    """Chequeos a nivel sitio (se corren una vez sobre la página base)."""
    findings: list[Finding] = []
    findings += check_tls(resp)
    findings += check_https_redirect(resp)
    findings += check_headers(resp)
    findings += check_cookies(resp)
    findings += check_disclosure(resp)
    findings += check_exposed_paths(resp.final_url)
    findings += check_cors(resp)
    findings += check_methods(resp)
    findings += check_security_txt(resp.final_url)
    return findings


def run_page(resp: Response) -> list[Finding]:
    """Chequeos a nivel página (se corren por cada página crawleada)."""
    findings: list[Finding] = []
    findings += check_forms(resp)
    findings += check_reflection(resp)
    return findings


def run_all(resp: Response) -> list[Finding]:
    """Escaneo de una sola página (sitio + página)."""
    return run_site(resp) + run_page(resp)
