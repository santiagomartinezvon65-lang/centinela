"""Centinela Engine — pentester autónomo por REGLAS (sin IA, sin API, sin deps).

El "cerebro" es lógica determinística codificada a mano: reconoce el objetivo,
detecta la superficie de ataque y decide qué probar según lo que encuentra
(reflejo/XSS, CORS, open-redirect, métodos peligrosos), valida y reporta.
Anda solo, offline, gratis. Uso ético: solo sitios propios/autorizados.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from .http import fetch, normalize
from .report import PENALTY, _grade
from .scanner import scan as deterministic_scan

C = {"crit": "\033[91m", "high": "\033[93m", "ok": "\033[92m", "blue": "\033[96m",
     "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}

_REDIR_PARAM = re.compile(
    r"^(next|url|redirect|redir|return|returnurl|return_url|dest|destination|"
    r"continue|goto|out|target|forward|to|r|u)$", re.I)
_MARK = "https://centinela-evil.example/pwn"
_SEV_ORDER = list(PENALTY)  # critical..info

# firmas de error SQL por motor (error-based SQLi)
_SQL_ERRORS = re.compile(
    r"(SQL syntax.*MySQL|Warning.*\bmysqli?_|valid MySQL result|"
    r"MySqlException|com\.mysql\.jdbc|PostgreSQL.{0,25}ERROR|pg_query\(\)|"
    r"PG::SyntaxError|unterminated quoted string|Microsoft SQL Server|"
    r"ODBC SQL Server Driver|Unclosed quotation mark|SqlException|"
    r"ORA-\d{5}|Oracle error|SQLite3?::|sqlite3\.OperationalError|"
    r"unrecognized token|quoted string not properly terminated|"
    r"you have an error in your sql syntax)", re.I)

# mini-base de versiones de servidor con CVE crítica conocida
_SERVER_CVES = [
    ("2.4.49", "Apache httpd 2.4.49 — CVE-2021-41773 (path traversal → RCE)",
     "Actualizá Apache httpd a 2.4.51 o superior."),
    ("2.4.50", "Apache httpd 2.4.50 — CVE-2021-42013 (path traversal → RCE)",
     "Actualizá Apache httpd a 2.4.51 o superior."),
]


_DIR_LISTING = re.compile(
    r"(Index of /|Directory listing for|<title>\s*Index of|"
    r"\[To Parent Directory\]|Parent Directory</a>)", re.I)
_BACKUP_SUFFIXES = (".bak", "~", ".old", ".save", ".orig", ".swp", ".tmp")
_ROOT_DUMPS = ("/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip",
               "/backup.sql", "/database.sql", "/db.sql", "/dump.sql", "/.env.bak")
_HIGH_BACKUP = (".sql", ".zip", ".tar.gz", ".env", ".php", ".asp", ".aspx",
                ".py", ".rb", ".config")
_XSS_PAYLOAD = 'cz9k7q"><svg/onload=1>'
_COMMON_DIRS = ("/uploads/", "/files/", "/images/", "/assets/", "/backup/",
                "/backups/", "/tmp/", "/temp/", "/old/", "/test/")


# wordlist de descubrimiento: (path, severidad, firma_regex|None, título)
_WORDLIST = [
    ("/.git/config", "high", r"\[core\]|repositoryformatversion", "Repositorio .git expuesto"),
    ("/.git/HEAD", "high", r"ref:\s*refs/", "Repositorio .git expuesto"),
    ("/.env", "critical", r"(?m)^[A-Z0-9_]+=", "Archivo .env con variables/secretos expuesto"),
    ("/.env.local", "critical", r"(?m)^[A-Z0-9_]+=", "Archivo .env.local expuesto"),
    ("/wp-config.php", "high", r"DB_PASSWORD|DB_NAME", "wp-config.php expuesto"),
    ("/phpinfo.php", "high", r"phpinfo\(\)|PHP Version", "phpinfo() expuesto"),
    ("/info.php", "high", r"phpinfo\(\)|PHP Version", "phpinfo() expuesto"),
    ("/server-status", "medium", r"Apache Server Status", "mod_status (server-status) expuesto"),
    ("/server-info", "medium", r"Apache Server Information", "mod_info (server-info) expuesto"),
    ("/actuator/env", "high", r"propertySources|systemEnvironment", "Spring Actuator /env expuesto"),
    ("/actuator/health", "low", r'"status"\s*:', "Spring Actuator expuesto"),
    ("/.aws/credentials", "critical", r"aws_access_key_id", "Credenciales AWS expuestas"),
    ("/config.json", "medium", r"[{].*[}]", "config.json accesible"),
    ("/swagger.json", "low", r"swagger|openapi", "Documentación de API (Swagger) expuesta"),
    ("/openapi.json", "low", r"openapi", "Especificación OpenAPI expuesta"),
    ("/api-docs", "low", r"swagger|openapi", "Documentación de API expuesta"),
    ("/.DS_Store", "low", r"Bud1|\x00\x00\x00", "Archivo .DS_Store expuesto"),
    ("/.htaccess", "medium", r"Rewrite|Order |Deny ", ".htaccess accesible"),
]

# patrones de secretos en respuestas/JS
_SECRETS = [
    ("AWS Access Key", "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", "high", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe live key", "critical", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("GitHub token", "critical", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Slack token", "high", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Private key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", "low", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]
_GENERIC_SECRET = re.compile(
    r"""(?i)(api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|password)"""
    r"""\s*[:=]\s*['"][^'"\s]{8,}['"]""")

# LFI / path traversal
_LFI = [("../../../../../../etc/passwd", re.compile(r"root:.*:0:0:")),
        (r"..\..\..\..\..\..\windows\win.ini", re.compile(r"\[fonts\]|\[extensions\]|16-bit app support"))]
# SSTI (producto poco común para evitar falsos positivos)
_SSTI = [("{{31337*31337}}", "981801769"), ("${31337*31337}", "981801769"),
         ("#{31337*31337}", "981801769"), ("<%= 31337*31337 %>", "981801769")]

# JWT: detección de tokens + secretos HMAC débiles
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}")
_JWT_SECRETS = ["secret", "password", "123456", "changeme", "jwt", "key", "admin",
                "test", "your-256-bit-secret", "secretkey", "mysecret", "jwtsecret",
                "supersecret", "secret123", "qwerty", "letmein", "token", "private",
                "jwt_secret", "app_secret", "s3cr3t", "default", "1234567890"]
# command injection (payloads de solo lectura: id/dir, no destructivos)
_CMDI = [(";id", r"uid=\d+\("), ("|id", r"uid=\d+\("), ("$(id)", r"uid=\d+\("),
         ("`id`", r"uid=\d+\("), ("& dir", r"Volume Serial Number|<DIR>")]
_NOSQL_ERRORS = re.compile(
    r"(MongoError|MongoServerError|BSONError|E11000|com\.mongodb|mongoose|"
    r"CastError|\$where|unexpected token .*in JSON)", re.I)


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwt_analyze(token: str) -> list[tuple]:
    """Devuelve issues (id, title, severidad, evidencia) de un JWT."""
    issues = []
    try:
        h, p, sig = token.split(".")
        header = json.loads(_b64url(h))
        payload = json.loads(_b64url(p))
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return issues
    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        issues.append(("jwt-none", "JWT acepta alg:none (firma omitible)", "critical",
                       f"header alg={header.get('alg')!r} — se puede falsificar sin firma"))
    if alg == "hs256":
        signing = (h + "." + p).encode()
        try:
            sigb = _b64url(sig)
        except binascii.Error:
            sigb = b""
        for sec in _JWT_SECRETS:
            if hmac.compare_digest(
                    hmac.new(sec.encode(), signing, hashlib.sha256).digest(), sigb):
                issues.append(("jwt-weak", "JWT firmado con secreto HMAC débil", "critical",
                               f"secreto adivinado: '{sec}' → se pueden forjar tokens válidos"))
                break
    if "exp" not in payload:
        issues.append(("jwt-noexp", "JWT sin expiración (claim exp)", "medium",
                       "el token no caduca nunca"))
    sens = [k for k in payload if k.lower() in
            ("password", "pwd", "secret", "ssn", "credit_card", "card", "apikey", "api_key")]
    if sens:
        issues.append(("jwt-sensitive", "JWT con datos sensibles en el payload", "medium",
                       f"claims: {', '.join(sens)} — el payload es legible por cualquiera"))
    return issues


# categoría interna → OWASP Top 10 2021 (para el informe profesional)
_OWASP = {
    "injection": "A03:2021 Inyección", "xss": "A03:2021 Inyección",
    "cve": "A06:2021 Componentes vulnerables y desactualizados",
    "secrets": "A02:2021 Fallas criptográficas", "tls": "A02:2021 Fallas criptográficas",
    "csrf": "A01:2021 Pérdida de control de acceso",
    "redirect": "A01:2021 Pérdida de control de acceso",
    "cors": "A05:2021 Configuración de seguridad incorrecta",
    "headers": "A05:2021 Configuración de seguridad incorrecta",
    "cookies": "A05:2021 Configuración de seguridad incorrecta",
    "methods": "A05:2021 Configuración de seguridad incorrecta",
    "disclosure": "A05:2021 Configuración de seguridad incorrecta",
}
_OWASP_DEFAULT = "A05:2021 Configuración de seguridad incorrecta"


def _root(u: str) -> str:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def _say(msg: str) -> None:
    print(f"{C['blue']}▸{C['x']} {msg}")


class LocalPentester:
    def __init__(self, target: str, lab: bool = False, max_pages: int = 12,
                 request_budget: int = 240):
        self.target = normalize(target)
        self.lab = lab
        self.max_pages = max_pages
        self.budget = request_budget
        self.findings: list[dict] = []
        self.pages: list[str] = []
        self.notice = None
        self.http_status = 200
        self.reachable = True
        self.steps = 0

    def _add(self, fid, title, sev, cat, ev, fix, conf="confirmed", page=""):
        self.findings.append({
            "id": fid, "title": title, "severity": sev, "category": cat,
            "evidence": ev, "remediation": fix, "confidence": conf,
            "owasp": _OWASP.get(cat, _OWASP_DEFAULT), "passed": False, "page": page})
        col = C["crit"] if sev in ("critical", "high") else C["dim"]
        print(f"  {col}✚ {sev.upper()}{C['x']} {title}")

    def _parallel(self, items: list, worker, workers: int = 12) -> list:
        """Corre worker(item) en paralelo (solo I/O en threads). Devuelve los
        resultados no-None en orden. _add se llama después, en el hilo principal."""
        take = min(len(items), max(self.budget, 0))
        if take <= 0:
            return []
        items = items[:take]
        self.budget -= take
        self.steps += take
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return [r for r in ex.map(worker, items) if r]

    # ── flujo principal ─────────────────────────────────────────────
    def run(self) -> dict:
        mode = "LAB" if self.lab else "normal (no destructivo)"
        print(f"{C['b']}🛡  Centinela Engine → {self.target}{C['x']}  "
              f"{C['dim']}[motor de reglas · sin IA · modo {mode}]{C['x']}\n")

        # 1) Reconocimiento determinístico (incluye crawl + chequeos de sitio/página)
        _say("Reconocimiento: chequeos de seguridad + crawl del sitio…")
        report, err = deterministic_scan(self.target, crawl=True, max_pages=self.max_pages)
        if err:
            self.reachable = False
            self.notice = f"No se pudo conectar: {err}"
            _say(f"{C['crit']}{self.notice}{C['x']}")
            return self._build_report()

        self.pages = report["pages"]
        self.http_status = report["http_status"]
        self.reachable = report["reachable"]
        self.notice = report["notice"]
        if self.notice:
            _say(f"{C['high']}{self.notice}{C['x']}")

        base_fail = [f for f in report["findings"] if not f["passed"]]
        for f in base_fail:
            f.setdefault("confidence", "confirmed")
            f["owasp"] = _OWASP.get(f.get("category", ""), _OWASP_DEFAULT)
        self.findings.extend(base_fail)
        _say(f"Mapeé {len(self.pages)} página(s); el barrido base dejó "
             f"{len(base_fail)} hallazgo(s). Ahora decido qué validar a fondo.")

        # 2) Ampliar superficie con robots.txt / sitemap.xml
        self._ingest_robots_sitemap()

        # 3) Fingerprint de tecnología + CVEs conocidas
        self._probe_fingerprint()

        # 4) Descubrimiento de rutas sensibles + plantillas + secretos + JWT
        self._probe_content_discovery()
        self._probe_templates()
        self._probe_secrets()
        self._probe_jwt()

        # 5) Formularios (CSRF + inyección en POST) e inyección en parámetros
        self._probe_forms()
        self._probe_sqli()
        self._probe_nosql()
        self._probe_xss()
        self._probe_injection_deep()       # LFI/path-traversal + SSTI
        self._probe_command_injection()    # command injection
        self._probe_open_redirect()

        # 6) Descubrimiento de archivos y directorios
        self._probe_backups()
        self._probe_dir_listing()

        # 7) Cerrar
        _say("Sin más hipótesis abiertas. Cierro y armo el informe.")
        return self._build_report()

    # ── fingerprint de tecnología + CVEs conocidas ──────────────────
    def _probe_fingerprint(self) -> None:
        self.budget -= 1
        self.steps += 1
        base = fetch(self.target)
        if base.error:
            return
        h, body = base.headers, base.body or ""
        detected = [(k, h[k]) for k in
                    ("server", "x-powered-by", "x-aspnet-version", "x-generator")
                    if k in h]
        mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                       body, re.I)
        if mg:
            detected.append(("generator", mg.group(1)))
        libs = self._detect_libs(body)

        if detected or libs:
            ev = " · ".join([f"{k}: {v}" for k, v in detected]
                            + [f"{n} {ver}" for n, ver in libs])
            _say(f"Fingerprint: {ev[:120]}")
            self._add("fingerprint", "Tecnología/versión expuesta", "info", "disclosure",
                      ev[:220], "Ocultá versiones en headers/HTML para dificultar el "
                      "targeting de exploits.", conf="confirmed")
        else:
            _say("Sin versiones expuestas para fingerprint.")
        self._match_cves(detected, libs)

    def _detect_libs(self, body: str) -> list[tuple[str, str]]:
        out, seen = [], set()
        for name in ("jquery", "bootstrap", "angular", "lodash"):
            for m in re.finditer(name + r"[-./@](\d+\.\d+(?:\.\d+)?)", body, re.I):
                key = (name, m.group(1))
                if key not in seen:
                    seen.add(key)
                    out.append(key)
        return out

    @staticmethod
    def _vlt(a: str, b: str) -> bool:
        pa = [int(x) for x in re.findall(r"\d+", a)]
        pb = [int(x) for x in re.findall(r"\d+", b)]
        n = max(len(pa), len(pb))
        pa += [0] * (n - len(pa))
        pb += [0] * (n - len(pb))
        return pa < pb

    def _match_cves(self, detected: list, libs: list) -> None:
        server = next((v for k, v in detected if k == "server"), "")
        for needle, title, fix in _SERVER_CVES:
            if needle in server:
                self._add(f"cve-srv-{needle}", title, "critical", "cve",
                          f"Server: {server}", fix, conf="likely")
        for name, ver in libs:
            if name == "jquery" and self._vlt(ver, "3.5.0"):
                self._add(f"cve-jquery-{ver}",
                          f"jQuery {ver} — XSS conocido (CVE-2020-11022/11023)",
                          "medium", "cve", f"jQuery {ver} < 3.5.0",
                          "Actualizá jQuery a 3.5.0 o superior.", conf="likely")
            elif name == "bootstrap" and (self._vlt(ver, "3.4.0") or (
                    not self._vlt(ver, "4.0.0") and self._vlt(ver, "4.3.1"))):
                self._add(f"cve-bootstrap-{ver}",
                          f"Bootstrap {ver} — XSS en data-attributes (CVE-2019-8331)",
                          "medium", "cve", f"Bootstrap {ver} vulnerable",
                          "Actualizá Bootstrap a 3.4.1+/4.3.1+.", conf="likely")
            elif name == "lodash" and self._vlt(ver, "4.17.12"):
                self._add(f"cve-lodash-{ver}",
                          f"Lodash {ver} — prototype pollution (CVE-2019-10744)",
                          "high", "cve", f"Lodash {ver} < 4.17.12",
                          "Actualizá Lodash a 4.17.12 o superior.", conf="likely")

    # ── probe adaptativo: SQL injection (error-based) ───────────────
    def _probe_sqli(self) -> None:
        targets = [(p, parse_qs(urlparse(p).query)) for p in self.pages
                   if urlparse(p).query]
        if not targets:
            _say("No hay parámetros con valores — salteo SQLi.")
            return
        _say(f"Probando SQLi error-based (inyecto ') en {len(targets)} página(s)…")
        for page, qs in targets:
            base = fetch(page)
            base_err = True if base.error else bool(_SQL_ERRORS.search(base.body or ""))
            for param in qs:
                if self.budget <= 0:
                    return
                self.budget -= 1
                self.steps += 1
                newqs = {k: (v[0] + "'") if k == param else v[0] for k, v in qs.items()}
                test = urlunparse(urlparse(page)._replace(query=urlencode(newqs)))
                r = fetch(test)
                if r.error:
                    continue
                m = _SQL_ERRORS.search(r.body or "")
                if m and not base_err:
                    self._add(
                        f"sqli-{param}",
                        f"Posible SQL injection en parámetro '{param}'",
                        "high", "injection",
                        f"inyectar ' en '{param}' disparó un error SQL: «{m.group(0)[:70]}»",
                        "Usá consultas parametrizadas (prepared statements); nunca "
                        "concatenes input del usuario en el SQL.", conf="likely", page=page)
                    break  # un hallazgo por página alcanza

    # ── probe adaptativo: open redirect ─────────────────────────────
    def _probe_open_redirect(self) -> None:
        targets = []
        for page in self.pages:
            qs = parse_qs(urlparse(page).query)
            params = [k for k in qs if _REDIR_PARAM.match(k)]
            if params:
                targets.append((page, qs, params))
        if not targets:
            _say("No vi parámetros de redirección — salteo el test de open-redirect.")
            return

        _say(f"Detecté parámetros sospechosos de redirección en {len(targets)} "
             f"página(s) → pruebo open-redirect con un destino externo.")
        for page, qs, params in targets:
            for p in params:
                if self.budget <= 0:
                    return
                self.budget -= 1
                self.steps += 1
                newqs = {k: (_MARK if k == p else v[0]) for k, v in qs.items()}
                test = urlunparse(urlparse(page)._replace(query=urlencode(newqs)))
                r = fetch(test, follow=False)
                loc = r.headers.get("location", "")
                if r.status in (301, 302, 303, 307, 308) and "centinela-evil" in loc:
                    self._add(
                        f"openredir-{p}", f"Open redirect vía parámetro '{p}'",
                        "medium", "redirect",
                        f"{p}={_MARK} → HTTP {r.status} Location: {loc[:120]}",
                        "Validá/allowlist el destino de redirección; no uses el "
                        "valor del parámetro directamente.",
                        page=page)

    # ── probe adaptativo: XSS reflejado confirmado ──────────────────
    def _probe_xss(self) -> None:
        targets = [(p, parse_qs(urlparse(p).query)) for p in self.pages
                   if urlparse(p).query]
        if not targets:
            return
        _say(f"Confirmando XSS (payload que rompe contexto) en {len(targets)} página(s)…")
        for page, qs in targets:
            for param in qs:
                if self.budget <= 0:
                    return
                self.budget -= 1
                self.steps += 1
                newqs = {k: (_XSS_PAYLOAD if k == param else v[0]) for k, v in qs.items()}
                test = urlunparse(urlparse(page)._replace(query=urlencode(newqs)))
                r = fetch(test)
                if r.error:
                    continue
                body = r.body or ""
                if _XSS_PAYLOAD in body or 'cz9k7q"><' in body:
                    self._add(
                        f"xss-{param}", f"XSS reflejado en parámetro '{param}'",
                        "high", "xss",
                        f"el payload se reflejó SIN sanitizar en '{param}': «{_XSS_PAYLOAD}»",
                        "Escapá/encodeá toda salida según el contexto (HTML, atributo, JS).",
                        conf="confirmed", page=page)
                    break

    # ── descubrimiento: backups / archivos viejos ───────────────────
    def _probe_backups(self) -> None:
        cands: list[str] = []
        for page in self.pages:
            path = urlparse(page).path
            if "." in path.rsplit("/", 1)[-1]:
                for suf in _BACKUP_SUFFIXES:
                    cands.append(_root(page) + path + suf)
        for d in _ROOT_DUMPS:
            cands.append(_root(self.target) + d)
        cands = list(dict.fromkeys(cands))
        if not cands:
            return
        _say(f"Buscando backups/archivos viejos ({len(cands)} candidatos, en paralelo)…")

        def w(url):
            r = fetch(url)
            ct = r.headers.get("content-type", "").lower()
            if r.status == 200 and r.body and "html" not in ct:
                sev = "high" if any(e in url for e in _HIGH_BACKUP) else "medium"
                return (f"backup-{url[-32:]}", "Archivo de backup/sensible accesible",
                        sev, "disclosure",
                        f"{url} → 200 ({ct or 'sin content-type'}, {len(r.body)} bytes)",
                        "Quitá el archivo del webroot o bloqueá su acceso en el servidor.",
                        "confirmed", "")
            return None

        for args in self._parallel(cands, w):
            self._add(*args)

    # ── descubrimiento: directory listing ───────────────────────────
    def _probe_dir_listing(self) -> None:
        dirs = set()
        for page in self.pages:
            path = urlparse(page).path
            d = (path.rsplit("/", 1)[0] + "/") if "/" in path else "/"
            dirs.add(_root(page) + d)
        for d in _COMMON_DIRS:
            dirs.add(_root(self.target) + d)
        _say(f"Chequeando directory listing en {len(dirs)} directorio(s), en paralelo…")

        def w(url):
            r = fetch(url)
            if r.status == 200 and _DIR_LISTING.search(r.body or ""):
                return (f"dirlist-{url[-28:]}", "Directory listing habilitado",
                        "medium", "disclosure",
                        f"{url} expone el listado de archivos del directorio",
                        "Deshabilitá el autoindex (Apache: Options -Indexes; "
                        "nginx: autoindex off).", "confirmed", "")
            return None

        for args in self._parallel(list(dirs), w):
            self._add(*args)

    # ── recon: robots.txt / sitemap.xml → amplía la superficie ──────
    def _ingest_robots_sitemap(self) -> None:
        root = _root(self.target)
        host = urlparse(self.target).hostname
        added = 0
        self.budget -= 1
        self.steps += 1
        r = fetch(root + "/robots.txt")
        if r.status == 200 and r.body:
            sensitive = []
            for line in r.body.splitlines():
                m = re.match(r"\s*(?:Disallow|Allow)\s*:\s*(\S+)", line, re.I)
                if not m:
                    continue
                path = m.group(1)
                if path.startswith("/") and path not in ("/", ""):
                    u = root + path
                    if u not in self.pages and len(self.pages) < 40:
                        self.pages.append(u)
                        added += 1
                    if re.search(r"admin|secret|backup|config|private|api|internal|hidden|panel",
                                 path, re.I):
                        sensitive.append(path)
            if sensitive:
                self._add("robots-leak", "robots.txt revela rutas sensibles", "low",
                          "disclosure", "Disallow: " + ", ".join(sensitive[:8]),
                          "No uses robots.txt para ocultar rutas sensibles; protegelas "
                          "con autenticación/autorización.", conf="confirmed")
        self.budget -= 1
        self.steps += 1
        s = fetch(root + "/sitemap.xml")
        if s.status == 200 and "<loc>" in (s.body or ""):
            for m in re.finditer(r"<loc>\s*([^<]+?)\s*</loc>", s.body):
                u = m.group(1).strip()
                if (urlparse(u).hostname == host and u not in self.pages
                        and len(self.pages) < 40):
                    self.pages.append(u)
                    added += 1
        if added:
            _say(f"robots/sitemap sumaron {added} ruta(s) a la superficie de ataque.")

    # ── motor de plantillas (estilo Nuclei, extensible sin código) ──
    def _probe_templates(self) -> None:
        from . import templates as T
        tdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "templates")
        tpls = T.load(tdir)
        if not tpls:
            return
        items = [(tpl, req) for tpl in tpls for req in tpl.get("requests", [])]
        _say(f"Plantillas: {len(tpls)} cargada(s) → {len(items)} chequeo(s) en paralelo…")

        def w(item):
            tpl, req = item
            url, resp = T.do_request(self.target, req, fetch)
            if resp is None or not T.matches(resp, req):
                return None
            info = tpl["info"]
            return (f"tpl-{tpl['id']}", info["name"], info.get("severity", "info"),
                    info.get("category", "template"),
                    f"{url} → {resp.status} (plantilla {tpl['id']})",
                    info.get("remediation", ""), "confirmed", "")

        seen = set()
        for args in self._parallel(items, w):
            if args[0] in seen:
                continue
            seen.add(args[0])
            self._add(*args)

    # ── descubrimiento de rutas sensibles (content discovery) ───────
    def _probe_content_discovery(self) -> None:
        root = _root(self.target)
        _say(f"Descubrimiento de rutas sensibles ({len(_WORDLIST)} candidatas, en paralelo)…")

        def w(entry):
            path, sev, sig, title = entry
            r = fetch(root + path)
            if r.status != 200 or not r.body:
                return None
            ct = r.headers.get("content-type", "").lower()
            hit = bool(re.search(sig, r.body)) if sig else ("html" not in ct)
            if not hit:
                return None
            return (f"disc-{path}", title, sev, "disclosure",
                    f"{root + path} → 200 ({len(r.body)} bytes)",
                    "Quitá o protegé el recurso: no debería ser accesible públicamente.",
                    "confirmed", "")

        for args in self._parallel(_WORDLIST, w):
            self._add(*args)

    # ── secretos / API keys filtrados en HTML y JS ──────────────────
    def _probe_secrets(self) -> None:
        host = urlparse(self.target).hostname
        bodies: dict[str, str] = {}
        js: set[str] = set()
        for page in [self.target] + self.pages[:6]:
            if self.budget <= 0:
                break
            self.budget -= 1
            self.steps += 1
            r = fetch(page)
            if r.error or not r.body:
                continue
            bodies[page] = r.body
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)', r.body, re.I):
                u = urljoin(page, m.group(1)).split("#")[0]
                if urlparse(u).hostname == host:
                    js.add(u)
        for u in list(js)[:12]:
            if self.budget <= 0:
                break
            self.budget -= 1
            self.steps += 1
            r = fetch(u)
            if not r.error and r.body:
                bodies[u] = r.body
        _say(f"Buscando secretos en {len(bodies)} recurso(s) (HTML+JS)…")
        seen = set()
        generic_done = False
        for src, body in bodies.items():
            for name, sev, rx in _SECRETS:
                m = rx.search(body)
                if m and name not in seen:
                    seen.add(name)
                    self._add(f"secret-{name}", f"Secreto filtrado: {name}", sev, "secrets",
                              f"en {src.rsplit('/', 1)[-1] or src}: {m.group(0)[:26]}…",
                              "Rotá la credencial YA y sacala del código cliente "
                              "(movela al backend / variables de entorno).", conf="confirmed")
            if not generic_done and not seen and _GENERIC_SECRET.search(body):
                generic_done = True
                self._add("secret-generic", "Posible credencial hardcodeada", "medium",
                          "secrets", f"asignación tipo api_key/secret en {src.rsplit('/', 1)[-1]}",
                          "Revisá si es un secreto real; movelo al backend.", conf="needs-review")

    # ── inyección avanzada: LFI/path-traversal + SSTI ───────────────
    def _probe_injection_deep(self) -> None:
        targets = [(p, parse_qs(urlparse(p).query)) for p in self.pages
                   if urlparse(p).query]
        if not targets:
            return
        _say(f"Inyección avanzada (LFI/path-traversal + SSTI) en {len(targets)} página(s)…")
        for page, qs in targets:
            for param in qs:
                if self._inject_once(page, qs, param, _LFI, "lfi",
                                     "Path traversal / LFI en", "critical",
                                     "el payload de traversal devolvió contenido de un "
                                     "archivo del sistema",
                                     "Validá/normalizá rutas; nunca abras archivos con "
                                     "input del usuario sin allowlist."):
                    continue
                self._inject_ssti(page, qs, param)

    def _inject_once(self, page, qs, param, payloads, pid, title, sev, ev, fix) -> bool:
        for payload, sig in payloads:
            if self.budget <= 0:
                return False
            self.budget -= 1
            self.steps += 1
            nq = {k: (payload if k == param else v[0]) for k, v in qs.items()}
            test = urlunparse(urlparse(page)._replace(query=urlencode(nq)))
            r = fetch(test)
            if not r.error and sig.search(r.body or ""):
                self._add(f"{pid}-{param}", f"{title} '{param}'", sev, "injection",
                          f"{ev} (parámetro '{param}')", fix, conf="confirmed", page=page)
                return True
        return False

    def _inject_ssti(self, page, qs, param) -> None:
        for payload, expect in _SSTI:
            if self.budget <= 0:
                return
            self.budget -= 1
            self.steps += 1
            nq = {k: (payload if k == param else v[0]) for k, v in qs.items()}
            test = urlunparse(urlparse(page)._replace(query=urlencode(nq)))
            r = fetch(test)
            if not r.error and expect in (r.body or ""):
                self._add(f"ssti-{param}", f"Server-Side Template Injection en '{param}'",
                          "critical", "injection",
                          f"'{param}'={payload} evaluó la expresión (apareció {expect})",
                          "No metas input del usuario en plantillas del servidor; "
                          "renderizá con contexto seguro/sandbox.", conf="confirmed", page=page)
                return

    # ── formularios: CSRF + inyección en POST/GET ───────────────────
    _CSRF_RE = re.compile(r"csrf|token|nonce|authenticity|verification|xsrf", re.I)
    _INJECTABLE = ("text", "search", "email", "url", "", "textarea", "password", "tel")

    def _parse_forms(self, body: str, page_url: str) -> list[dict]:
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
                fields.append({"name": nm.group(1),
                               "type": (tm.group(1).lower() if tm else "text"),
                               "value": vm.group(1) if vm else ""})
            if fields:
                forms.append({"method": method, "action": action, "fields": fields})
        return forms

    def _probe_forms(self) -> None:
        seen = set()
        forms = []
        for page in self.pages[:8]:
            if self.budget <= 0:
                break
            self.budget -= 1
            self.steps += 1
            r = fetch(page)
            if r.error or not r.body:
                continue
            for form in self._parse_forms(r.body, page):
                key = (form["method"], form["action"],
                       tuple(f["name"] for f in form["fields"]))
                if key not in seen:
                    seen.add(key)
                    forms.append((form, page))
        if not forms:
            return
        _say(f"Analizando {len(forms)} formulario(s): CSRF + inyección en campos…")
        for form, page in forms:
            self._test_form(form, page)

    def _submit(self, form: dict, data: dict):
        if form["method"] == "post":
            return fetch(form["action"], method="POST", data=data)
        sep = "&" if urlparse(form["action"]).query else "?"
        return fetch(form["action"] + sep + urlencode(data))

    def _test_form(self, form: dict, page: str) -> None:
        if form["method"] == "post" and not any(
                self._CSRF_RE.search(f["name"]) for f in form["fields"]):
            self._add(f"csrf-{form['action'][-28:]}",
                      "Formulario POST sin token anti-CSRF", "medium", "csrf",
                      f"{form['action']} acepta POST sin token CSRF visible",
                      "Agregá un token anti-CSRF por sesión y validalo en el servidor.",
                      conf="likely", page=page)
        targets = [f for f in form["fields"] if f["type"] in self._INJECTABLE][:3]
        if not targets:
            return
        base = {f["name"]: (f["value"] or "test") for f in form["fields"]
                if f["type"] not in ("submit", "button", "image", "file", "reset")}
        for fld in targets:
            if self.budget <= 0:
                return
            self.budget -= 1
            self.steps += 1
            r = self._submit(form, {**base, fld["name"]: "test'"})
            if r and not r.error and _SQL_ERRORS.search(r.body or ""):
                self._add(f"sqli-form-{fld['name']}",
                          f"SQL injection en formulario (campo '{fld['name']}')",
                          "high", "injection",
                          f"inyectar ' en '{fld['name']}' de {form['action']} disparó error SQL",
                          "Usá prepared statements; no concatenes input en SQL.",
                          conf="likely", page=page)
                return
        for fld in targets:
            if self.budget <= 0:
                return
            self.budget -= 1
            self.steps += 1
            r = self._submit(form, {**base, fld["name"]: _XSS_PAYLOAD})
            if r and not r.error and _XSS_PAYLOAD in (r.body or ""):
                self._add(f"xss-form-{fld['name']}",
                          f"XSS reflejado en formulario (campo '{fld['name']}')",
                          "high", "xss",
                          f"el payload se reflejó sin sanitizar desde el campo '{fld['name']}'",
                          "Escapá/encodeá la salida según el contexto.",
                          conf="confirmed", page=page)
                return

    # ── JWT: tokens débiles / mal configurados ──────────────────────
    def _probe_jwt(self) -> None:
        tokens: set[str] = set()
        sources = []
        base = fetch(self.target)
        self.budget -= 1
        self.steps += 1
        sources.append(base.body or "")
        sources += base.set_cookies or []
        for page in self.pages[:5]:
            if self.budget <= 0:
                break
            self.budget -= 1
            self.steps += 1
            r = fetch(page)
            if not r.error:
                sources.append(r.body or "")
                sources += r.set_cookies or []
        for src in sources:
            for m in _JWT_RE.finditer(src):
                tokens.add(m.group(0))
        if not tokens:
            return
        _say(f"Analizando {len(tokens)} JWT encontrado(s)…")
        seen = set()
        for tok in list(tokens)[:6]:
            for fid, title, sev, ev in _jwt_analyze(tok):
                if fid in seen:
                    continue
                seen.add(fid)
                self._add(fid, title, sev, "auth", ev,
                          "Usá un algoritmo fijo (RS256 o HS256 con secreto fuerte y "
                          "aleatorio), exp corto, y no pongas datos sensibles en el payload.",
                          conf="confirmed")

    # ── NoSQL injection (error-based) ───────────────────────────────
    def _probe_nosql(self) -> None:
        targets = [(p, parse_qs(urlparse(p).query)) for p in self.pages
                   if urlparse(p).query]
        if not targets:
            return
        _say(f"Probando NoSQL injection en {len(targets)} página(s)…")
        for page, qs in targets:
            base = fetch(page)
            base_err = True if base.error else bool(_NOSQL_ERRORS.search(base.body or ""))
            for param in qs:
                if self.budget <= 0:
                    return
                self.budget -= 1
                self.steps += 1
                nq = {k: (qs[k][0] + "'\"{" if k == param else qs[k][0]) for k in qs}
                test = urlunparse(urlparse(page)._replace(query=urlencode(nq)))
                r = fetch(test)
                if not r.error and _NOSQL_ERRORS.search(r.body or "") and not base_err:
                    self._add(f"nosql-{param}", f"Posible NoSQL injection en '{param}'",
                              "high", "injection",
                              f"caracteres especiales en '{param}' dispararon un error de NoSQL",
                              "Validá/sanitizá el input y usá el query builder del driver.",
                              conf="likely", page=page)
                    break

    # ── command injection (payloads de solo lectura) ────────────────
    def _probe_command_injection(self) -> None:
        targets = [(p, parse_qs(urlparse(p).query)) for p in self.pages
                   if urlparse(p).query]
        if not targets:
            return
        _say(f"Probando command injection en {len(targets)} página(s)…")
        for page, qs in targets:
            for param in qs:
                for payload, sig in _CMDI:
                    if self.budget <= 0:
                        return
                    self.budget -= 1
                    self.steps += 1
                    nq = {k: (qs[k][0] + payload if k == param else qs[k][0]) for k in qs}
                    test = urlunparse(urlparse(page)._replace(query=urlencode(nq)))
                    r = fetch(test)
                    if not r.error and re.search(sig, r.body or ""):
                        self._add(f"cmdi-{param}", f"Command injection en '{param}'",
                                  "critical", "injection",
                                  f"el payload «{payload}» en '{param}' ejecutó un comando del SO",
                                  "Nunca pases input del usuario a comandos del sistema; "
                                  "usá APIs nativas y listas blancas estrictas.",
                                  conf="confirmed", page=page)
                        return

    # ── informe (mismo shape que el agente, viewable en el dashboard) ─
    def _build_report(self) -> dict:
        score = 100
        counts = {s: 0 for s in PENALTY}
        for f in self.findings:
            score -= PENALTY.get(f["severity"], 0)
            counts[f["severity"]] += 1
        score = max(0, min(100, score))
        findings = sorted(self.findings, key=lambda f: _SEV_ORDER.index(f["severity"]))
        owasp: dict[str, int] = {}
        for f in findings:
            owasp[f.get("owasp", _OWASP_DEFAULT)] = owasp.get(
                f.get("owasp", _OWASP_DEFAULT), 0) + 1

        return {
            "kind": "agent", "provider": "engine", "model": "motor de reglas (sin IA)",
            "target": self.target,
            "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "score": score, "grade": _grade(score), "counts": counts,
            "total_checks": len(self.findings), "passed": 0,
            "pages": self.pages or [self.target], "profile": {},
            "http_status": self.http_status, "reachable": self.reachable,
            "notice": self.notice, "lab": self.lab, "steps": self.steps,
            "overall_risk": self._risk(counts),
            "owasp": owasp,
            "summary": self._summary(counts, findings),
            "usage": {"input_tokens": 0, "output_tokens": 0, "est_cost_usd": 0.0},
            "findings": findings,
        }

    def _risk(self, c: dict) -> str:
        if c["critical"]:
            return "critical"
        if c["high"]:
            return "high"
        if c["medium"]:
            return "medium"
        if c["low"]:
            return "low"
        return "minimal"

    def _summary(self, c: dict, findings: list[dict]) -> str:
        if not self.reachable:
            return f"No se pudo evaluar el sitio (HTTP {self.http_status}). " + (self.notice or "")
        n = len(self.findings)
        if n == 0:
            return (f"Pentesteé {len(self.pages)} página(s) sin IA y no encontré "
                    "vulnerabilidades de impacto. El sitio pasó los controles probados.")
        top = findings[0]
        return (f"Pentest determinístico sobre {len(self.pages)} página(s): {n} "
                f"hallazgo(s) — {c['critical']} críticas, {c['high']} altas, "
                f"{c['medium']} medias, {c['low']} bajas. Lo más grave: "
                f"«{top['title']}» ({top['severity']}). Revisá cada hallazgo para "
                "la remediación concreta.")
