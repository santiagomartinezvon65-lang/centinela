"""Centinela Recon — descubrimiento de superficie de ataque (DNS + puertos).

Enumera subdominios comunes (resolución DNS) y escanea puertos/servicios abiertos
(sockets), en paralelo. Stdlib puro. Detecta servicios riesgosos expuestos a
internet (bases de datos, RDP, Redis, etc.). Uso ético: solo dominios propios o
con permiso (un port-scan es activo).
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

from .http import normalize
from .report import PENALTY, _grade

_SUBS = [
    "www", "api", "dev", "staging", "stage", "test", "admin", "portal", "app",
    "mail", "webmail", "vpn", "ns1", "ns2", "smtp", "ftp", "cpanel", "blog",
    "shop", "store", "m", "mobile", "beta", "demo", "dashboard", "git", "gitlab",
    "jenkins", "grafana", "kibana", "status", "cdn", "assets", "static", "docs",
    "support", "help", "secure", "login", "auth", "internal", "intranet", "db",
    "database", "redis", "backup", "old", "new", "qa", "uat", "preprod", "monitor",
]

_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2375: "docker-api", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
}

# servicios que NO deberían estar expuestos a internet → (título, severidad)
_RISKY = {
    23: ("Telnet expuesto a internet (sin cifrado)", "high"),
    445: ("SMB expuesto a internet", "medium"),
    1433: ("MSSQL expuesto a internet", "high"),
    2375: ("Docker API expuesta sin TLS (riesgo de RCE)", "critical"),
    3306: ("MySQL expuesto a internet", "high"),
    3389: ("RDP expuesto a internet", "high"),
    5432: ("PostgreSQL expuesto a internet", "high"),
    5900: ("VNC expuesto a internet", "high"),
    6379: ("Redis expuesto (sin autenticación por defecto)", "critical"),
    9200: ("Elasticsearch expuesto a internet", "high"),
    11211: ("Memcached expuesto a internet", "high"),
    27017: ("MongoDB expuesto a internet", "critical"),
}


# banner/versión → vulnerabilidad conocida: (regex, descripción, severidad)
_SERVICE_CVE = [
    (r"vsftpd 2\.3\.4", "vsftpd 2.3.4 — backdoor (CVE-2011-2523, RCE)", "critical"),
    (r"ProFTPD 1\.3\.[0-3]\b", "ProFTPD viejo (CVE-2015-3306, mod_copy RCE)", "high"),
    (r"OpenSSH[_ ](?:[0-6]\.|7\.[0-3])", "OpenSSH viejo con CVEs conocidas (actualizá a 8.x+)", "medium"),
    (r"Apache/2\.4\.49", "Apache 2.4.49 — CVE-2021-41773 (path traversal/RCE)", "critical"),
    (r"Apache/2\.4\.50", "Apache 2.4.50 — CVE-2021-42013 (RCE)", "critical"),
    (r"Exim 4\.(?:8[0-9]|9[01])\b", "Exim viejo (CVE-2019-10149, RCE)", "high"),
    (r"Microsoft-IIS/[0-6]\.", "IIS muy viejo y sin soporte", "medium"),
    (r"nginx/1\.(?:[0-9]|1[0-7])\.", "nginx viejo — conviene actualizar", "low"),
]

_HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 8888}


def grab_banner(host: str, port: int, timeout: float = 1.6) -> str:
    """Conecta y captura el banner del servicio (server-first o HTTP)."""
    try:
        s = socket.create_connection((host, port), timeout)
    except OSError:
        return ""
    s.settimeout(timeout)
    try:
        try:
            data = s.recv(300)  # servicios que hablan primero (ssh/ftp/smtp/…)
        except OSError:
            data = b""
        if not data and port not in (443, 8443):  # HTTP espera un request
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = s.recv(400)
            except OSError:
                data = b""
        return _clean_banner(data.decode("latin-1", "replace"))
    finally:
        s.close()


def _clean_banner(raw: str) -> str:
    for line in raw.splitlines():
        if line.lower().startswith("server:"):
            return line.strip()
    first = next((ln.strip() for ln in raw.splitlines() if ln.strip()), "")
    return first[:90]


def _cve_for(banner: str):
    for rx, desc, sev in _SERVICE_CVE:
        if re.search(rx, banner, re.I):
            return desc, sev
    return None


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def find_subdomains(domain: str, workers: int = 40) -> list[dict]:
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(resolve, f"{s}.{domain}"): s for s in _SUBS}
        for f in futs:
            ip = f.result()
            if ip:
                out.append({"sub": f"{futs[f]}.{domain}", "ip": ip})
    return sorted(out, key=lambda x: x["sub"])


def _check_port(host: str, port: int, timeout: float) -> int | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return port if s.connect_ex((host, port)) == 0 else None
    except OSError:
        return None
    finally:
        s.close()


def scan_ports(host: str, ports=None, workers: int = 60, timeout: float = 1.2) -> list[int]:
    ports = ports or list(_PORTS)
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_check_port, host, p, timeout) for p in ports]
        for f in futs:
            p = f.result()
            if p:
                out.append(p)
    return sorted(out)


def run(target: str, do_subs: bool = True, do_ports: bool = True,
        say=print) -> dict:
    host = urlparse(normalize(target)).hostname or target
    findings: list[dict] = []
    pages = [host]

    is_ip = host.replace(".", "").isdigit()
    if do_subs and not is_ip and "." in host:
        say(f"Enumerando subdominios de {host} ({len(_SUBS)} candidatos)…")
        subs = find_subdomains(host)
        for s in subs:
            findings.append(_f(f"sub-{s['sub']}", f"Subdominio activo: {s['sub']}",
                               "info", "recon", f"{s['sub']} → {s['ip']}",
                               "Inventariá y asegurá cada subdominio; quitá los que no uses."))
        say(f"  {len(subs)} subdominio(s) activo(s).")

    if do_ports:
        say(f"Escaneando {len(_PORTS)} puertos comunes en {host}…")
        openp = scan_ports(host)
        banners: dict[int, str] = {}
        if openp:
            say("  capturando banners (versión de cada servicio)…")
            with ThreadPoolExecutor(max_workers=min(len(openp), 20)) as ex:
                for p, b in zip(openp, ex.map(lambda pp: grab_banner(host, pp), openp)):
                    banners[p] = b
        for p in openp:
            svc = _PORTS.get(p, "?")
            banner = banners.get(p, "")
            ev = f"{host}:{p} ({svc})" + (f" — {banner}" if banner else "")
            cve = _cve_for(banner) if banner else None
            if cve:
                desc, sev = cve
                findings.append(_f(f"svc-{p}", f"{desc} — puerto {p}", sev, "cve", ev,
                                   "Actualizá el servicio a una versión soportada y parcheada."))
            elif p in _RISKY:
                title, sev = _RISKY[p]
                findings.append(_f(f"port-{p}", title, sev, "network", ev,
                                   f"Cerrá el puerto {p} o restringilo por firewall/VPN; "
                                   "no expongas este servicio a internet."))
            else:
                findings.append(_f(f"port-{p}", f"Puerto {p} abierto ({svc})", "info",
                                   "network", ev,
                                   "Verificá que el servicio deba estar accesible."))
        say(f"  {len(openp)} puerto(s) abierto(s).")

    return _build(host, findings, pages)


def _f(fid, title, sev, cat, ev, fix):
    return {"id": fid, "title": title, "severity": sev, "category": cat,
            "evidence": ev, "remediation": fix, "confidence": "confirmed",
            "passed": False, "page": ""}


def _build(host: str, findings: list[dict], pages: list[str]) -> dict:
    order = list(PENALTY)
    score, counts = 100, {s: 0 for s in PENALTY}
    for f in findings:
        score -= PENALTY.get(f["severity"], 0)
        counts[f["severity"]] += 1
    score = max(0, min(100, score))
    findings.sort(key=lambda f: order.index(f["severity"]))
    risk = next((s for s in order[:4] if counts[s]), "minimal")
    n_risky = sum(1 for f in findings if f["category"] == "network" and not f["passed"]
                  and f["severity"] != "info")
    summary = (f"Recon de red sobre {host}: {len([f for f in findings if f['category'] == 'recon'])} "
               f"subdominio(s) y {len([f for f in findings if f['category'] == 'network'])} "
               f"puerto(s) abierto(s)" + (f", {n_risky} servicio(s) riesgoso(s) expuesto(s)."
                                          if n_risky else "."))
    return {
        "kind": "recon", "provider": "recon", "model": "recon de red",
        "target": f"https://{host}",
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "score": score, "grade": _grade(score), "counts": counts,
        "total_checks": len(findings), "passed": 0, "pages": pages, "profile": {},
        "http_status": 200, "reachable": True, "notice": None,
        "overall_risk": "critical" if risk == "critical" else risk,
        "summary": summary, "usage": {"input_tokens": 0, "output_tokens": 0,
                                      "est_cost_usd": 0.0}, "findings": findings,
    }
