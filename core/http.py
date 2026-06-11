"""HTTP/TLS fetch helpers — stdlib only (urllib + ssl + socket)."""
from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

UA = "Centinela/0.1 (+https://github.com/santi/centinela) security-scanner"
TIMEOUT = 12

# Headers por defecto que se aplican a TODOS los fetch (ej. Cookie de sesión
# para escaneo autenticado). Se setean antes de un scan y se limpian al final.
_DEFAULT_HEADERS: dict[str, str] = {}


def set_default_headers(headers: dict | None) -> None:
    _DEFAULT_HEADERS.clear()
    if headers:
        _DEFAULT_HEADERS.update(headers)


@dataclass
class Response:
    requested_url: str
    final_url: str
    status: int
    headers: dict[str, str]          # lower-cased keys
    set_cookies: list[str]
    body: str
    error: str | None = None
    redirects: list[str] = field(default_factory=list)

    @property
    def scheme(self) -> str:
        return urlparse(self.final_url).scheme

    @property
    def host(self) -> str:
        return urlparse(self.final_url).hostname or ""


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def normalize(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """No sigue redirects — deja ver el 30x y su Location (para open-redirect)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str, method: str = "GET", headers: dict | None = None,
          follow: bool = True, data: dict | str | None = None) -> Response:
    url = normalize(url)
    tracker = _Redirects()
    opener = urllib.request.build_opener(tracker if follow else _NoRedirect())
    hdrs = {"User-Agent": UA}
    hdrs.update(_DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        if isinstance(data, dict):
            data = urlencode(data)
        body = data.encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if method == "GET":
            method = "POST"
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            raw = r.read(600_000) if method == "GET" else b""
            body = raw.decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in r.headers.items()}
            cookies = r.headers.get_all("Set-Cookie") or []
            return Response(url, r.url, r.status, headers, cookies, body,
                            redirects=tracker.chain)
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        return Response(url, e.url or url, e.code, headers, cookies or [], "",
                        redirects=tracker.chain)
    except Exception as e:  # noqa: BLE001 — network errors are expected
        return Response(url, url, 0, {}, [], "", error=str(e),
                        redirects=tracker.chain)


@dataclass
class TLSInfo:
    ok: bool
    protocol: str | None = None
    cipher: str | None = None
    not_after: str | None = None
    days_left: int | None = None
    issuer: str | None = None
    error: str | None = None


def tls_info(host: str, port: int = 443) -> TLSInfo:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
                cipher = ss.cipher()[0] if ss.cipher() else None
        not_after = cert.get("notAfter")
        days = None
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
        issuer = None
        for part in cert.get("issuer", ()):  # tuple of tuples
            for k, v in part:
                if k == "organizationName":
                    issuer = v
        return TLSInfo(True, proto, cipher, not_after, days, issuer)
    except Exception as e:  # noqa: BLE001
        return TLSInfo(False, error=str(e))
