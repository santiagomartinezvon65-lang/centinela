"""Lab vulnerable LOCAL (offline) para el benchmark — sin internet, determinista.

Sirve para demostrar el valor del cerebro propio de forma reproducible: incluye
un SQL injection CIEGO (boolean-blind) que NO tira error ni refleja nada, así que
el motor de reglas (error-based) no lo ve, pero la capa boolean del `brain` sí.

Vulnerabilidades a propósito:
  • /search?q=   → XSS reflejado            (lo cazan engine y brain)
  • /user?uid=   → SQLi boolean-blind       (SOLO lo caza el brain)
  • /.env        → fuga de secretos          (ambos)
  • sin headers de seguridad                 (ambos)

Solo librería estándar. NO exponer en una red real: es vulnerable a propósito.
"""
from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Ground-truth para el scoring del benchmark (mismo formato que bench/targets.json)
VULNS = [
    {"id": "xss", "label": "XSS reflejado", "severity": "high",
     "match": ["xss", "cross-site script", "reflej"]},
    {"id": "sqli", "label": "SQLi boolean-blind", "severity": "high",
     "match": ["sql"]},
    {"id": "env", "label": "Fuga de .env", "severity": "critical",
     "match": [".env"]},
    {"id": "headers", "label": "Faltan headers de seguridad", "severity": "medium",
     "match": ["hsts", "strict-transport", "content-security-policy",
               "x-content-type", "x-frame"]},
]


class _VulnApp(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _html(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()  # a propósito: SIN headers de seguridad
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            return self._html(
                "<html><body><h1>Tienda demo</h1>"
                '<a href="/search?q=hola">buscar</a> '
                '<a href="/user?uid=1">mi perfil</a></body></html>')
        if u.path == "/search":
            q = qs.get("q", [""])[0]
            return self._html(f"<p>Resultados para: {q}</p>")  # XSS: refleja sin sanitizar
        if u.path == "/user":
            uid = qs.get("uid", [""])[0]
            # Simula  SELECT * FROM users WHERE id = <uid>  — inyectable boolean-blind.
            # NO refleja el uid (no hay XSS) y NO muestra error de SQL (no error-based):
            # la única forma de detectarlo es comparar respuesta "verdadera" vs "falsa".
            s = uid.replace(" ", "").lower()
            truthy = uid.strip() == "1" or "1=1" in s or "'1'='1" in s or "or1=1" in s
            if "1=2" in s or "'1'='2" in s:
                truthy = False
            if truthy:
                return self._html(
                    "<h2>Perfil</h2><p>Usuario: Alice Cooper</p>"
                    "<p>Email: alice@corp.example</p><p>Rol: admin</p>"
                    "<p>Miembro desde 2019. Última conexión: ayer. "
                    "Pedidos recientes: 7. Dirección guardada.</p>")
            return self._html("<p>No se encontró el usuario.</p>")
        if u.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"APP_KEY=supersecret\nDB_PASSWORD=hunter2\n")
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")


@contextlib.contextmanager
def running():
    """Levanta el lab en un puerto libre y devuelve la URL base. Lo apaga al salir."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnApp)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def target(url: str) -> dict:
    return {"name": "local-lab", "url": url, "lab": True,
            "vendor": "lab local (offline)", "vulns": VULNS}
