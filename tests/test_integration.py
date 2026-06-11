"""Test de integración end-to-end: levanta una app vulnerable a propósito y
verifica que el motor de Centinela detecta las vulnerabilidades reales.

Esto prueba que la herramienta funciona de punta a punta contra un objetivo vivo,
no solo en unit tests aislados.
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _VulnApp(BaseHTTPRequestHandler):
    """App deliberadamente vulnerable (solo para tests): XSS, SQLi, .env expuesto,
    sin headers de seguridad."""

    def log_message(self, *a):
        pass

    def _html(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()  # a propósito: SIN headers de seguridad
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            return self._html(
                '<html><body><h1>App de prueba</h1>'
                '<a href="/search?q=hola">buscar</a> '
                '<a href="/item?id=1">item</a></body></html>')
        if u.path == "/search":
            q = qs.get("q", [""])[0]
            return self._html(f"<p>Resultados para: {q}</p>")  # XSS: refleja sin sanitizar
        if u.path == "/item":
            iid = qs.get("id", [""])[0]
            if "'" in iid:  # SQLi error-based
                return self._html(
                    "Database error: You have an error in your SQL syntax near ''", 500)
            return self._html(f"<p>Item {iid}</p>")
        if u.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"APP_KEY=supersecret\nDB_PASSWORD=hunter2\n")
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnApp)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_engine_finds_real_vulns(self):
        from core.engine import LocalPentester
        report = LocalPentester(f"http://127.0.0.1:{self.port}/").run()
        cats = {f["category"] for f in report["findings"] if not f["passed"]}
        ids = {f["id"] for f in report["findings"] if not f["passed"]}
        # detecta inyección (SQLi o XSS), fuga del .env, y falta de headers
        self.assertTrue("injection" in cats or "xss" in cats,
                        f"no detectó inyección/XSS; categorías: {cats}")
        self.assertTrue(any("env" in i or "disc" in i or "secret" in i for i in ids)
                        or "secrets" in cats or "disclosure" in cats,
                        f"no detectó el .env expuesto; ids: {ids}")
        self.assertIn("headers", cats, "no detectó headers de seguridad faltantes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
