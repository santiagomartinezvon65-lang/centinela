"""Test de integración de la capa enterprise: API REST con autenticación.

Levanta el servidor con --auth, crea usuarios reales y verifica login por cookie,
autenticación por API-key y el gating por rol — la parte más sensible del sistema.
"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _req(url, method="GET", headers=None, data=None):
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


class TestAuthAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from core import auth
        import cli
        cls.auth, cls.cli = auth, cli
        cls.tmp = tempfile.mkdtemp()
        auth.USERS = os.path.join(cls.tmp, "users.json")
        auth.SECRET = os.path.join(cls.tmp, "secret.key")
        cls.admin = auth.create_user("admin", "adminpass", "admin")
        cls.viewer = auth.create_user("viewer", "viewerpass", "viewer")
        cli.Handler.auth = True
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), cli.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.cli.Handler.auth = False

    def test_requires_auth(self):
        status, _, _ = _req(self.base + "/api/history")
        self.assertEqual(status, 401)

    def test_login_with_cookie(self):
        status, _, hdr = _req(self.base + "/api/login", "POST",
                              {"Content-Type": "application/json"},
                              {"username": "admin", "password": "adminpass"})
        self.assertEqual(status, 200)
        cookie = hdr.get("Set-Cookie", "").split(";")[0]
        self.assertTrue(cookie.startswith("cent_session="))
        status2, _, _ = _req(self.base + "/api/history", headers={"Cookie": cookie})
        self.assertEqual(status2, 200)

    def test_bad_login(self):
        status, _, _ = _req(self.base + "/api/login", "POST",
                            {"Content-Type": "application/json"},
                            {"username": "admin", "password": "MAL"})
        self.assertEqual(status, 401)

    def test_api_key_auth(self):
        status, _, _ = _req(self.base + "/api/history",
                            headers={"X-API-Key": self.admin["api_key"]})
        self.assertEqual(status, 200)

    def test_role_gating(self):
        # un viewer NO puede lanzar escaneos
        status, body, _ = _req(self.base + "/api/scan", "POST",
                               {"X-API-Key": self.viewer["api_key"],
                                "Content-Type": "application/json"},
                               {"url": "https://x.com", "authorized": True})
        self.assertEqual(status, 403)
        self.assertIn("viewer", body.decode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
