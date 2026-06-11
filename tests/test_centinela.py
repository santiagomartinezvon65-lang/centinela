"""Suite de tests de Centinela — stdlib unittest, sin dependencias.

Corré:  python -m unittest discover -s tests   (desde la raíz del proyecto)
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.http import Response  # noqa: E402


def _resp(status=200, headers=None, body="", url="http://t/", error=None):
    return Response(url, url, status, headers or {}, [], body, error=error)


class TestChecks(unittest.TestCase):
    def test_sql_error_regex(self):
        from core.engine import _SQL_ERRORS
        self.assertTrue(_SQL_ERRORS.search("You have an error in your SQL syntax"))
        self.assertTrue(_SQL_ERRORS.search("Warning: pg_query() failed"))
        self.assertFalse(_SQL_ERRORS.search("una página normal"))

    def test_headers_check_flags_missing(self):
        from core.checks import check_headers
        out = check_headers(_resp(headers={}))
        ids = {f.id: f for f in out}
        self.assertFalse(ids["strict-transport-security"].passed)
        self.assertFalse(ids["content-security-policy"].passed)

    def test_headers_check_passes_present(self):
        from core.checks import check_headers
        out = check_headers(_resp(headers={"strict-transport-security": "max-age=1"}))
        ids = {f.id: f for f in out}
        self.assertTrue(ids["strict-transport-security"].passed)


class TestReport(unittest.TestCase):
    def test_grade_thresholds(self):
        from core.report import _grade
        self.assertEqual(_grade(95), "A")
        self.assertEqual(_grade(72), "C")
        self.assertEqual(_grade(10), "F")

    def test_build_scoring(self):
        from core.report import build
        from core.checks import Finding
        fs = [Finding("a", "t", "high", False, "headers"),
              Finding("b", "t", "low", False, "headers")]
        rep = build("https://x", fs)
        self.assertEqual(rep["score"], 100 - 15 - 3)
        self.assertEqual(rep["counts"]["high"], 1)
        self.assertIn("findings", rep)


class TestProfile(unittest.TestCase):
    def test_detect_static_vs_login(self):
        from core.profile import detect
        self.assertEqual(detect([_resp(body="<p>hola</p>")])["tier"], 0)
        self.assertEqual(detect([_resp(body='<input type="password">')])["tier"], 2)

    def test_apply_profile_floor(self):
        # un hallazgo >= low nunca cae a info (0 penalización) al bajar de tier
        from core.profile import apply_profile
        from core.checks import Finding
        f = Finding("content-security-policy", "csp", "high", False, "headers")
        apply_profile([f], 0)
        self.assertIn(f.severity, ("low", "medium"))
        self.assertNotEqual(f.severity, "info")


class TestEngineProbes(unittest.TestCase):
    def setUp(self):
        import core.engine as engine
        self.engine = engine
        self._orig = engine.fetch

    def tearDown(self):
        self.engine.fetch = self._orig

    def _pentester(self):
        from core.engine import LocalPentester
        return LocalPentester("https://lab.test/")

    def test_content_discovery_env(self):
        self.engine.fetch = lambda url, **k: (
            _resp(200, {"content-type": "text/plain"}, "APP_KEY=x\nDB_PASSWORD=y")
            if url.endswith("/.env") else _resp(404, {}, "nope"))
        p = self._pentester()
        p._probe_content_discovery()
        self.assertTrue(any(f["id"] == "disc-/.env" and f["severity"] == "critical"
                            for f in p.findings))

    def test_lfi_detection(self):
        self.engine.fetch = lambda url, **k: (
            _resp(200, {}, "root:x:0:0:root:/root:/bin/bash")
            if "etc" in url and "passwd" in url else _resp(200, {}, "ok"))
        p = self._pentester()
        p.pages = ["https://lab.test/p?file=a"]
        p._probe_injection_deep()
        self.assertTrue(any(f["id"].startswith("lfi") for f in p.findings))

    def test_ssti_detection(self):
        self.engine.fetch = lambda url, **k: (
            _resp(200, {}, "out=981801769") if "31337" in url else _resp(200, {}, "x"))
        p = self._pentester()
        p.pages = ["https://lab.test/p?tpl=a"]
        p._probe_injection_deep()
        self.assertTrue(any(f["id"].startswith("ssti") for f in p.findings))

    def test_secret_leak(self):
        self.engine.fetch = lambda url, **k: _resp(200, {}, 'k="AKIAIOSFODNN7EXAMPLE"')
        p = self._pentester()
        p.pages = []
        p._probe_secrets()
        self.assertTrue(any(f["category"] == "secrets" for f in p.findings))

    def test_form_parse_and_csrf(self):
        p = self._pentester()
        html = ('<form method="post" action="/login">'
                '<input name="user" type="text"><input name="pass" type="password"></form>')
        forms = p._parse_forms(html, "https://lab.test/")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["method"], "post")
        self.engine.fetch = lambda url, **k: _resp(200, {}, "ok")
        p._test_form(forms[0], "https://lab.test/")
        self.assertTrue(any(f["category"] == "csrf" for f in p.findings))


class TestVulns(unittest.TestCase):
    def setUp(self):
        from core import vulns
        self.vulns = vulns
        self.tmp = tempfile.mkdtemp()
        vulns.VULNS = os.path.join(self.tmp, "vulns.json")

    def _rep(self, findings):
        return {"target": "https://lab.test/", "kind": "scan", "reachable": True,
                "findings": findings}

    def test_lifecycle(self):
        v = self.vulns
        A = {"id": "a", "title": "HSTS", "severity": "high", "category": "headers", "passed": False}
        B = {"id": "b", "title": "SQLi", "severity": "critical", "category": "injection",
             "page": "https://lab.test/s?q=1", "passed": False}
        v.ingest(self._rep([A, B]))
        keys = {x["finding_id"]: k for k, x in v._load().items()}
        ka, kb = keys["a"], keys["b"]
        self.assertEqual(v.get(ka)["status"], "open")
        v.set_status(ka, "false_positive")
        self.assertTrue(v.is_muted("lab.test", "a"))
        v.ingest(self._rep([A]))            # B desaparece → fixed
        self.assertEqual(v.get(kb)["status"], "fixed")
        v.ingest(self._rep([A, B]))         # B reaparece → open
        self.assertEqual(v.get(kb)["status"], "open")


class TestAuth(unittest.TestCase):
    def setUp(self):
        from core import auth
        self.auth = auth
        self.tmp = tempfile.mkdtemp()
        auth.USERS = os.path.join(self.tmp, "users.json")
        auth.SECRET = os.path.join(self.tmp, "secret.key")

    def test_password_hash_and_verify(self):
        self.auth.create_user("admin", "S3cret!", "admin")
        self.assertTrue(self.auth.verify("admin", "S3cret!"))
        self.assertFalse(self.auth.verify("admin", "mal"))
        self.assertNotIn("S3cret", open(self.auth.USERS).read())  # nunca en claro

    def test_roles_and_api_key(self):
        u = self.auth.create_user("ana", "x", "analyst")
        self.assertTrue(self.auth.can("analyst", "scan"))
        self.assertFalse(self.auth.can("viewer", "scan"))
        self.assertEqual(self.auth.by_api_key(u["api_key"])["username"], "ana")

    def test_session_signing(self):
        self.auth.create_user("u", "p", "viewer")
        t = self.auth.make_session("u")
        self.assertEqual(self.auth.read_session(t), "u")
        self.assertIsNone(self.auth.read_session(t[:-3] + "xyz"))  # adulterada


class TestRemediate(unittest.TestCase):
    def test_generates_configs(self):
        from core import remediate
        rep = {"target": "https://x", "findings": [
            {"id": "content-security-policy", "severity": "high", "passed": False},
            {"id": "x-frame-options", "severity": "medium", "passed": False}]}
        self.assertTrue(remediate.missing_headers(rep))
        self.assertIn("Content-Security-Policy", remediate.generate(rep, "vercel"))
        self.assertIn("add_header", remediate.generate(rep, "nginx"))


class TestTemplates(unittest.TestCase):
    def test_load_and_match(self):
        from core import templates
        tdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "templates")
        tpls = templates.load(tdir)
        self.assertGreaterEqual(len(tpls), 6)
        svn = next(t for t in tpls if t["id"] == "svn-wc-db")
        ok = _resp(200, {"content-type": "application/octet-stream"}, "SQLite format 3\x00")
        self.assertTrue(templates.matches(ok, svn["requests"][0]))
        self.assertFalse(templates.matches(_resp(404, {}, "x"), svn["requests"][0]))


class TestJWT(unittest.TestCase):
    @staticmethod
    def _mk(alg, payload, secret=None):
        import base64
        import hashlib
        import hmac
        import json
        h = base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        if secret:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
            ).rstrip(b"=").decode()
        else:
            sig = "x" * 20
        return f"{h}.{p}.{sig}"

    def test_alg_none_is_critical(self):
        from core.engine import _jwt_analyze
        issues = _jwt_analyze(self._mk("none", {"u": "admin"}))
        self.assertTrue(any(i[0] == "jwt-none" and i[2] == "critical" for i in issues))

    def test_weak_secret_detected(self):
        from core.engine import _jwt_analyze
        issues = _jwt_analyze(self._mk("HS256", {"u": "admin"}, secret="secret"))
        self.assertTrue(any(i[0] == "jwt-weak" for i in issues))

    def test_strong_secret_no_false_positive(self):
        from core.engine import _jwt_analyze
        tok = self._mk("HS256", {"u": "x", "exp": 9999999999},
                       secret="un-secreto-largo-aleatorio-imposible-de-adivinar-2026")
        issues = _jwt_analyze(tok)
        self.assertFalse(any(i[0] == "jwt-weak" for i in issues))


class TestSAST(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, name, content):
        with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as fh:
            fh.write(content)

    def test_detects_real_secrets_and_danger(self):
        from core import sast
        self._write("config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        self._write("real.py", 'db_password = "Pr0dP4ss-xyz-123"\n')
        self._write("danger.py", 'subprocess.run(cmd, shell=True)\n')
        findings, _ = sast.scan_dir(self.tmp)
        titles = " ".join(f["title"] for f in findings)
        evidence = " ".join(f["evidence"] for f in findings)
        self.assertIn("AWS Access Key", titles)
        self.assertIn("credencial hardcodeada", titles)
        self.assertIn("shell=True", evidence)  # el código vulnerable queda en la evidencia

    def test_no_false_positives(self):
        from core import sast
        # placeholders, variables de entorno y comentarios NO deben marcarse
        self._write("safe.py",
                    'api_key = os.environ["KEY"]\n'
                    'password = "changeme"\n'
                    'secret = "your-secret-here"\n'
                    'token = "${ENV_TOKEN}"\n'
                    '# eval(user_input)  TODO\n')
        findings, _ = sast.scan_dir(self.tmp)
        self.assertEqual(findings, [], f"falsos positivos: {[f['evidence'] for f in findings]}")


class TestDNS(unittest.TestCase):
    def test_missing_spf_and_dmarc(self):
        from core.dnsaudit import analyze
        ids = {f["id"] for f in analyze("x.com", [], [])}
        self.assertIn("spf-missing", ids)
        self.assertIn("dmarc-missing", ids)

    def test_weak_spf(self):
        from core.dnsaudit import analyze
        ids = {f["id"]: f for f in analyze("x.com", ["v=spf1 +all"], ["v=DMARC1; p=reject"])}
        self.assertEqual(ids["spf-weak"]["severity"], "high")

    def test_good_config_no_findings(self):
        from core.dnsaudit import analyze
        out = analyze("x.com", ["v=spf1 include:_spf.google.com -all"],
                      ["v=DMARC1; p=reject; rua=mailto:a@x.com"])
        self.assertEqual(out, [])

    def test_dmarc_monitoring_only(self):
        from core.dnsaudit import analyze
        ids = {f["id"] for f in analyze("x.com", ["v=spf1 -all"], ["v=DMARC1; p=none"])}
        self.assertIn("dmarc-none", ids)


class TestRecon(unittest.TestCase):
    def test_version_cve(self):
        from core import recon
        self.assertEqual(recon._cve_for("220 (vsFTPd 2.3.4)")[1], "critical")
        self.assertEqual(recon._cve_for("SSH-2.0-OpenSSH_7.2p2")[1], "medium")
        self.assertIsNone(recon._cve_for("SSH-2.0-OpenSSH_9.0"))

    def test_clean_banner(self):
        from core import recon
        self.assertEqual(recon._clean_banner("HTTP/1.0 200 OK\r\nServer: nginx\r\n"),
                         "Server: nginx")


if __name__ == "__main__":
    unittest.main(verbosity=2)
