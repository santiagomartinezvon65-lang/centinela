#!/usr/bin/env python3
"""Centinela CLI — escáner de vulnerabilidades web (uso ético/autorizado).

  python cli.py scan https://misitio.com           # escaneo de una página
  python cli.py scan https://misitio.com --crawl    # escaneo de todo el sitio
  python cli.py serve                               # dashboard interactivo
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import sys
import time
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from core import auth, scan, store
from core.http import normalize, set_default_headers

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(ROOT, "web")

C = {"crit": "\033[91m", "high": "\033[93m", "ok": "\033[92m",
     "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}
SEV_C = {"critical": C["crit"], "high": C["high"], "medium": C["high"],
         "low": C["dim"], "info": C["dim"]}


def _is_private(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fail_check(report: dict, level: str | None) -> int:
    """Exit code 1 si hay hallazgos de severidad >= level (para CI/CD)."""
    if not level:
        return 0
    thr = _SEV_RANK.get(level, 1)
    fails = [f for f in report.get("findings", []) if not f.get("passed")]
    return 1 if any(_SEV_RANK.get(f.get("severity"), 4) <= thr for f in fails) else 0


def _parse_auth(args: argparse.Namespace) -> dict:
    """Construye headers de autenticación desde --cookie y --header."""
    h: dict[str, str] = {}
    if getattr(args, "cookie", None):
        h["Cookie"] = args.cookie
    for hv in (getattr(args, "header", None) or []):
        if ":" in hv:
            k, v = hv.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def _authorize(url: str, flag: bool) -> bool:
    host = urlparse(normalize(url)).hostname or ""
    if flag or _is_private(host):
        return True
    print(f"{C['high']}⚠  Solo escaneá sitios propios o con permiso escrito.{C['x']}")
    print(f"   Objetivo: {C['b']}{host}{C['x']}")
    try:
        ans = input("   ¿Tenés autorización para escanear este host? [s/N] ")
    except EOFError:
        print("   (no interactivo) usá --authorized para confirmar.")
        return False
    return ans.strip().lower() in ("s", "si", "sí", "y", "yes")


# ── scan ────────────────────────────────────────────────────────────
def cmd_scan(args: argparse.Namespace) -> int:
    if not _authorize(args.url, args.authorized):
        print(f"{C['crit']}Escaneo cancelado.{C['x']}")
        return 2

    modo = "sitio (crawl)" if args.crawl else "página"
    tier = None if args.profile == "auto" else int(args.profile)
    auth = _parse_auth(args)
    if auth:
        print(f"{C['dim']}autenticado: {', '.join(auth)}{C['x']}")
    print(f"{C['dim']}escaneando {args.url} [{modo}] …{C['x']}")
    set_default_headers(auth)
    report, err = scan(args.url, crawl=args.crawl, max_pages=args.pages, tier=tier)
    set_default_headers({})
    if err:
        print(f"{C['crit']}No se pudo conectar: {err}{C['x']}")
        return 1

    store.save_scan(report)
    _print_summary(report)
    print(f"\n{C['dim']}Dashboard interactivo: python cli.py serve{C['x']}")
    rc = _fail_check(report, getattr(args, "fail_on", None))
    if rc:
        print(f"{C['crit']}✗ fail-on {args.fail_on}: hay hallazgos de esa severidad o peor.{C['x']}")
    return rc


def _print_summary(r: dict) -> None:
    if r.get("notice"):
        print(f"\n{C['crit']}⚠  {r['notice']}{C['x']}")
    if r.get("reachable") is False:
        print(f"\n{C['b']}┌─ {r['target']}{C['x']}")
        print(f"{C['b']}│  Nota {C['dim']}N/A{C['x']}  (sitio no alcanzable — HTTP {r['http_status']})")
        print(f"{C['b']}└─{C['x']} {C['dim']}no se pudo evaluar el contenido real{C['x']}\n")
        return
    g = r["grade"]
    gc = C["ok"] if g in "AB" else C["high"] if g in "CD" else C["crit"]
    npages = len(r.get("pages", [])) or 1
    extra = f"  ·  {npages} páginas" if npages > 1 else ""
    prof = r.get("profile") or {}
    if prof:
        tag = "auto" if prof.get("auto") else "manual"
        print(f"{C['dim']}perfil: {prof['label']} · exigencia {prof['demand']} "
              f"({tag}) — {', '.join(prof['signals'])}{C['x']}")
    print(f"\n{C['b']}┌─ {r['target']}{extra}{C['x']}")
    print(f"{C['b']}│  Nota {gc}{g}{C['x']}  ({r['score']}/100)   "
          f"{r['passed']}/{r['total_checks']} chequeos OK")
    c = r["counts"]
    print(f"{C['b']}└─{C['x']} "
          f"{C['crit']}{c['critical']} críticas{C['x']}  "
          f"{C['high']}{c['high']} altas  {c['medium']} medias{C['x']}  "
          f"{C['dim']}{c['low']} bajas{C['x']}\n")
    for f in r["findings"]:
        if f["passed"]:
            continue
        col = SEV_C.get(f["severity"], C["dim"])
        print(f"  {col}● {f['severity'].upper():<8}{C['x']} {f['title']}")
        if f["evidence"]:
            print(f"    {C['dim']}{f['evidence'][:90]}{C['x']}")


# ── serve (dashboard interactivo) ───────────────────────────────────
_LOGIN_HTML = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Centinela — login</title>
<style>body{font-family:system-ui,sans-serif;background:#0a0d12;color:#e6edf3;display:flex;
min-height:100vh;align-items:center;justify-content:center;margin:0}
.box{background:#11151c;border:1px solid #232a36;border-radius:14px;padding:32px;width:300px}
.b{color:#3fb950;font-weight:800;letter-spacing:.14em;font-size:13px;margin-bottom:18px}
input{width:100%;box-sizing:border-box;background:#161b24;border:1px solid #232a36;color:#e6edf3;
padding:11px;border-radius:8px;margin:6px 0;font-size:14px}
button{width:100%;background:#3fb950;color:#04130a;border:0;font-weight:700;padding:12px;
border-radius:8px;margin-top:10px;cursor:pointer;font-size:14px}
.err{color:#f85149;font-size:13px;min-height:18px;margin-top:6px}</style></head><body>
<form class="box" onsubmit="login(event)">
<div class="b">◣ CENTINELA</div>
<input id="u" placeholder="usuario" autocomplete="username" autofocus>
<input id="p" type="password" placeholder="contraseña" autocomplete="current-password">
<button>Entrar</button><div class="err" id="e"></div></form>
<script>async function login(ev){ev.preventDefault();
const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:u.value,password:p.value})});
if(r.ok){location.href='/';}else{e.textContent='Credenciales inválidas';}}</script>
</body></html>"""


class Handler(SimpleHTTPRequestHandler):
    auth = False  # se setea en cmd_serve (--auth)

    def __init__(self, *a, **k):
        super().__init__(*a, directory=WEB, **k)

    def log_message(self, *a):  # silencioso
        pass

    # ── autenticación ───────────────────────────────────────────────
    def _user(self):
        key = self.headers.get("X-API-Key", "")
        authz = self.headers.get("Authorization", "")
        if authz.startswith("Bearer "):
            key = authz[7:]
        if key:
            u = auth.by_api_key(key)
            if u:
                return u
        from http.cookies import SimpleCookie
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        if "cent_session" in ck:
            un = auth.read_session(ck["cent_session"].value)
            if un:
                return auth.get(un)
        return None

    def _serve_login(self):
        body = _LOGIN_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _do_login(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "JSON inválido"}, 400)
        un = (body.get("username") or "").strip()
        if not auth.verify(un, body.get("password") or ""):
            return self._json({"error": "credenciales inválidas"}, 401)
        token = auth.make_session(un)
        payload = json.dumps({"ok": True, "role": auth.get(un)["role"]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie",
                         f"cent_session={token}; HttpOnly; SameSite=Strict; Path=/")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _can(self, perm: str) -> bool:
        """Gate por permiso. Sin --auth: permite todo. Con --auth: chequea rol."""
        if not self.auth:
            return True
        u = self._user()
        if not u:
            self._json({"error": "no autenticado"}, 401)
            return False
        if not auth.can(u["role"], perm):
            self._json({"error": f"sin permiso (rol {u['role']})"}, 403)
            return False
        return True

    def _send(self, body: bytes, ctype: str, code: int = 200, fname: str = "") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if fname:
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    def end_headers(self):  # evita que el navegador cachee el front viejo
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def _json(self, obj, code=200):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        # ── sello público: siempre accesible, incluso con --auth ──
        if path.startswith("/badge/"):
            return self._serve_badge(path)
        if path.startswith("/verify/"):
            return self._serve_verify(path)
        if self.auth:
            if path.startswith("/login"):
                return self._serve_login()
            if path.startswith("/api/"):
                if not self._user():
                    return self._json({"error": "no autenticado"}, 401)
            elif not self._user():
                return self._serve_login()

        if path == "/api/history":
            return self._json(store.list_history())
        if path == "/api/vulns/stats":
            from core import vulns
            return self._json(vulns.stats())
        if path == "/api/vulns":
            from core import vulns
            return self._json(vulns.list_vulns(
                status=qs.get("status", [""])[0], severity=qs.get("severity", [""])[0],
                host=qs.get("host", [""])[0]))
        if path.startswith("/api/vulns/"):
            from core import vulns
            v = vulns.get(path.rsplit("/", 1)[-1])
            return self._json(v) if v else self._json({"error": "no existe"}, 404)
        if path == "/api/assets":
            from core import guard
            return self._json(guard.list_assets())
        if path == "/api/alerts":
            from core import guard
            return self._json(guard.list_alerts(100))
        if path.startswith("/api/scan/"):
            rep = store.get_scan(path.rsplit("/", 1)[-1])
            return self._json(rep) if rep else self._json({"error": "no existe"}, 404)
        if path.startswith("/api/report/"):
            return self._serve_report(path.rsplit("/", 1)[-1], qs.get("format", ["html"])[0])
        return super().do_GET()

    def _serve_badge(self, path: str):
        from core import seal
        sid = path[len("/badge/"):].split(".")[0]
        st = seal.status(sid)
        svg = seal.badge_svg(st["state"] if st else "pending")
        body = svg.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_verify(self, path: str):
        from core import seal
        sid = path[len("/verify/"):].strip("/")
        st = seal.status(sid)
        if not st:
            return self._send(b"<h1>Unknown seal</h1>", "text/html; charset=utf-8", 404)
        self._send(seal.verify_page(st).encode("utf-8"), "text/html; charset=utf-8")

    def _serve_report(self, sid: str, fmt: str):
        rep = store.get_scan(sid)
        if not rep:
            return self._json({"error": "no existe"}, 404)
        from core import report_html
        if fmt == "json":
            return self._json(rep)
        if fmt == "csv":
            return self._send(report_html.build_csv(rep).encode("utf-8"),
                              "text/csv; charset=utf-8", fname=f"centinela-{sid}.csv")
        return self._send(report_html.build_html(rep).encode("utf-8"),
                          "text/html; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/login":
            return self._do_login()
        if path.startswith("/api/vulns/"):
            if not self._can("manage"):
                return
            from core import vulns
            key = path.rsplit("/", 1)[-1]
            b = self._read_body()
            done = False
            if b.get("status"):
                done = vulns.set_status(key, b["status"]) or done
            if "assignee" in b:
                done = vulns.assign(key, b["assignee"]) or done
            return self._json({"ok": done, "vuln": vulns.get(key)}, 200 if done else 404)
        if path == "/api/assets":
            if not self._can("manage"):
                return
            from core import guard
            b = self._read_body()
            if not b.get("url"):
                return self._json({"error": "falta url"}, 400)
            a = guard.add_asset(b["url"], mode=b.get("mode", "scan"),
                                interval=int(b.get("interval", 60)),
                                cookie=b.get("cookie", ""), lab=bool(b.get("lab")))
            return self._json({"ok": True, "asset": a})
        if path == "/api/guard/run":
            if not self._can("manage"):
                return
            from core import guard, notify
            fired = guard.guard_once(force=True)
            try:
                notify.notify(fired)
            except Exception:  # noqa: BLE001
                pass
            return self._json({"alerts": fired})
        if path != "/api/scan":
            return self.send_error(404)
        if self.auth:
            u = self._user()
            if not u:
                return self._json({"error": "no autenticado"}, 401)
            if not auth.can(u["role"], "scan"):
                return self._json({"error": f"sin permiso (rol {u['role']})"}, 403)
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "JSON inválido"}, 400)

        url = (body.get("url") or "").strip()
        if not url:
            return self._json({"error": "Falta la URL"}, 400)
        if not body.get("authorized"):
            return self._json(
                {"error": "Confirmá que tenés autorización para escanear este sitio."},
                403)

        cookie = (body.get("cookie") or "").strip()
        set_default_headers({"Cookie": cookie} if cookie else {})
        try:
            mode = body.get("mode") or "scan"
            if mode == "pentest":
                from core.engine import LocalPentester
                print(f"{C['dim']}[pentest]{' (auth)' if cookie else ''} {url}{C['x']}")
                try:
                    report = LocalPentester(url, lab=bool(body.get("lab"))).run()
                except Exception as e:  # noqa: BLE001
                    return self._json({"error": f"Error en el pentest: {e}"}, 502)
                store.save_scan(report)
                return self._json(report)

            crawl = bool(body.get("crawl"))
            tier = body.get("tier")
            tier = None if tier in (None, "", "auto") else int(tier)
            print(f"{C['dim']}[scan]{' (auth)' if cookie else ''} {url}"
                  f"{' (crawl)' if crawl else ''}{C['x']}")
            report, err = scan(url, crawl=crawl,
                               max_pages=int(body.get("max_pages", 12)), tier=tier)
            if err:
                return self._json({"error": f"No se pudo conectar: {err}"}, 502)
            store.save_scan(report)
            self._json(report)
        finally:
            set_default_headers({})

    def do_DELETE(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path == "/api/assets":
            if not self._can("manage"):
                return
            from core import guard
            return self._json({"removed": guard.remove_asset(qs.get("url", [""])[0])})
        return self.send_error(404)


def cmd_pentest(args: argparse.Namespace) -> int:
    if not _authorize(args.url, args.authorized):
        print(f"{C['crit']}Pentest cancelado.{C['x']}")
        return 2

    auth = _parse_auth(args)
    if auth:
        print(f"{C['dim']}autenticado: {', '.join(auth)}{C['x']}")
    set_default_headers(auth)
    try:
        if args.provider == "engine":
            from core.engine import LocalPentester
            report = LocalPentester(args.url, lab=args.lab).run()
        elif args.provider == "brain":
            from core.brain import BrainPentester
            report = BrainPentester(args.url, lab=args.lab).run()
        else:
            from core.agent import CentinelaAgent
            try:
                agent = CentinelaAgent(args.url, lab=args.lab, provider=args.provider,
                                       model=args.model, max_steps=args.max_steps)
            except RuntimeError as e:
                print(f"{C['crit']}{e}{C['x']}")
                return 1
            report = agent.run()
    finally:
        set_default_headers({})
    store.save_scan(report)

    if getattr(args, "json", None):
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"{C['dim']}informe JSON → {args.json}{C['x']}")

    u = report["usage"]
    print(f"\n{C['b']}── Pentest terminado ──{C['x']}")
    print(f"  {len(report['findings'])} hallazgos · riesgo {report.get('overall_risk') or '—'} "
          f"· {report['steps']} pasos")
    if report.get("owasp"):
        for cat, n in sorted(report["owasp"].items()):
            print(f"  {C['dim']}· {cat}: {n}{C['x']}")
    if report.get("provider") in ("engine", "brain", "ollama"):
        print(f"  {C['dim']}local · gratis · sin dependencias{C['x']}")
    elif report.get("provider") == "groq":
        print(f"  {C['dim']}nube · Groq (tier gratis) · tokens: "
              f"{u['input_tokens']}↓ {u['output_tokens']}↑{C['x']}")
    else:
        print(f"  {C['dim']}tokens: {u['input_tokens']}↓ {u['output_tokens']}↑ · "
              f"~USD {u['est_cost_usd']}{C['x']}")
    if report["summary"]:
        print(f"\n{report['summary']}\n")
    print(f"{C['dim']}Vela en el dashboard: python cli.py serve{C['x']}")
    rc = _fail_check(report, getattr(args, "fail_on", None))
    if rc:
        print(f"{C['crit']}✗ fail-on {args.fail_on}: hay hallazgos de esa severidad o peor.{C['x']}")
    return rc


def cmd_bench(args: argparse.Namespace) -> int:
    from core import benchmark as bench
    brains = [b for b in args.brains.split(",") if b.strip()]
    bad = [b for b in brains if b not in bench.BRAINS]
    if bad:
        print(f"{C['crit']}Cerebro(s) inválido(s): {bad}. Opciones: {bench.BRAINS}{C['x']}")
        return 1

    def _go(targets):
        print(f"{C['b']}🏁 Centinela Benchmark{C['x']}  "
              f"{C['dim']}{len(targets)} target(s) × {len(brains)} cerebro(s): "
              f"{', '.join(brains)}{C['x']}\n")
        results = bench.run_benchmark(targets, brains, model=args.model,
                                      max_steps=args.max_steps, verbose=args.verbose)
        bench.print_leaderboard(results)
        if args.json:
            bench.to_json(results, args.json)
            print(f"\n{C['dim']}JSON → {args.json}{C['x']}")
        if args.html:
            bench.to_html(results, args.html)
            print(f"{C['dim']}HTML → {args.html}{C['x']}")

    if args.local:  # lab local offline (SQLi ciego, XSS, .env) — sin internet
        from core import locallab
        with locallab.running() as url:
            _go([locallab.target(url)])
        return 0

    only = [n for n in args.targets.split(",") if n.strip()] if args.targets else None
    try:
        targets = bench.load_targets(only=only)
    except FileNotFoundError:
        print(f"{C['crit']}No encontré bench/targets.json{C['x']}")
        return 1
    if not targets:
        print(f"{C['crit']}Ningún target coincide con: {args.targets}{C['x']}")
        return 1
    _go(targets)
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from core import brain
    try:
        out = brain.train_from_samples(epochs=args.epochs, lr=args.lr)
    except (FileNotFoundError, ValueError) as e:
        print(f"{C['crit']}{e}{C['x']}")
        return 1
    m = out["metrics"]
    print(f"{C['b']}🧠 Modelo entrenado{C['x']}  {C['dim']}{out['n_samples']} muestras "
          f"({out['positives']} positivas){C['x']}")
    print(f"  accuracy {C['ok']}{m['accuracy']*100:.0f}%{C['x']} · "
          f"precision {m['precision']*100:.0f}% · recall {m['recall']*100:.0f}% · "
          f"F1 {m['f1']:.2f} · loss {m['loss']}")
    print(f"\n{C['b']}Pesos aprendidos (qué señales importan):{C['x']}")
    for name, w in out["weights"]:
        bar = ("+" if w >= 0 else "-") * min(int(abs(w) * 2) + 1, 20)
        col = C["ok"] if w >= 0 else C["crit"]
        print(f"  {name:18s} {col}{w:+.2f}{C['x']} {C['dim']}{bar}{C['x']}")
    print(f"\n{C['dim']}Modelo → {out['model_path']}  ·  usalo con --provider brain{C['x']}")
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    from core import seal
    op = args.op
    if op == "issue":
        out = seal.issue(args.url, base_url=args.base_url)
        st = seal.status(out["seal_id"])
        print(f"{C['b']}🛡  Trust Seal emitido para {out['host']}{C['x']}")
        print(f"  {C['dim']}estado actual: {st['state']}{C['x']}")
        print(f"  verificación: {C['ok']}{out['verify_url']}{C['x']}")
        print(f"  badge:        {C['dim']}{out['badge_url']}{C['x']}\n")
        print(f"{C['b']}Pegá esto en la web del cliente (HTML):{C['x']}\n")
        print(out["snippet"] + "\n")
        if st["state"] != "verified":
            print(f"{C['high']}⚠ El sello no está 'verified' todavía. "
                  f"Corré un scan/pentest del sitio para activarlo.{C['x']}")
        return 0
    if op == "status":
        st = seal.status_for_url(args.url) if args.url else None
        if not st:
            print(f"{C['crit']}No hay sello para ese sitio. Emitilo: seal issue <url>{C['x']}")
            return 1
        print(f"{C['b']}{st['host']}{C['x']} → {st['state']}  "
              f"{C['dim']}(grade {st.get('grade') or '—'}, "
              f"último audit {st.get('last_audit') or 'nunca'}){C['x']}")
        return 0
    if op == "list":
        seals = seal.list_seals()
        if not seals:
            print(f"{C['dim']}Sin sellos emitidos. Emití uno: seal issue <url>{C['x']}")
            return 0
        print(f"{C['b']}Sellos emitidos:{C['x']}")
        for s in seals:
            st = seal.status(s["seal_id"])
            print(f"  {C['ok']}●{C['x']} {s['host']:<28} {C['dim']}[{st['state']}] "
                  f"{s['seal_id']}{C['x']}")
        return 0
    return 1


def cmd_prospect(args: argparse.Namespace) -> int:
    from core import prospect
    urls = list(args.urls or [])
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                urls += [ln.strip() for ln in fh
                         if ln.strip() and not ln.lstrip().startswith("#")]
        except FileNotFoundError:
            print(f"{C['crit']}No encontré el archivo: {args.file}{C['x']}")
            return 1
    if not urls:
        print(f"{C['crit']}Pasá una o más URLs, o --file lista.txt{C['x']}")
        return 1

    print(f"{C['b']}🎯 Prospección — {len(urls)} tienda(s){C['x']}  "
          f"{C['dim']}scan pasivo + compliance PCI + email de outreach{C['x']}\n")
    results = prospect.run_batch(urls, outdir=args.out,
                                 sender=args.sender or "{YOUR NAME}")

    print(f"{C['b']}{'TIENDA':<26}{'NOTA':<6}{'PCI':<7}{'CALOR':<7}HALLAZGO TOP{C['x']}")
    for r in results:
        if not r.get("ok"):
            print(f"  {C['dim']}{r['host']:<24} (no alcanzable: {r.get('error','')[:30]}){C['x']}")
            continue
        gc = C["ok"] if r["grade"] in ("A", "B") else C["high"] if r["grade"] in ("C", "D") else C["crit"]
        heat = "🔥" * min(1 + r["sales_score"] // 20, 5)
        print(f"  {r['host']:<24} {gc}{r['grade']:<5}{C['x']} "
              f"{C['crit']}{r['pci_pass']}/{r['pci_total']}{C['x']}   "
              f"{heat:<6} {C['dim']}{r['top'][:38]}{C['x']}")

    ok = [r for r in results if r.get("ok")]
    print(f"\n{C['ok']}Material listo en ./{args.out}/{C['x']}  "
          f"{C['dim']}(por tienda: report.html + email.txt){C['x']}")
    if ok:
        hot = ok[0]
        print(f"{C['b']}Prospecto más caliente: {hot['host']}{C['x']} "
              f"{C['dim']}— {hot['gaps']} gaps PCI, abrí {hot['dir']}/{C['x']}")
    print(f"{C['dim']}Nota: scan pasivo (no intrusivo). Pentest profundo (--deep) = "
          f"sólo con autorización del dueño, usá el comando 'pentest'.{C['x']}")
    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    if not _authorize(args.url, args.authorized):
        print(f"{C['crit']}Recon cancelado.{C['x']}")
        return 2
    from core import recon
    say = lambda m: print(f"{C['ok']}▸{C['x']} {m}")
    print(f"{C['b']}🛰  Centinela Recon → {args.url}{C['x']}\n")
    rep = recon.run(args.url, do_subs=not args.no_subs, do_ports=not args.no_ports, say=say)
    store.save_scan(rep)
    print(f"\n{C['b']}── Superficie de ataque ──{C['x']}")
    for f in rep["findings"]:
        if f["category"] == "recon":
            print(f"  {C['dim']}◦ {f['evidence']}{C['x']}")
    for f in rep["findings"]:
        if f["category"] == "network":
            col = C["crit"] if f["severity"] in ("critical", "high") else (
                C["high"] if f["severity"] == "medium" else C["dim"])
            tag = f"  {col}⚠ {f['title']}{C['x']}" if f["severity"] != "info" else \
                  f"  {C['dim']}• {f['evidence']}{C['x']}"
            print(tag)
    print(f"\n{rep['summary']}")
    print(f"{C['dim']}Guardado en el historial · vela en el dashboard.{C['x']}")
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    from core import dnsaudit
    print(f"{C['ok']}📡 Auditando DNS/email de {args.domain} …{C['x']}")
    rep = dnsaudit.run(args.domain)
    store.save_scan(rep)
    if not rep["reachable"]:
        print(f"{C['high']}{rep['notice']}{C['x']}")
        return 1
    for f in rep["findings"]:
        col = C["crit"] if f["severity"] in ("critical", "high") else (
            C["high"] if f["severity"] == "medium" else C["dim"])
        print(f"  {col}[{f['severity'].upper():<8}]{C['x']} {f['title']}  {C['dim']}{f['evidence']}{C['x']}")
    if not rep["findings"]:
        print(f"  {C['ok']}SPF y DMARC bien configurados. ✓{C['x']}")
    print(f"\n{rep['summary']}")
    return _fail_check(rep, getattr(args, "fail_on", None))


def cmd_gui(args: argparse.Namespace) -> int:
    from core.gui import launch
    launch()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from core import report_html
    sid = args.id
    if not sid:
        hist = store.list_history()
        if not hist:
            print(f"{C['dim']}No hay escaneos en el historial. Corré un scan/pentest primero.{C['x']}")
            return 0
        print(f"{C['b']}Escaneos recientes{C['x']}  {C['dim']}(generá con: report <id>){C['x']}")
        for h in hist[:15]:
            print(f"  {C['dim']}{h['id']}{C['x']}  [{h.get('kind', 'scan')}]  "
                  f"{h['grade']}  {h['target']}")
        return 0
    if sid == "last":
        hist = store.list_history()
        if not hist:
            print(f"{C['crit']}No hay escaneos.{C['x']}")
            return 1
        sid = hist[0]["id"]
    rep = store.get_scan(sid)
    if not rep:
        print(f"{C['crit']}No existe ese id.{C['x']}")
        return 1
    host = urlparse(rep["target"]).hostname or "site"
    out = args.output or f"informe-{host}-{sid}.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(report_html.build_html(rep))
    print(f"{C['ok']}Informe HTML → {out}{C['x']}")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as fh:
            fh.write(report_html.build_csv(rep))
        print(f"{C['ok']}CSV → {args.csv}{C['x']}")
    if args.open:
        webbrowser.open("file://" + os.path.abspath(out))
    print(f"{C['dim']}Abrilo y usá Imprimir → Guardar como PDF para el deliverable.{C['x']}")
    return 0


def cmd_compliance(args: argparse.Namespace) -> int:
    from core import compliance
    sid = args.id
    if sid in (None, "last"):
        hist = store.list_history()
        if not hist:
            print(f"{C['crit']}No hay escaneos. Corré un scan/pentest del sitio primero.{C['x']}")
            return 1
        sid = hist[0]["id"]
    rep = store.get_scan(sid)
    if not rep:
        print(f"{C['crit']}No existe ese id.{C['x']}")
        return 1

    a = compliance.assess(rep, args.standard)
    vcol = C["ok"] if a["verdict"] == "Compliant" else C["crit"]
    print(f"\n{C['b']}{a['std_name']} — {a['host']}{C['x']}")
    print(f"  {vcol}{a['verdict']}{C['x']}  {C['dim']}({a['passing']}/{a['total']} "
          f"requisitos OK){C['x']}\n")
    for r in a["results"]:
        ok = r["status"] == "pass"
        mark = f"{C['ok']}✓ PASS{C['x']}" if ok else f"{C['crit']}✗ ACTION{C['x']}"
        print(f"  {mark}  {C['dim']}{r['code']:<10}{C['x']} {r['title']}")
        for f in r["findings"][:4]:
            print(f"      {C['dim']}· [{f['severity']}] {f['label']}{C['x']}")

    host = urlparse(rep["target"]).hostname or "site"
    out = args.output or f"compliance-{args.standard}-{host}-{sid}.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(compliance.build_html(rep, args.standard))
    print(f"\n{C['ok']}Compliance report → {out}{C['x']}")
    print(f"{C['dim']}Abrilo y usá Imprimir → Guardar como PDF para mandárselo al cliente.{C['x']}")
    if args.open:
        webbrowser.open("file://" + os.path.abspath(out))
    return 0


def cmd_user(args: argparse.Namespace) -> int:
    from core import auth
    op = args.op
    if op == "list":
        us = auth.list_users()
        if not us:
            print(f"{C['dim']}Sin usuarios. Creá uno: user add <nombre> --role admin{C['x']}")
            return 0
        print(f"{C['b']}Usuarios:{C['x']}")
        for u in us:
            print(f"  {u['username']:<16} {C['dim']}[{u['role']}] · key {u['api_key'][:12]}… "
                  f"· {u['created_at']}{C['x']}")
        return 0
    if not args.username:
        print(f"{C['crit']}Falta el nombre de usuario.{C['x']}")
        return 1
    if op == "add":
        pw = args.password or secrets.token_urlsafe(10)
        try:
            u = auth.create_user(args.username, pw, args.role or "viewer")
        except ValueError as e:
            print(f"{C['crit']}{e}{C['x']}")
            return 1
        print(f"{C['ok']}Usuario '{args.username}' creado [{u['role']}].{C['x']}")
        if not args.password:
            print(f"  {C['high']}contraseña generada: {pw}{C['x']}  (guardala)")
        print(f"  {C['dim']}API key: {u['api_key']}{C['x']}")
        return 0
    if op == "role":
        ok = auth.set_role(args.username, args.value or args.role or "")
        print(f"{C['ok']}{args.username} → {args.value or args.role}{C['x']}" if ok
              else "No existe el usuario o rol inválido.")
        return 0 if ok else 1
    if op == "passwd":
        pw = args.password or secrets.token_urlsafe(10)
        ok = auth.set_password(args.username, pw)
        if ok and not args.password:
            print(f"{C['high']}nueva contraseña: {pw}{C['x']}")
        print(f"{C['ok']}Contraseña actualizada.{C['x']}" if ok else "No existe el usuario.")
        return 0 if ok else 1
    if op == "delete":
        print("Eliminado." if auth.delete(args.username) else "No existe el usuario.")
        return 0
    if op == "key":
        if args.regen:
            k = auth.regen_key(args.username)
            print(f"{C['ok']}Nueva API key: {k}{C['x']}" if k else "No existe el usuario.")
        else:
            u = auth.get(args.username)
            print(u["api_key"] if u else "No existe el usuario.")
        return 0
    return 1


def cmd_code(args: argparse.Namespace) -> int:
    from core import sast
    if not os.path.isdir(args.path):
        print(f"{C['crit']}No es un directorio: {args.path}{C['x']}")
        return 1
    print(f"{C['ok']}🔎 Análisis estático de código en {args.path} …{C['x']}")
    rep = sast.scan(args.path)
    store.save_scan(rep)
    fails = rep["findings"]
    if not fails:
        print(f"{C['ok']}Sin hallazgos. Código limpio. ✓{C['x']}")
    for f in fails[:40]:
        col = C["crit"] if f["severity"] in ("critical", "high") else (
            C["high"] if f["severity"] == "medium" else C["dim"])
        print(f"  {col}[{f['severity'].upper():<8}]{C['x']} {f['title']}  "
              f"{C['dim']}{f['evidence']}{C['x']}")
    print(f"\n{rep['summary']}")
    rc = _fail_check(rep, getattr(args, "fail_on", None))
    if rc:
        print(f"{C['crit']}✗ fail-on {args.fail_on}: hay hallazgos de esa severidad o peor.{C['x']}")
    return rc


def cmd_fix(args: argparse.Namespace) -> int:
    from core import remediate
    sid = args.id
    if sid in (None, "last"):
        hist = store.list_history()
        if not hist:
            print(f"{C['crit']}No hay escaneos. Corré un scan/pentest primero.{C['x']}")
            return 1
        sid = hist[0]["id"]
    rep = store.get_scan(sid)
    if not rep:
        print(f"{C['crit']}No existe ese id.{C['x']}")
        return 1
    out = remediate.generate(rep, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"{C['ok']}Config de remediación → {args.output}{C['x']}")
    else:
        print(out)
    return 0


def cmd_templates(args: argparse.Namespace) -> int:
    from core import templates as T
    tdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    tpls = T.load(tdir)
    print(f"{C['b']}{len(tpls)} plantilla(s){C['x']} en {tdir}")
    for t in tpls:
        sev = t["info"].get("severity", "info")
        col = C["crit"] if sev in ("critical", "high") else C["dim"]
        print(f"  {C['dim']}{t['id']:<26}{C['x']} {col}[{sev}]{C['x']} {t['info']['name']}")
    print(f"\n{C['dim']}Agregá chequeos creando un .json en esa carpeta (sin tocar código).{C['x']}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from core import guard
    if args.op == "list":
        items = guard.list_assets()
        if not items:
            print(f"{C['dim']}Sin sitios vigilados. Agregá: watch add <url>{C['x']}")
            return 0
        print(f"{C['b']}Sitios bajo vigilancia:{C['x']}")
        for a in items:
            last = ("nunca" if not a["last_check"]
                    else f"hace {int((time.time() - a['last_check']) / 60)}m")
            print(f"  {C['ok']}●{C['x']} {a['url']}  {C['dim']}[{a['mode']}] "
                  f"cada {a['interval']}m · último: {last}{C['x']}")
        return 0
    if not args.url:
        print(f"{C['crit']}Falta la URL.{C['x']}")
        return 1
    if args.op == "add":
        mode = "pentest" if args.pentest else "scan"
        guard.add_asset(args.url, mode=mode, interval=args.every,
                        cookie=args.cookie or "", lab=args.lab)
        print(f"{C['ok']}Vigilando {args.url} cada {args.every} min ({mode}).{C['x']}")
        return 0
    if args.op == "remove":
        ok = guard.remove_asset(args.url)
        print(f"Quité {args.url}." if ok else "No estaba en la lista.")
        return 0
    return 1


def cmd_notify(args: argparse.Namespace) -> int:
    from core import notify
    op = args.op
    if op == "status":
        st = notify.status()
        print(f"{C['b']}Notificaciones:{C['x']}")
        print(f"  webhooks: {', '.join(st['webhooks']) or '(ninguno)'}")
        print(f"  email →: {', '.join(st['email_to']) or '(no configurado)'}"
              f"  {C['dim']}pass en env: {'sí' if st['smtp_pass_env'] else 'no'}{C['x']}")
        print(f"  notificaciones de escritorio: {'ON' if st.get('desktop') else 'OFF'}")
        print(f"  severidad mínima: {st['min_severity']}")
        return 0
    if op == "add-webhook":
        if not args.value:
            print(f"{C['crit']}Falta la URL del webhook.{C['x']}")
            return 1
        notify.add_webhook(args.value)
        print(f"{C['ok']}Webhook agregado.{C['x']}")
        return 0
    if op == "remove-webhook":
        print("Quité el webhook." if notify.remove_webhook(args.value or "") else "No estaba.")
        return 0
    if op == "min-severity":
        if args.value not in ("critical", "high", "medium", "low", "info"):
            print(f"{C['crit']}Nivel inválido (critical/high/medium/low/info).{C['x']}")
            return 1
        notify.set_min_severity(args.value)
        print(f"{C['ok']}Severidad mínima: {args.value}{C['x']}")
        return 0
    if op == "email":
        if not (args.host and args.sender and args.to):
            print(f"{C['crit']}Faltan datos: --host, --from y --to son obligatorios.{C['x']}")
            return 1
        notify.set_email(args.host, args.port, args.user or "", args.sender,
                         [t.strip() for t in args.to.split(",")], not args.no_tls)
        print(f"{C['ok']}Email configurado. Poné la contraseña en CENTINELA_SMTP_PASS.{C['x']}")
        return 0
    if op == "desktop":
        on = (args.value or "on").lower() not in ("off", "no", "0", "false")
        cfg = notify.load()
        cfg["desktop"] = on
        notify.save(cfg)
        print(f"{C['ok']}Notificaciones de escritorio: {'ON' if on else 'OFF'}{C['x']}")
        return 0
    if op == "test":
        sent = notify.test()
        print(f"{C['ok']}Test enviado a: {', '.join(sent)}{C['x']}" if sent
              else f"{C['high']}No hay canales configurados (o nada pasó el filtro de severidad).{C['x']}")
        return 0
    return 1


_STATUS_ALIAS = {"open": "open", "ack": "acknowledged", "acknowledged": "acknowledged",
                 "fp": "false_positive", "false-positive": "false_positive",
                 "false_positive": "false_positive", "risk": "accepted_risk",
                 "accepted": "accepted_risk", "accepted_risk": "accepted_risk",
                 "fixed": "fixed", "arreglado": "fixed"}
_STATUS_ICON = {"open": "🔴", "acknowledged": "👀", "false_positive": "🚫",
                "accepted_risk": "🟡", "fixed": "✅"}
_SEV_COL = {"critical": "crit", "high": "high", "medium": "high", "low": "dim", "info": "dim"}


def cmd_vulns(args: argparse.Namespace) -> int:
    from core import vulns
    op = args.op
    if op == "stats":
        s = vulns.stats()
        print(f"{C['b']}Backlog de vulnerabilidades{C['x']}  (total: {s['total']})")
        bs = s["by_status"]
        print(f"  🔴 abiertas: {bs['open']}  👀 reconocidas: {bs['acknowledged']}  "
              f"✅ arregladas: {bs['fixed']}  🚫 falso-pos: {bs['false_positive']}  "
              f"🟡 riesgo-aceptado: {bs['accepted_risk']}")
        ob = s["open_by_severity"]
        print(f"  abiertas por severidad → {C['crit']}{ob['critical']} críticas{C['x']} · "
              f"{C['high']}{ob['high']} altas · {ob['medium']} medias{C['x']} · "
              f"{C['dim']}{ob['low']} bajas{C['x']}")
        print(f"  {C['b']}Puntaje de riesgo abierto: {s['open_risk_score']}{C['x']}")
        return 0
    if op == "list":
        items = vulns.list_vulns(
            status=_STATUS_ALIAS.get((args.status or "").lower(), args.status or ""),
            severity=args.severity or "", host=args.host or "")
        if not items:
            print(f"{C['dim']}Sin vulnerabilidades que coincidan.{C['x']}")
            return 0
        for v in items:
            col = C[_SEV_COL.get(v["severity"], "dim")]
            who = f" → {v['assignee']}" if v["assignee"] else ""
            print(f"  {C['dim']}{v['key']}{C['x']} {col}[{v['severity'].upper():<8}]{C['x']} "
                  f"{_STATUS_ICON.get(v['status'], '')} {v['host']}  {v['title'][:48]}{who}")
        return 0
    if op == "show":
        v = vulns.get(args.key or "")
        if not v:
            print(f"{C['crit']}No existe esa clave.{C['x']}")
            return 1
        print(f"{C['b']}{v['title']}{C['x']}  [{v['severity']}] {_STATUS_ICON.get(v['status'])} {v['status']}")
        print(f"  clave: {v['key']} · host: {v['host']} · OWASP: {v.get('owasp', '')}")
        print(f"  responsable: {v['assignee'] or '(sin asignar)'} · visto {v['times_seen']}x")
        print(f"  primera vez: {v['first_seen']} · última: {v['last_seen']}"
              + (f" · arreglado: {v['fixed_at']}" if v.get("fixed_at") else ""))
        print(f"  evidencia: {v['evidence'][:120]}")
        print(f"  remediación: {v['remediation'][:160]}")
        if v.get("note"):
            print(f"  nota: {v['note']}")
        return 0
    if op == "set":
        st = _STATUS_ALIAS.get((args.value or "").lower())
        if not st:
            print(f"{C['crit']}Estado inválido. Usá: open/ack/fp/risk/fixed{C['x']}")
            return 1
        ok = vulns.set_status(args.key or "", st)
        print(f"{C['ok']}{args.key} → {st}{C['x']}" if ok else "No existe esa clave.")
        return 0 if ok else 1
    if op == "assign":
        ok = vulns.assign(args.key or "", args.value or "")
        print(f"{C['ok']}{args.key} asignada a {args.value}{C['x']}" if ok else "No existe esa clave.")
        return 0 if ok else 1
    return 1


def _print_alert(a: dict) -> None:
    sev = a["severity"]
    col = C["crit"] if sev in ("critical", "high") else (
        C["high"] if sev == "medium" else C["dim"])
    host = a["target"].split("//")[-1].split("/")[0]
    print(f"  {col}⚠ [{sev.upper()}] {host}{C['x']} — {a['title']}"
          + (f"  {C['dim']}{a['detail'][:70]}{C['x']}" if a.get("detail") else ""))


def cmd_guard(args: argparse.Namespace) -> int:
    from core import guard
    items = guard.list_assets()
    print(f"{C['ok']}╭───────────────────────────────────────────────╮{C['x']}")
    print(f"{C['ok']}│{C['x']}  🛡  {C['b']}Centinela Guardian{C['x']} — protección continua")
    print(f"{C['ok']}│{C['x']}  {C['dim']}{len(items)} activo(s) en vigilancia · Ctrl+C para detener{C['x']}")
    print(f"{C['ok']}╰───────────────────────────────────────────────╯{C['x']}")
    if not items:
        print(f"{C['high']}No hay sitios vigilados. Agregá con: watch add <url>{C['x']}")
        return 1
    first = True
    try:
        while True:
            fired = guard.guard_once(force=first)
            first = False
            stamp = time.strftime("%H:%M:%S")
            if fired:
                print(f"\n{C['b']}[{stamp}] {len(fired)} alerta(s):{C['x']}")
                for a in fired:
                    _print_alert(a)
                from core import notify
                sent = notify.notify(fired)
                if sent:
                    print(f"  {C['dim']}→ notificado a: {', '.join(sent)}{C['x']}")
            else:
                print(f"{C['dim']}[{stamp}] 🛡 todo en orden{C['x']}")
            if args.once:
                break
            time.sleep(args.tick)
    except KeyboardInterrupt:
        print(f"\n{C['dim']}Guardián detenido.{C['x']}")
    return 0


def _lan_ip() -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:  # noqa: BLE001
        return "127.0.0.1"
    finally:
        s.close()


def cmd_serve(args: argparse.Namespace) -> int:
    port = args.port
    Handler.auth = bool(getattr(args, "auth", False))
    if Handler.auth and auth.count() == 0:
        print(f"{C['high']}⚠ --auth activado pero no hay usuarios. Creá uno:{C['x']}")
        print(f"{C['dim']}   python cli.py user add admin --role admin{C['x']}")
    srv = ThreadingHTTPServer((args.host, port), Handler)
    local = f"http://127.0.0.1:{port}/"
    print(f"{C['ok']}╭─────────────────────────────────────────────╮{C['x']}")
    print(f"{C['ok']}│{C['x']}  Centinela en esta PC: {C['b']}{local}{C['x']}")
    if args.host == "0.0.0.0":
        print(f"{C['ok']}│{C['x']}  Desde el celu (misma WiFi): "
              f"{C['b']}http://{_lan_ip()}:{port}/{C['x']}")
        print(f"{C['ok']}│{C['x']}  {C['high']}⚠ expuesto a tu red local mientras corra{C['x']}")
    print(f"{C['ok']}│{C['x']}  {C['dim']}Ctrl+C para salir{C['x']}")
    print(f"{C['ok']}╰─────────────────────────────────────────────╯{C['x']}")
    if not args.no_open and args.host != "0.0.0.0":
        webbrowser.open(local)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{C['dim']}chau.{C['x']}")
        srv.shutdown()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="centinela", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="escanear una URL por consola")
    s.add_argument("url")
    s.add_argument("--crawl", action="store_true", help="escanear todo el sitio")
    s.add_argument("--pages", type=int, default=12, help="máx. páginas a crawlear")
    s.add_argument("--profile", choices=["auto", "0", "1", "2", "3"], default="auto",
                   help="perfil de sensibilidad: auto, 0=vitrina, 1=forms, 2=login, 3=pagos")
    s.add_argument("--cookie", help="Cookie de sesión para escaneo autenticado")
    s.add_argument("--header", action="append", metavar="'K: V'",
                   help="header extra (repetible), ej. --header 'Authorization: Bearer ...'")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="exit code 1 si hay hallazgos de esa severidad o peor (CI/CD)")
    s.add_argument("--authorized", action="store_true",
                   help="confirmás que tenés permiso para escanear el host")
    s.set_defaults(func=cmd_scan)

    pt = sub.add_parser("pentest", help="pentest autónomo (motor de reglas, o IA opcional)")
    pt.add_argument("url")
    pt.add_argument("--lab", action="store_true",
                    help="target intencionalmente vulnerable (permite payloads de detección)")
    pt.add_argument("--provider",
                    choices=["engine", "brain", "auto", "anthropic", "groq", "ollama"],
                    default="engine",
                    help="engine: motor de reglas. brain: cerebro propio entrenable "
                    "(sin deps, aprende). groq: Llama 70B nube (gratis). "
                    "anthropic: Claude (pago). ollama: modelo local.")
    pt.add_argument("--model", default=None,
                    help="modelo LLM si usás un provider de IA (no aplica a engine)")
    pt.add_argument("--json", default=None, help="guardar el informe en un archivo .json")
    pt.add_argument("--cookie", help="Cookie de sesión para pentest autenticado")
    pt.add_argument("--header", action="append", metavar="'K: V'",
                    help="header extra (repetible), ej. --header 'Authorization: Bearer ...'")
    pt.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                    help="exit code 1 si hay hallazgos de esa severidad o peor (CI/CD)")
    pt.add_argument("--max-steps", type=int, default=20)
    pt.add_argument("--authorized", action="store_true")
    pt.set_defaults(func=cmd_pentest)

    bm = sub.add_parser("bench", help="benchmark: cuánto resuelve el agente sobre labs conocidos")
    bm.add_argument("--targets", default=None,
                    help="filtrar por nombre (coma-separado), ej. ginandjuice,testfire. Default: todos.")
    bm.add_argument("--brains", default="engine",
                    help="cerebros a comparar (coma-separado): engine,ollama,anthropic. Default: engine.")
    bm.add_argument("--model", default=None, help="modelo LLM para cerebros de IA")
    bm.add_argument("--max-steps", type=int, default=14)
    bm.add_argument("--json", default=None, help="guardar resultados en .json")
    bm.add_argument("--html", default=None, help="guardar leaderboard en .html")
    bm.add_argument("--verbose", action="store_true", help="mostrar la traza de cada corrida")
    bm.add_argument("--local", action="store_true",
                    help="benchmarkea contra un lab local offline (SQLi ciego + XSS + .env), sin internet")
    bm.set_defaults(func=cmd_bench)

    tr = sub.add_parser("train", help="entrena el cerebro propio con las muestras juntadas (--provider brain)")
    tr.add_argument("--epochs", type=int, default=400)
    tr.add_argument("--lr", type=float, default=0.3)
    tr.set_defaults(func=cmd_train)

    dn = sub.add_parser("dns", help="auditoría de DNS/email (SPF/DMARC: ¿se puede falsificar tu email?)")
    dn.add_argument("domain")
    dn.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    dn.set_defaults(func=cmd_dns)

    pr = sub.add_parser("prospect",
                        help="batch: scan pasivo + compliance PCI + email de outreach por tienda")
    pr.add_argument("urls", nargs="*", help="URLs de tiendas a prospectar")
    pr.add_argument("--file", help="archivo con una URL por línea (# = comentario)")
    pr.add_argument("--out", default="outreach", help="carpeta de salida (default: outreach)")
    pr.add_argument("--sender", help="tu nombre/firma para el email de outreach")
    pr.set_defaults(func=cmd_prospect)

    sl = sub.add_parser("seal", help="sello de confianza verificable (badge para la web del cliente)")
    sl.add_argument("op", choices=["issue", "status", "list"])
    sl.add_argument("url", nargs="?", help="URL del sitio (issue/status)")
    sl.add_argument("--base-url", default="http://localhost:8077",
                    help="dominio público donde corre Centinela (va en el snippet del badge)")
    sl.set_defaults(func=cmd_seal)

    rc = sub.add_parser("recon", help="recon de red: subdominios (DNS) + puertos abiertos")
    rc.add_argument("url")
    rc.add_argument("--no-subs", action="store_true", help="no enumerar subdominios")
    rc.add_argument("--no-ports", action="store_true", help="no escanear puertos")
    rc.add_argument("--authorized", action="store_true")
    rc.set_defaults(func=cmd_recon)

    sub.add_parser("gui", help="app de escritorio: hablale a Centinela").set_defaults(func=cmd_gui)
    sub.add_parser("templates", help="listar plantillas de chequeos cargadas").set_defaults(func=cmd_templates)

    u = sub.add_parser("user", help="cuentas, roles y API-keys (multi-usuario)")
    u.add_argument("op", choices=["add", "list", "role", "passwd", "delete", "key"])
    u.add_argument("username", nargs="?")
    u.add_argument("value", nargs="?", help="rol nuevo (para 'role')")
    u.add_argument("--role", choices=["admin", "analyst", "viewer"])
    u.add_argument("--password", help="contraseña (si se omite, se genera una)")
    u.add_argument("--regen", action="store_true", help="regenerar la API key (con 'key')")
    u.set_defaults(func=cmd_user)

    co = sub.add_parser("code", help="SAST: análisis estático de código local (secretos + patrones)")
    co.add_argument("path", help="directorio del código/repo a analizar")
    co.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                    help="exit code 1 si hay hallazgos de esa severidad o peor (CI/CD)")
    co.set_defaults(func=cmd_code)

    fx = sub.add_parser("fix", help="modo defensa: genera la config lista para arreglar")
    fx.add_argument("id", nargs="?", help="id del escaneo (o 'last')")
    fx.add_argument("--format", choices=["vercel", "nginx", "apache", "netlify"],
                    default="vercel", help="formato de la config (default vercel)")
    fx.add_argument("-o", "--output", help="guardar la config en un archivo")
    fx.set_defaults(func=cmd_fix)

    rp = sub.add_parser("report", help="generar informe HTML/CSV (deliverable de auditoría)")
    rp.add_argument("id", nargs="?", help="id del escaneo (o 'last'); vacío = listar")
    rp.add_argument("-o", "--output", help="archivo HTML de salida")
    rp.add_argument("--csv", help="además, exportar los hallazgos a este CSV")
    rp.add_argument("--open", action="store_true", help="abrir el informe en el navegador")
    rp.set_defaults(func=cmd_report)

    cp = sub.add_parser("compliance",
                        help="informe de cumplimiento (PCI) — deliverable de venta para USA")
    cp.add_argument("id", nargs="?", help="id del escaneo (o 'last'); vacío = último")
    cp.add_argument("--standard", choices=["pci"], default="pci",
                    help="estándar a evaluar (por ahora pci)")
    cp.add_argument("-o", "--output", help="archivo HTML de salida")
    cp.add_argument("--open", action="store_true", help="abrir el informe en el navegador")
    cp.set_defaults(func=cmd_compliance)

    w = sub.add_parser("watch", help="gestionar los sitios que vigila el guardián")
    w.add_argument("op", choices=["add", "list", "remove"])
    w.add_argument("url", nargs="?")
    w.add_argument("--every", type=int, default=60, help="cada cuántos minutos (default 60)")
    w.add_argument("--pentest", action="store_true", help="usar el motor de pentest (no scan)")
    w.add_argument("--lab", action="store_true")
    w.add_argument("--cookie", help="Cookie de sesión para vigilar áreas autenticadas")
    w.set_defaults(func=cmd_watch)

    g = sub.add_parser("guard", help="bot protector: vigila en loop y alerta de cambios")
    g.add_argument("--once", action="store_true", help="una pasada y salir")
    g.add_argument("--tick", type=int, default=60,
                   help="cada cuántos segundos revisa si hay algo por escanear")
    g.set_defaults(func=cmd_guard)

    n = sub.add_parser("notify", help="alertas a Slack/Discord/Teams/email")
    n.add_argument("op", choices=["status", "add-webhook", "remove-webhook",
                                  "min-severity", "email", "desktop", "test"])
    n.add_argument("value", nargs="?", help="URL del webhook o nivel de severidad")
    n.add_argument("--host", help="servidor SMTP (email)")
    n.add_argument("--port", type=int, default=587)
    n.add_argument("--user", help="usuario SMTP")
    n.add_argument("--from", dest="sender", help="remitente del email")
    n.add_argument("--to", help="destinatarios separados por coma")
    n.add_argument("--no-tls", action="store_true", help="no usar STARTTLS")
    n.set_defaults(func=cmd_notify)

    v = sub.add_parser("vulns", help="gestión de vulnerabilidades (backlog con estados)")
    v.add_argument("op", choices=["list", "show", "set", "assign", "stats"])
    v.add_argument("key", nargs="?", help="clave de la vuln (show/set/assign)")
    v.add_argument("value", nargs="?", help="estado (set: open/ack/fp/risk/fixed) o responsable (assign)")
    v.add_argument("--status", help="filtrar por estado")
    v.add_argument("--severity", help="filtrar por severidad")
    v.add_argument("--host", help="filtrar por host")
    v.set_defaults(func=cmd_vulns)

    sv = sub.add_parser("serve", help="dashboard interactivo en el navegador")
    sv.add_argument("--port", type=int, default=8077)
    sv.add_argument("--host", default="127.0.0.1",
                    help="0.0.0.0 para acceder desde el celu en la misma WiFi")
    sv.add_argument("--auth", action="store_true",
                    help="exigir login (cuentas/roles) + API-key en la API")
    sv.add_argument("--no-open", action="store_true", help="no abrir el navegador solo")
    sv.set_defaults(func=cmd_serve)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
