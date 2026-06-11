"""Centinela GUI — app de escritorio (Tkinter, sin deps) para hablarle a Centinela.

Ventana con un chat: escribís qué hacer en lenguaje casi natural
("escaneá tal sitio", "pentest a tal otro") y Centinela ejecuta y responde en
vivo. El "entendimiento" es por reglas — sin LLM, sin API, sin navegador.
"""
from __future__ import annotations

import queue
import re
import sys
import threading
import webbrowser

from .report import build  # noqa: F401  (asegura core cargado)
from .scanner import scan as deterministic_scan
from .store import save_scan

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_URL = re.compile(r"\b((?:https?://)?[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s]*)?)", re.I)
_DONE = object()

_PENTEST_W = ("pentest", "penetr", "atac", "hacke", "auditá", "auditar", "auditor",
              "explot", "metete", "métete", "entra", "entrá", "rompé", "romper")
_SCAN_W = ("escane", "escáner", "escaner", "chequea", "chequeá", "scan", "headers",
           "analizá", "analizar", "revisá", "mirá", "fijate", "fijáte")
_RECON_W = ("recon", "subdomin", "puerto", "superficie", "red", "mapea", "mapeá",
            "descubr", "enumera", "enumerá")
_VULNS_W = ("vuln", "hallazgo", "backlog", "encontraste", "encontró", "qué hay",
            "que hay", "mostrame", "mostrá", "listá", "estado de seguridad", "riesgo")
_REPORT_W = ("informe", "reporte", "report", "pdf", "documento", "auditoría")
_GUARD_W = ("vigil", "cuid", "guard", "proteg", "monitor", "ojo a", "controlá")
_FIX_W = ("arregl", "areglar", "soluci", "reparar", "repará", "defensa", "cómo lo arreglo",
          "como arreglo", "cómo arreglo")

WELCOME = (
    "Hola, soy Centinela. Decime a dónde meterme y qué hacer:\n"
    "   • escaneá misitio.com              (escaneo rápido)\n"
    "   • metete en misitio.com y hacé un pentest\n"
    "   • hacé recon de misitio.com        (subdominios + puertos)\n"
    "   • vigilá misitio.com               (lo cuido 24/7)\n"
    "   • qué vulnerabilidades hay         (backlog)\n"
    "   • hacé el informe                  (genera el PDF del último)\n"
    "   • dashboard · ayuda · limpiar · salir\n"
    "Uso ético: solo sitios propios o con permiso.\n")


class _Pipe:
    """Captura los print() del motor y los manda a la ventana (sin ANSI)."""
    def __init__(self, q: queue.Queue):
        self.q = q

    def write(self, s: str):
        s = _ANSI.sub("", s)
        if s:
            self.q.put(s)

    def flush(self):
        pass


class CentinelaGUI:
    def __init__(self):
        import tkinter as tk
        self.tk = tk
        self.q: queue.Queue = queue.Queue()
        self.busy = False

        self.root = tk.Tk()
        self.root.title("Centinela")
        self.root.configure(bg="#0a0d12")
        self.root.geometry("780x580")
        self.root.minsize(560, 420)

        head = tk.Frame(self.root, bg="#11151c")
        head.pack(fill="x")
        tk.Label(head, text="◣ CENTINELA", fg="#3fb950", bg="#11151c",
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=14, pady=10)
        tk.Label(head, text="escáner de seguridad · hablale", fg="#7d8794",
                 bg="#11151c", font=("Segoe UI", 9)).pack(side="left")

        self.log = tk.Text(self.root, bg="#0a0d12", fg="#e6edf3", bd=0,
                           font=("Consolas", 10), wrap="word", padx=14, pady=12,
                           insertbackground="#e6edf3", state="disabled")
        self.log.pack(fill="both", expand=True)
        sb = tk.Scrollbar(self.log, command=self.log.yview)
        sb.pack(side="right", fill="y")
        self.log.config(yscrollcommand=sb.set)
        self.log.tag_config("you", foreground="#58a6ff", font=("Consolas", 10, "bold"))
        self.log.tag_config("sys", foreground="#d29922")
        self.log.tag_config("bot", foreground="#adbac7")
        self.log.tag_config("hit", foreground="#f85149")

        bar = tk.Frame(self.root, bg="#11151c")
        bar.pack(fill="x")
        self.entry = tk.Entry(bar, bg="#161b24", fg="#e6edf3", bd=0,
                              font=("Consolas", 11), insertbackground="#3fb950")
        self.entry.pack(side="left", fill="x", expand=True, padx=(12, 8), pady=10, ipady=7)
        self.entry.bind("<Return>", lambda e: self._send())
        self.btn = tk.Button(bar, text="Enviar", command=self._send, bd=0,
                             bg="#3fb950", fg="#04130a", font=("Segoe UI", 10, "bold"),
                             activebackground="#54c662", padx=18, cursor="hand2")
        self.btn.pack(side="right", padx=(0, 12), pady=10)

        self._append(WELCOME, "sys")
        self.entry.focus_set()
        self.root.after(80, self._poll)

    # ── UI helpers ──────────────────────────────────────────────────
    def _append(self, text: str, tag: str = "bot"):
        self.log.config(state="normal")
        if tag == "bot":
            for line in text.splitlines(keepends=True):
                t = "hit" if line.lstrip().startswith("✚") else "bot"
                self.log.insert("end", line, t)
        else:
            self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _set_busy(self, on: bool):
        self.busy = on
        self.btn.config(state="disabled" if on else "normal",
                        text="…" if on else "Enviar")
        self.entry.config(state="disabled" if on else "normal")
        if not on:
            self.entry.focus_set()

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item is _DONE:
                    self._set_busy(False)
                else:
                    self._append(item, "bot")
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    # ── input ───────────────────────────────────────────────────────
    def _send(self):
        if self.busy:
            return
        text = self.entry.get().strip()
        if not text:
            return
        self.entry.delete(0, "end")
        self._append(f"\nvos › {text}\n", "you")
        self._interpret(text)

    def _interpret(self, text: str):
        low = text.lower()
        if low in ("salir", "chau", "exit", "quit"):
            self.root.destroy()
            return
        if low in ("limpiar", "clear", "cls"):
            self.log.config(state="normal")
            self.log.delete("1.0", "end")
            self.log.config(state="disabled")
            self._append(WELCOME, "sys")
            return
        if any(w in low for w in ("ayuda", "help", "comandos", "qué podés", "que podes")):
            self._append(WELCOME, "sys")
            return
        if any(w in low for w in ("dashboard", "navegador", "panel", "web")):
            self._append("Abriendo el dashboard en el navegador "
                         "(necesita `python cli.py serve` corriendo)…\n", "sys")
            webbrowser.open("http://127.0.0.1:8077")
            return

        if any(w in low for w in _FIX_W):
            self._run(self._do_fix)
            return

        m = _URL.search(text)
        url = m.group(1) if m else None
        lab = "--lab" in low or " lab" in low
        has = lambda ws: any(w in low for w in ws)

        if url:  # hay un sitio → ejecutar la acción sobre él
            if has(_RECON_W):
                self._append(f"Voy a hacer recon de {url} (subdominios + puertos)…\n", "sys")
                self._run(self._do_recon, url)
            elif has(_GUARD_W):
                self._append(f"Listo, pongo {url} bajo vigilancia y lo reviso ahora…\n", "sys")
                self._run(self._do_watch, url)
            elif has(_SCAN_W):
                self._run(self._do_scan, url, False)
            elif has(_PENTEST_W):
                self._run(self._do_pentest, url, lab)
            else:
                self._append("(no aclaraste qué hacer — le hago un pentest completo)\n", "sys")
                self._run(self._do_pentest, url, lab)
            return

        # sin sitio → acciones que no necesitan URL
        if has(_VULNS_W):
            self._run(self._do_vulns)
        elif has(_REPORT_W):
            self._run(self._do_report)
        elif has(_GUARD_W):
            self._append("Corro el guardián sobre todos los sitios vigilados…\n", "sys")
            self._run(self._do_guard)
        elif has(_RECON_W) or has(_SCAN_W) or has(_PENTEST_W):
            self._append("¿A qué sitio? Decime la URL. Ej: pentest misitio.com\n", "sys")
        else:
            self._append("No te entendí. Probá: escaneá <url> · recon <url> · "
                         "qué vulns hay · hacé el informe · ayuda\n", "sys")

    # ── acciones (en thread, con stdout capturado) ──────────────────
    def _run(self, fn, *args):
        self._set_busy(True)
        threading.Thread(target=self._worker, args=(fn, args), daemon=True).start()

    def _worker(self, fn, args):
        old = sys.stdout
        sys.stdout = _Pipe(self.q)
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001
            self.q.put(f"\n⚠ error: {e}\n")
        finally:
            sys.stdout = old
            self.q.put(_DONE)

    def _do_pentest(self, url: str, lab: bool):
        from .engine import LocalPentester
        report = LocalPentester(url, lab=lab).run()
        save_scan(report)
        self._summary(report)

    def _do_scan(self, url: str, _lab: bool):
        print(f"▸ Escaneando {url} …")
        report, err = deterministic_scan(url, crawl=True)
        if err:
            print(f"✚ No se pudo conectar: {err}")
            return
        save_scan(report)
        self._summary(report)

    def _do_recon(self, url: str):
        from . import recon
        report = recon.run(url, say=lambda m: print("▸ " + m))
        save_scan(report)
        self._summary(report)

    def _do_watch(self, url: str):
        from . import guard
        a = guard.add_asset(url, mode="scan", interval=60)
        print(f"▸ {url} agregado a vigilancia (cada 60 min). Lo reviso ahora…")
        _, alerts = guard.check_asset(a)
        if alerts:
            for a in alerts:
                print(f"  ⚠ [{a['severity']}] {a['title']}")
        else:
            print("  🛡 todo en orden por ahora.")
        print("Tip: dejá corriendo `python cli.py guard` para vigilancia 24/7.")

    def _do_guard(self):
        from . import guard
        fired = guard.guard_once(force=True)
        if not fired:
            print("🛡 Revisé todos los sitios vigilados — todo en orden.")
            return
        print(f"⚠ {len(fired)} alerta(s):")
        for a in fired:
            print(f"  [{a['severity']}] {a['target']} — {a['title']}")

    def _do_fix(self):
        from . import remediate, store
        hist = store.list_history()
        if not hist:
            print("Todavía no escaneaste nada. Hacé un scan/pentest primero.")
            return
        rep = store.get_scan(hist[0]["id"])
        if not remediate.missing_headers(rep):
            print(f"En {rep['target']} no faltan headers de seguridad. 🎉")
            return
        print(f"▸ Cómo arreglar {rep['target']} (pegá esto en tu vercel.json):\n")
        print(remediate.generate(rep, "vercel"))

    def _do_vulns(self):
        from . import vulns
        s = vulns.stats()
        bs = s["by_status"]
        print("── Backlog de vulnerabilidades ──")
        print(f"  🔴 {bs['open']} abiertas · 👀 {bs['acknowledged']} reconocidas · "
              f"✅ {bs['fixed']} arregladas · puntaje de riesgo: {s['open_risk_score']}")
        openv = vulns.list_vulns(status="open")
        if not openv:
            print("  No hay vulnerabilidades abiertas. 🎉")
            return
        for v in openv[:12]:
            print(f"  • [{v['severity']}] {v['host']} — {v['title']}  ({v['key']})")

    def _do_report(self):
        import os
        import tempfile
        from . import report_html, store
        hist = store.list_history()
        if not hist:
            print("Todavía no escaneaste nada. Hacé un scan/pentest primero.")
            return
        rep = store.get_scan(hist[0]["id"])
        out = os.path.join(tempfile.gettempdir(), "centinela-informe.html")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(report_html.build_html(rep))
        print(f"▸ Informe generado de {rep['target']} → abriéndolo en el navegador…")
        webbrowser.open("file://" + out)
        print("  (en el navegador: Imprimir → Guardar como PDF)")

    def _summary(self, r: dict):
        g, s = r["grade"], r["score"]
        c = r["counts"]
        print(f"\n── {r['target']} ──")
        if r.get("reachable") is False:
            print(f"  Nota: N/A (HTTP {r.get('http_status')}) — {r.get('notice') or ''}")
            return
        print(f"  Nota {g} ({s}/100) · {c['critical']} críticas · {c['high']} altas · "
              f"{c['medium']} medias · {c['low']} bajas")
        fails = [f for f in r["findings"] if not f["passed"]]
        for f in fails[:12]:
            print(f"  ✚ [{f['severity']}] {f['title']}")
        if r.get("summary"):
            print(f"\n{r['summary']}")
        print("\n(detalle completo en el dashboard: escribí 'dashboard')\n")


def launch():
    CentinelaGUI().root.mainloop()
